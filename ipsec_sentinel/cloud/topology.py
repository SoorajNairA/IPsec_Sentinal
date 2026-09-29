from __future__ import annotations

from collections.abc import Callable
import json
import os
from pathlib import Path
import subprocess
from typing import TextIO

from ipsec_sentinel.command import CommandFailure, run_checked
from ipsec_sentinel.models import Check


CLOUD_NAMESPACES = ("ips-client", "ips-gwa")
ROOT_LINKS = ("ips-client0", "ips-host0")


class CloudClientTopology:
    def __init__(
        self,
        log: TextIO,
        *,
        session_id: str,
        timeout: float = 8,
        euid: Callable[[], int] = os.geteuid,
    ) -> None:
        self.log = log
        self.session_id = session_id
        self.timeout = timeout
        self._euid = euid
        self.endpoint: str | None = None
        self.egress_interface: str | None = None
        self._host_forwarding: str | None = None
        self._configured = False

    @property
    def capture_namespace(self) -> str:
        return "ips-gwa"

    @property
    def capture_interface(self) -> str:
        return "wan0"

    @property
    def capture_peers(self) -> tuple[str, str]:
        if self.endpoint is None:
            raise RuntimeError("cloud endpoint is not configured")
        return ("172.31.254.2", self.endpoint)

    def set_endpoint(self, address: str) -> None:
        import ipaddress

        endpoint = ipaddress.ip_address(address)
        if endpoint.version != 4 or not endpoint.is_global:
            raise ValueError("cloud endpoint must be a public IPv4 address")
        self.endpoint = str(endpoint)

    def _run(self, argv: list[str], timeout: float | None = None) -> str:
        return run_checked(argv, timeout or self.timeout, self.log).stdout

    def _egress(self) -> str:
        if self.endpoint is None:
            raise RuntimeError("cloud endpoint must be set before topology setup")
        payload = json.loads(self._run(["ip", "-j", "route", "get", self.endpoint]))
        if not isinstance(payload, list) or not payload or not isinstance(payload[0], dict):
            raise RuntimeError("host route lookup did not return an egress interface")
        interface = payload[0].get("dev")
        if not isinstance(interface, str) or not interface or interface in ROOT_LINKS:
            raise RuntimeError("host route lookup returned an unsafe egress interface")
        return interface

    def setup(self) -> None:
        if self._euid() != 0:
            raise PermissionError("cloud topology operations require root")
        if self._configured:
            raise RuntimeError("cloud topology is already configured")
        self.egress_interface = self._egress()
        self._host_forwarding = self._run(["sysctl", "-n", "net.ipv4.ip_forward"]).strip()
        commands = [
            ["ip", "netns", "add", "ips-client"],
            ["ip", "netns", "add", "ips-gwa"],
            ["ip", "link", "add", "ips-client0", "type", "veth", "peer", "name", "ips-client1"],
            ["ip", "link", "add", "ips-host0", "type", "veth", "peer", "name", "ips-wan0"],
            ["ip", "link", "set", "ips-client0", "netns", "ips-client"],
            ["ip", "link", "set", "ips-client1", "netns", "ips-gwa"],
            ["ip", "link", "set", "ips-wan0", "netns", "ips-gwa"],
            ["ip", "-n", "ips-client", "link", "set", "ips-client0", "name", "eth0"],
            ["ip", "-n", "ips-gwa", "link", "set", "ips-client1", "name", "lan0"],
            ["ip", "-n", "ips-gwa", "link", "set", "ips-wan0", "name", "wan0"],
            ["ip", "-n", "ips-client", "addr", "add", "10.10.0.2/24", "dev", "eth0"],
            ["ip", "-n", "ips-gwa", "addr", "add", "10.10.0.1/24", "dev", "lan0"],
            ["ip", "-n", "ips-gwa", "addr", "add", "172.31.254.2/30", "dev", "wan0"],
            ["ip", "addr", "add", "172.31.254.1/30", "dev", "ips-host0"],
        ]
        for namespace in CLOUD_NAMESPACES:
            commands.append(["ip", "-n", namespace, "link", "set", "lo", "up"])
        commands.extend(
            [
                ["ip", "-n", "ips-client", "link", "set", "eth0", "up"],
                ["ip", "-n", "ips-gwa", "link", "set", "lan0", "up"],
                ["ip", "-n", "ips-gwa", "link", "set", "wan0", "up"],
                ["ip", "link", "set", "ips-host0", "up"],
                ["ip", "-n", "ips-client", "route", "add", "10.20.0.0/24", "via", "10.10.0.1"],
                ["ip", "-n", "ips-gwa", "route", "add", "default", "via", "172.31.254.1"],
                ["ip", "netns", "exec", "ips-gwa", "sysctl", "-qw", "net.ipv4.ip_forward=1"],
            ]
        )
        for scope in ("all", "default", "lan0", "wan0"):
            commands.append(
                ["ip", "netns", "exec", "ips-gwa", "sysctl", "-qw", f"net.ipv4.conf.{scope}.rp_filter=0"]
            )
        try:
            for command in commands:
                self._run(command)
            self._run(["sysctl", "-qw", "net.ipv4.ip_forward=1"])
            comment = f"ipsec-sentinel:{self.session_id}"
            self._run([
                "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "172.31.254.0/30",
                "-o", self.egress_interface, "-m", "comment", "--comment", comment,
                "-j", "MASQUERADE",
            ])
            self._run([
                "iptables", "-A", "FORWARD", "-i", "ips-host0", "-o", self.egress_interface,
                "-m", "comment", "--comment", comment, "-j", "ACCEPT",
            ])
            self._run([
                "iptables", "-A", "FORWARD", "-i", self.egress_interface, "-o", "ips-host0",
                "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
                "-m", "comment", "--comment", comment, "-j", "ACCEPT",
            ])
            self._configured = True
        except BaseException:
            self.reset()
            raise

    def verify(self) -> tuple[Check, ...]:
        checks: list[Check] = []
        namespaces = self._run(["ip", "netns", "list"])
        for namespace in CLOUD_NAMESPACES:
            checks.append(Check(f"namespace.{namespace}", namespace in namespaces, (namespaces,)))
        client_route = self._run(["ip", "-n", "ips-client", "route", "show", "10.20.0.0/24"]).strip()
        checks.append(Check(
            "route.client.protected",
            client_route == "10.20.0.0/24 via 10.10.0.1 dev eth0",
            (client_route,),
        ))
        gateway_default = self._run(["ip", "-n", "ips-gwa", "route", "show", "default"]).strip()
        checks.append(Check(
            "route.gateway.default",
            gateway_default == "default via 172.31.254.1 dev wan0",
            (gateway_default,),
        ))
        comment = f"ipsec-sentinel:{self.session_id}"
        rules = self._run(["iptables-save"])
        checks.append(Check("nat.scoped", comment in rules and "172.31.254.0/30" in rules, (comment,)))
        return tuple(checks)

    def reset(self) -> None:
        if self._euid() != 0:
            raise PermissionError("cloud topology operations require root")
        errors: list[str] = []

        def attempt(argv: list[str]) -> None:
            try:
                completed = subprocess.run(
                    argv, text=True, capture_output=True, timeout=self.timeout, check=False
                )
            except BaseException as error:
                errors.append(f"{' '.join(argv)}: {error}")
                return
            if completed.returncode != 0 and not any(
                marker in completed.stderr
                for marker in (
                    "No such file", "No chain/target/match", "Bad rule",
                    "Cannot remove namespace file", "Cannot find device",
                )
            ):
                errors.append(f"{' '.join(argv)}: {completed.stderr.strip()}")

        if self.egress_interface:
            comment = f"ipsec-sentinel:{self.session_id}"
            attempt([
                "iptables", "-D", "FORWARD", "-i", self.egress_interface, "-o", "ips-host0",
                "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
                "-m", "comment", "--comment", comment, "-j", "ACCEPT",
            ])
            attempt([
                "iptables", "-D", "FORWARD", "-i", "ips-host0", "-o", self.egress_interface,
                "-m", "comment", "--comment", comment, "-j", "ACCEPT",
            ])
            attempt([
                "iptables", "-t", "nat", "-D", "POSTROUTING", "-s", "172.31.254.0/30",
                "-o", self.egress_interface, "-m", "comment", "--comment", comment,
                "-j", "MASQUERADE",
            ])
        for namespace in CLOUD_NAMESPACES:
            attempt(["ip", "netns", "del", namespace])
        for link in ROOT_LINKS:
            attempt(["ip", "link", "del", link])
        if self._host_forwarding is not None:
            attempt(["sysctl", "-qw", f"net.ipv4.ip_forward={self._host_forwarding}"])
        self._configured = False
        if errors:
            raise RuntimeError("cloud topology cleanup errors: " + "; ".join(errors))
