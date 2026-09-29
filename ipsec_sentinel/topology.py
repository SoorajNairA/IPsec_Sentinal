from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any, TextIO
import os
import shlex
import subprocess

from ipsec_sentinel.command import CommandFailure, run_checked
from ipsec_sentinel.models import Check


NAMESPACES = ("ips-client", "ips-gwa", "ips-gwb", "ips-server")
GATEWAYS = ("ips-gwa", "ips-gwb")
ROOT_VETH_NAMES = (
    "veth-c", "veth-a-lan", "veth-a-wan",
    "veth-b-wan", "veth-b-lan", "veth-s",
)
SYSCTL_EXPECTATIONS = {
    "net.ipv4.ip_forward": "1",
    "net.ipv4.conf.all.rp_filter": "0",
    "net.ipv4.conf.default.rp_filter": "0",
    "net.ipv4.conf.lan0.rp_filter": "0",
    "net.ipv4.conf.wan0.rp_filter": "0",
}


class Topology:
    def __init__(
        self,
        log: TextIO,
        *,
        timeout: float = 5,
        euid: Callable[[], int] = os.geteuid,
    ) -> None:
        self.log = log
        self.timeout = timeout
        self._euid = euid
        self._tracked_pids: list[int] = []

    @staticmethod
    def setup_commands() -> tuple[tuple[str, ...], ...]:
        commands: list[tuple[str, ...]] = []
        commands.extend(("ip", "netns", "add", namespace) for namespace in NAMESPACES)
        commands.extend(
            (
                ("ip", "link", "add", "veth-c", "type", "veth", "peer", "name", "veth-a-lan"),
                ("ip", "link", "add", "veth-a-wan", "type", "veth", "peer", "name", "veth-b-wan"),
                ("ip", "link", "add", "veth-b-lan", "type", "veth", "peer", "name", "veth-s"),
                ("ip", "link", "set", "veth-c", "netns", "ips-client"),
                ("ip", "link", "set", "veth-a-lan", "netns", "ips-gwa"),
                ("ip", "link", "set", "veth-a-wan", "netns", "ips-gwa"),
                ("ip", "link", "set", "veth-b-wan", "netns", "ips-gwb"),
                ("ip", "link", "set", "veth-b-lan", "netns", "ips-gwb"),
                ("ip", "link", "set", "veth-s", "netns", "ips-server"),
                ("ip", "-n", "ips-client", "link", "set", "veth-c", "name", "eth0"),
                ("ip", "-n", "ips-gwa", "link", "set", "veth-a-lan", "name", "lan0"),
                ("ip", "-n", "ips-gwa", "link", "set", "veth-a-wan", "name", "wan0"),
                ("ip", "-n", "ips-gwb", "link", "set", "veth-b-wan", "name", "wan0"),
                ("ip", "-n", "ips-gwb", "link", "set", "veth-b-lan", "name", "lan0"),
                ("ip", "-n", "ips-server", "link", "set", "veth-s", "name", "eth0"),
            )
        )
        for namespace, address, interface in (
            ("ips-client", "10.10.0.2/24", "eth0"),
            ("ips-gwa", "10.10.0.1/24", "lan0"),
            ("ips-gwa", "192.0.2.1/30", "wan0"),
            ("ips-gwb", "192.0.2.2/30", "wan0"),
            ("ips-gwb", "10.20.0.1/24", "lan0"),
            ("ips-server", "10.20.0.2/24", "eth0"),
        ):
            commands.append(("ip", "-n", namespace, "addr", "add", address, "dev", interface))
        commands.extend(("ip", "-n", namespace, "link", "set", "lo", "up") for namespace in NAMESPACES)
        for namespace, interface in (
            ("ips-client", "eth0"),
            ("ips-gwa", "lan0"),
            ("ips-gwa", "wan0"),
            ("ips-gwb", "wan0"),
            ("ips-gwb", "lan0"),
            ("ips-server", "eth0"),
        ):
            commands.append(("ip", "-n", namespace, "link", "set", interface, "up"))
        commands.extend(
            (
                ("ip", "-n", "ips-client", "route", "add", "10.20.0.0/24", "via", "10.10.0.1"),
                ("ip", "-n", "ips-server", "route", "add", "10.10.0.0/24", "via", "10.20.0.1"),
            )
        )
        for namespace in GATEWAYS:
            commands.append(
                ("ip", "netns", "exec", namespace, "sysctl", "-qw", "net.ipv4.ip_forward=1")
            )
            for scope in ("all", "default", "lan0", "wan0"):
                commands.append(
                    (
                        "ip",
                        "netns",
                        "exec",
                        namespace,
                        "sysctl",
                        "-qw",
                        f"net.ipv4.conf.{scope}.rp_filter=0",
                    )
                )
        return tuple(commands)

    @staticmethod
    def reset_commands(tracked_pids: Iterable[int]) -> tuple[tuple[str, ...], ...]:
        commands = [("kill", "-TERM", str(pid)) for pid in tracked_pids]
        commands.extend(("ip", "netns", "del", namespace) for namespace in NAMESPACES)
        commands.extend(("ip", "link", "del", interface) for interface in ROOT_VETH_NAMES)
        return tuple(commands)

    def track_pid(self, pid: int) -> None:
        if pid not in self._tracked_pids:
            self._tracked_pids.append(pid)

    def setup(self) -> None:
        self._require_root()
        for command in self.setup_commands():
            run_checked(list(command), self.timeout, self.log)

    def reset(self) -> None:
        self._require_root()
        for command in self.reset_commands(self._tracked_pids):
            self.log.write(f"$ {shlex.join(command)}\n")
            try:
                completed = subprocess.run(
                    command,
                    text=True,
                    capture_output=True,
                    timeout=self.timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                self.log.write("cleanup command timed out\n")
                continue
            self.log.write(completed.stdout)
            self.log.write(completed.stderr)
        self.log.flush()
        self._tracked_pids.clear()

    def snapshot(self) -> dict[str, object]:
        self._require_root()
        namespaces_output = run_checked(
            ["ip", "netns", "list"], self.timeout, self.log
        ).stdout
        addresses = {
            namespace: run_checked(
                ["ip", "-n", namespace, "-4", "-o", "addr"],
                self.timeout,
                self.log,
            ).stdout
            for namespace in NAMESPACES
        }
        routes = {
            namespace: run_checked(
                ["ip", "-n", namespace, "route"], self.timeout, self.log
            ).stdout
            for namespace in ("ips-client", "ips-server")
        }
        sysctls: dict[str, dict[str, str]] = {}
        nat: dict[str, str] = {}
        for namespace in GATEWAYS:
            sysctls[namespace] = {
                key: run_checked(
                    ["ip", "netns", "exec", namespace, "sysctl", "-n", key],
                    self.timeout,
                    self.log,
                ).stdout.strip()
                for key in SYSCTL_EXPECTATIONS
            }
            nat[namespace] = run_checked(
                ["ip", "netns", "exec", namespace, "iptables", "-t", "nat", "-S"],
                self.timeout,
                self.log,
            ).stdout
        return {
            "namespaces": tuple(
                line.split()[0] for line in namespaces_output.splitlines() if line.strip()
            ),
            "addresses": addresses,
            "routes": routes,
            "sysctls": sysctls,
            "nat": nat,
        }

    def verify(self) -> list[Check]:
        try:
            snapshot = self.snapshot()
        except CommandFailure as error:
            return [Check("topology.snapshot", False, (str(error),))]
        return evaluate_snapshot(snapshot)

    def _require_root(self) -> None:
        if self._euid() != 0:
            raise PermissionError("topology operations require root")


def evaluate_snapshot(snapshot: dict[str, Any]) -> list[Check]:
    checks: list[Check] = []
    namespaces = set(snapshot["namespaces"])
    for namespace in NAMESPACES:
        checks.append(
            Check(
                name=f"namespace.{namespace}",
                passed=namespace in namespaces,
                evidence=(f"present={namespace in namespaces}",),
            )
        )

    addresses = snapshot["addresses"]
    for namespace, address in (
        ("ips-client", "10.10.0.2/24"),
        ("ips-gwa", "10.10.0.1/24"),
        ("ips-gwa", "192.0.2.1/30"),
        ("ips-gwb", "192.0.2.2/30"),
        ("ips-gwb", "10.20.0.1/24"),
        ("ips-server", "10.20.0.2/24"),
    ):
        present = address in addresses[namespace]
        checks.append(Check(f"address.{namespace}.{address}", present, (addresses[namespace],)))

    routes = snapshot["routes"]
    for namespace, name, expected in (
        ("ips-client", "remote_protected", "10.20.0.0/24 via 10.10.0.1 dev eth0"),
        ("ips-server", "remote_protected", "10.10.0.0/24 via 10.20.0.1 dev eth0"),
    ):
        present = any(line.strip() == expected for line in routes[namespace].splitlines())
        checks.append(Check(f"route.{namespace}.{name}", present, (routes[namespace],)))

    sysctls = snapshot["sysctls"]
    for namespace in GATEWAYS:
        for key, expected in SYSCTL_EXPECTATIONS.items():
            actual = sysctls[namespace][key]
            checks.append(
                Check(
                    f"sysctl.{namespace}.{key}",
                    actual == expected,
                    (f"expected={expected}", f"actual={actual}"),
                )
            )

    nat = snapshot["nat"]
    for namespace in GATEWAYS:
        rules = [line for line in nat[namespace].splitlines() if line.startswith("-A ")]
        checks.append(
            Check(
                f"nat.{namespace}.empty",
                not rules,
                tuple(rules) if rules else ("no append rules",),
            )
        )
    return checks
