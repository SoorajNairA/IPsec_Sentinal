from io import StringIO
import unittest

from ipsec_sentinel.topology import Topology, evaluate_snapshot


VALID_SNAPSHOT = {
    "namespaces": ("ips-client", "ips-gwa", "ips-gwb", "ips-server"),
    "addresses": {
        "ips-client": "eth0    inet 10.10.0.2/24 scope global eth0\n",
        "ips-gwa": (
            "lan0    inet 10.10.0.1/24 scope global lan0\n"
            "wan0    inet 192.0.2.1/30 scope global wan0\n"
        ),
        "ips-gwb": (
            "wan0    inet 192.0.2.2/30 scope global wan0\n"
            "lan0    inet 10.20.0.1/24 scope global lan0\n"
        ),
        "ips-server": "eth0    inet 10.20.0.2/24 scope global eth0\n",
    },
    "routes": {
        "ips-client": (
            "10.10.0.0/24 dev eth0 proto kernel scope link src 10.10.0.2\n"
            "10.20.0.0/24 via 10.10.0.1 dev eth0\n"
        ),
        "ips-server": (
            "10.10.0.0/24 via 10.20.0.1 dev eth0\n"
            "10.20.0.0/24 dev eth0 proto kernel scope link src 10.20.0.2\n"
        ),
    },
    "sysctls": {
        "ips-gwa": {
            "net.ipv4.ip_forward": "1",
            "net.ipv4.conf.all.rp_filter": "0",
            "net.ipv4.conf.default.rp_filter": "0",
            "net.ipv4.conf.lan0.rp_filter": "0",
            "net.ipv4.conf.wan0.rp_filter": "0",
        },
        "ips-gwb": {
            "net.ipv4.ip_forward": "1",
            "net.ipv4.conf.all.rp_filter": "0",
            "net.ipv4.conf.default.rp_filter": "0",
            "net.ipv4.conf.lan0.rp_filter": "0",
            "net.ipv4.conf.wan0.rp_filter": "0",
        },
    },
    "nat": {
        "ips-gwa": "-P PREROUTING ACCEPT\n-P POSTROUTING ACCEPT\n",
        "ips-gwb": "-P PREROUTING ACCEPT\n-P POSTROUTING ACCEPT\n",
    },
}


class TopologyTest(unittest.TestCase):
    def test_setup_plan_contains_every_phase_one_network_operation(self) -> None:
        commands = Topology.setup_commands()

        for namespace in ("ips-client", "ips-gwa", "ips-gwb", "ips-server"):
            self.assertIn(("ip", "netns", "add", namespace), commands)
        self.assertIn(
            ("ip", "link", "add", "veth-c", "type", "veth", "peer", "name", "veth-a-lan"),
            commands,
        )
        self.assertIn(
            ("ip", "link", "add", "veth-a-wan", "type", "veth", "peer", "name", "veth-b-wan"),
            commands,
        )
        self.assertIn(
            ("ip", "link", "add", "veth-b-lan", "type", "veth", "peer", "name", "veth-s"),
            commands,
        )
        expected_addresses = (
            ("ips-client", "10.10.0.2/24", "eth0"),
            ("ips-gwa", "10.10.0.1/24", "lan0"),
            ("ips-gwa", "192.0.2.1/30", "wan0"),
            ("ips-gwb", "192.0.2.2/30", "wan0"),
            ("ips-gwb", "10.20.0.1/24", "lan0"),
            ("ips-server", "10.20.0.2/24", "eth0"),
        )
        for namespace, address, interface in expected_addresses:
            self.assertIn(
                ("ip", "-n", namespace, "addr", "add", address, "dev", interface),
                commands,
            )
        self.assertIn(
            ("ip", "-n", "ips-client", "route", "add", "10.20.0.0/24", "via", "10.10.0.1"),
            commands,
        )
        self.assertIn(
            ("ip", "-n", "ips-server", "route", "add", "10.10.0.0/24", "via", "10.20.0.1"),
            commands,
        )
        for namespace in ("ips-gwa", "ips-gwb"):
            self.assertIn(
                ("ip", "netns", "exec", namespace, "sysctl", "-qw", "net.ipv4.ip_forward=1"),
                commands,
            )
            for scope in ("all", "default", "lan0", "wan0"):
                self.assertIn(
                    (
                        "ip",
                        "netns",
                        "exec",
                        namespace,
                        "sysctl",
                        "-qw",
                        f"net.ipv4.conf.{scope}.rp_filter=0",
                    ),
                    commands,
                )
        self.assertFalse(any("nat" in command for command in commands))

    def test_cleanup_plan_names_only_tracked_pids_and_exact_lab_resources(self) -> None:
        commands = Topology.reset_commands((101, 202))

        self.assertIn(("kill", "-TERM", "101"), commands)
        self.assertIn(("kill", "-TERM", "202"), commands)
        for namespace in ("ips-client", "ips-gwa", "ips-gwb", "ips-server"):
            self.assertIn(("ip", "netns", "del", namespace), commands)
        for interface in (
            "veth-c", "veth-a-lan", "veth-a-wan",
            "veth-b-wan", "veth-b-lan", "veth-s",
        ):
            self.assertIn(("ip", "link", "del", interface), commands)
        rendered = " ".join(" ".join(command) for command in commands)
        self.assertNotIn("pkill", rendered)
        self.assertNotIn("killall", rendered)
        self.assertNotIn("*", rendered)

    def test_valid_snapshot_passes_every_required_check(self) -> None:
        checks = evaluate_snapshot(VALID_SNAPSHOT)

        self.assertGreater(len(checks), 0)
        self.assertTrue(all(check.passed for check in checks))

    def test_route_and_forwarding_mismatches_are_named_failures(self) -> None:
        snapshot = {
            **VALID_SNAPSHOT,
            "routes": {
                **VALID_SNAPSHOT["routes"],
                "ips-client": "10.10.0.0/24 dev eth0\n",
            },
            "sysctls": {
                **VALID_SNAPSHOT["sysctls"],
                "ips-gwa": {
                    **VALID_SNAPSHOT["sysctls"]["ips-gwa"],
                    "net.ipv4.ip_forward": "0",
                },
            },
        }

        failed = {check.name for check in evaluate_snapshot(snapshot) if not check.passed}

        self.assertIn("route.ips-client.remote_protected", failed)
        self.assertIn("sysctl.ips-gwa.net.ipv4.ip_forward", failed)

    def test_setup_requires_root_before_running_commands(self) -> None:
        topology = Topology(log=StringIO(), euid=lambda: 1000)

        with self.assertRaisesRegex(PermissionError, "root"):
            topology.setup()


if __name__ == "__main__":
    unittest.main()
