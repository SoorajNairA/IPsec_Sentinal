from __future__ import annotations

import json
import io
from pathlib import Path
import struct
import subprocess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from ipsec_sentinel.cloud.config import GcpLabConfig
from ipsec_sentinel.cloud.ipsec import CloudEndpointClient
from ipsec_sentinel.cloud.gcloud import GcloudClient
from ipsec_sentinel.cloud.manifest import (
    APPROVED_MANIFEST,
    command_digest,
    inspect_deployment,
    render_creation_commands,
    render_post_provision_commands,
)
from ipsec_sentinel.cloud.natt import normalize_natt_workload
from ipsec_sentinel.dataset.models import WorkloadWindow
from ipsec_sentinel.evidence import parse_xfrm
from ipsec_sentinel.live.provider import GcpLabProvider, ProviderEndpoint
from ipsec_sentinel.pcap import PcapFormatError, inspect_ml_pcap
from ipsec_sentinel.scenario import negotiated_policy
from tests.pcap_helpers import ethernet_ipv4, write_pcap


def _config(root: Path) -> GcpLabConfig:
    return GcpLabConfig(
        operator="black",
        operator_uid=1000,
        operator_home=Path("/home/black"),
        cloudsdk_config=Path("/home/black/.config/gcloud"),
        source_cidr="8.8.8.8/32",
        psk_file=root / "psk",
        control_token_file=root / "token",
        tls_ca_file=root / "ca",
        tls_cert_file=root / "cert",
        tls_key_file=root / "key",
    )


class GcpPrototypeTest(unittest.TestCase):
    def test_resource_inspection_uses_bounded_slow_read_timeout(self) -> None:
        observed: list[float] = []

        class Client:
            def run_json(self, args: tuple[str, ...], *, timeout: float):
                observed.append(timeout)
                if args[:2] == ("projects", "describe"):
                    return {"projectNumber": APPROVED_MANIFEST.project_number}
                if args[:3] == ("compute", "networks", "describe"):
                    return {"autoCreateSubnetworks": False}
                if args[:4] == ("compute", "networks", "subnets", "describe"):
                    return {"ipCidrRange": APPROVED_MANIFEST.subnet_cidr}
                if args[:3] == ("compute", "instances", "list"):
                    return [
                        {
                            "name": name,
                            "status": "TERMINATED",
                            "labels": {"deployment": APPROVED_MANIFEST.deployment_id, "scenario": scenario},
                            "machineType": "/" + APPROVED_MANIFEST.machine_type,
                            "serviceAccounts": [],
                            "canIpForward": True,
                            "tags": {"items": ["ipsec-sentinel-vpn"]},
                            "networkInterfaces": [{"network": "/" + APPROVED_MANIFEST.network, "subnetwork": "/" + APPROVED_MANIFEST.subnet}],
                            "disks": [{"diskSizeGb": str(APPROVED_MANIFEST.boot_disk_size_gb)}],
                        }
                        for scenario, name in APPROVED_MANIFEST.instance_by_scenario.items()
                    ]
                if args[:3] == ("compute", "disks", "describe"):
                    return {"type": "/" + APPROVED_MANIFEST.boot_disk_type}
                if args[:3] == ("compute", "firewall-rules", "describe"):
                    return {
                        "allowed": [{"IPProtocol": "udp", "ports": ["500", "4500"]}],
                        "sourceRanges": ["8.8.8.8/32"],
                        "targetTags": ["ipsec-sentinel-vpn"],
                        "network": "/" + APPROVED_MANIFEST.network,
                    }
                raise AssertionError(args)

        result = inspect_deployment(Client(), APPROVED_MANIFEST, "8.8.8.8/32")
        self.assertTrue(result.ready, result.issues)
        self.assertGreater(len(observed), 4)
        self.assertEqual(set(observed), {60})

    def test_endpoint_helper_is_importable_inside_network_namespace(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            token = root / "token"
            ca = root / "ca.pem"
            token.write_text("x" * 32, encoding="utf-8")
            ca.write_text("test-ca", encoding="utf-8")
            observed: dict[str, object] = {}

            def run(argv: list[str], _timeout: float, _log: object, **kwargs: object):
                observed.update(kwargs)
                output = Path(argv[argv.index("--output") + 1])
                output.write_text('{"status":"ok"}\n', encoding="utf-8")
                return SimpleNamespace(stdout="", stderr="")

            client = CloudEndpointClient(
                root,
                io.StringIO(),
                token_file=token,
                ca_file=ca,
                session_nonce="n" * 64,
            )
            with patch("ipsec_sentinel.cloud.ipsec.run_checked", side_effect=run):
                self.assertEqual(client.health(), {"status": "ok"})

            environment = observed.get("env")
            self.assertIsInstance(environment, dict)
            package_root = str(Path(__file__).resolve().parent.parent)
            self.assertEqual(str(environment["PYTHONPATH"]).split(":", 1)[0], package_root)

    def test_cloud_xfrm_accepts_reciprocal_dynamic_outer_addresses(self) -> None:
        text = """STATE
src 172.31.254.2 dst 34.100.156.168
\tproto esp spi 0xcb84c5f4 reqid 1 mode tunnel
\taead rfc4106(gcm(aes)) 0x00 128
src 34.100.156.168 dst 172.31.254.2
\tproto esp spi 0xc1da4d07 reqid 1 mode tunnel
\taead rfc4106(gcm(aes)) 0x00 128
POLICY
src 10.10.0.0/24 dst 10.20.0.0/24
\tdir out priority 1 ptype main
\ttmpl src 172.31.254.2 dst 34.100.156.168
\t\tproto esp spi 0xcb84c5f4 reqid 1 mode tunnel
src 10.20.0.0/24 dst 10.10.0.0/24
\tdir fwd priority 1 ptype main
\ttmpl src 34.100.156.168 dst 172.31.254.2
\t\tproto esp reqid 1 mode tunnel
src 10.20.0.0/24 dst 10.10.0.0/24
\tdir in priority 1 ptype main
\ttmpl src 34.100.156.168 dst 172.31.254.2
\t\tproto esp reqid 1 mode tunnel
"""
        sa = SimpleNamespace(spis=("c1da4d07", "cb84c5f4"))
        evidence = parse_xfrm(
            text,
            "gateway-a",
            sa,
            negotiated_policy("aes128-gcm"),
            allow_dynamic_outer=True,
        )
        self.assertTrue(evidence.state_valid)
        self.assertTrue(evidence.policy_valid)

    def test_resource_plan_is_fixed_and_natt_only(self) -> None:
        commands = (
            *render_creation_commands(APPROVED_MANIFEST, "8.8.8.8/32"),
            *render_post_provision_commands(APPROVED_MANIFEST),
        )
        rendered = "\n".join(command.shell() for command in commands)
        self.assertEqual(rendered.count("compute instances create"), 4)
        self.assertIn("udp:500,udp:4500", rendered)
        self.assertNotIn("ip:50", rendered)
        self.assertNotIn("0.0.0.0/0", rendered)
        self.assertEqual(len(command_digest(commands)), 64)

    def test_provider_refuses_preexisting_running_instance(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            calls: list[list[str]] = []

            def runner(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                calls.append(argv)
                payload = {
                    "name": "vpn-secure",
                    "status": "RUNNING",
                    "labels": {"scenario": "secure-baseline", "deployment": "gcp-live-lab-v1"},
                }
                return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")

            config = _config(root)
            client = GcloudClient(config, runner=runner)
            session = SimpleNamespace(run_dir=root)
            provider = GcpLabProvider(session, config=config, client=client)
            with patch(
                "ipsec_sentinel.cloud.manifest.inspect_deployment",
                return_value=SimpleNamespace(ready=True, issues=()),
            ):
                with self.assertRaisesRegex(RuntimeError, "already running"):
                    provider.start_scenario("secure-baseline")
            self.assertFalse(any("start" in call for call in calls))

    def test_natt_window_normalizes_to_strict_native_esp(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "full.pcap"
            output = root / "encrypted.pcap"
            peers = ("172.31.254.2", "34.10.20.30")
            esp = struct.pack("!II", 0x10203040, 1) + b"encrypted-payload"
            udp = struct.pack("!HHHH", 4500, 4500, 8 + len(esp), 0) + esp
            frame = ethernet_ipv4(peers[0], peers[1], 17, udp)
            write_pcap(source, [(2_000_000_000, frame)])
            receipt = normalize_natt_workload(
                source, output, peers, 1_900_000_000, 2_100_000_000
            )
            summary = inspect_ml_pcap(
                output, WorkloadWindow(1_900_000_000, 2_100_000_000), peers
            )
            self.assertEqual(receipt.packet_count, 1)
            self.assertEqual(summary.packet_count, 1)
            self.assertEqual(receipt.provenance, "NATT_NORMALIZED_WORKLOAD_WINDOW")

    def test_natt_window_rejects_ike_keepalive_and_control_overlap(self) -> None:
        peers = ("172.31.254.2", "34.10.20.30")
        for name, payload in (("ike", b"\0\0\0\0" + b"ike"), ("keepalive", b"\xff")):
            with self.subTest(name=name), TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "full.pcap"
                udp = struct.pack("!HHHH", 4500, 4500, 8 + len(payload), 0) + payload
                write_pcap(source, [(2_000_000_000, ethernet_ipv4(*peers, 17, udp))])
                with self.assertRaises(PcapFormatError):
                    normalize_natt_workload(
                        source, root / "out.pcap", peers, 1_900_000_000, 2_100_000_000
                    )
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "full.pcap"
            write_pcap(source, [])
            with self.assertRaisesRegex(PcapFormatError, "control traffic"):
                normalize_natt_workload(
                    source,
                    root / "out.pcap",
                    peers,
                    1_900_000_000,
                    2_100_000_000,
                    excluded_intervals=((2_000_000_000, 2_000_000_100),),
                )

    def test_public_endpoint_projection_hides_scenario_and_instance(self) -> None:
        endpoint = ProviderEndpoint(
            "gcp", "Mystery VPN #01", "34.10.20.30", "natt", "no-pfs",
            {"instance": "vpn-no-pfs"},
        )
        public = endpoint.to_public_dict()
        self.assertNotIn("scenario_id", public)
        self.assertNotIn("private", public)
        self.assertNotIn("vpn-no-pfs", json.dumps(public))


if __name__ == "__main__":
    unittest.main()
