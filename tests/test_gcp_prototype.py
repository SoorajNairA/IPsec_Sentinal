from __future__ import annotations

import json
from pathlib import Path
import struct
import subprocess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from ipsec_sentinel.cloud.config import GcpLabConfig
from ipsec_sentinel.cloud.gcloud import GcloudClient
from ipsec_sentinel.cloud.manifest import (
    APPROVED_MANIFEST,
    command_digest,
    render_creation_commands,
    render_post_provision_commands,
)
from ipsec_sentinel.cloud.natt import normalize_natt_workload
from ipsec_sentinel.dataset.models import WorkloadWindow
from ipsec_sentinel.live.provider import GcpLabProvider, ProviderEndpoint
from ipsec_sentinel.pcap import PcapFormatError, inspect_ml_pcap
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
