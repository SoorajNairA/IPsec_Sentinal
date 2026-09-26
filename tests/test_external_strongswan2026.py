from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from ipsec_sentinel.external.adapters.strongswan2026 import (
    StrongSwan2026CatalogAdapter,
)


class StrongSwan2026AdapterTest(unittest.TestCase):
    def test_catalog_preserves_protocol_platform_condition_and_raw_evidence_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = root / "latency_ipsec_wsl_5GHz_fixture"
            run.mkdir()
            (run / "metadata.json").write_text(
                json.dumps({
                    "run_id": run.name,
                    "vpn": "ipsec",
                    "client_role": "wsl",
                    "wifi_band": "5GHz",
                    "stage": "latency",
                    "delay_ms": 50,
                    "loss_pct": None,
                    "mtu": 1500,
                    "cpu_stress": False,
                    "duration_sec": 60,
                }),
                encoding="utf-8",
            )
            for name in ("ipsec_status.txt", "iperf_tcp.json", "ping.log"):
                (run / name).write_text("evidence", encoding="utf-8")

            records = StrongSwan2026CatalogAdapter(root).read()

            self.assertEqual(len(records), 1)
            record = records[0]
            self.assertEqual(
                (record.vpn, record.platform, record.wifi_band, record.stage),
                ("ipsec", "wsl", "5GHz", "latency"),
            )
            self.assertEqual((record.delay_ms, record.loss_pct, record.mtu), (50, None, 1500))
            self.assertEqual(
                record.evidence_paths,
                ("iperf_tcp.json", "ipsec_status.txt", "metadata.json", "ping.log"),
            )

    def test_catalog_never_emits_packet_observations_from_iperf_ping_cpu_or_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = root / "baseline_ipsec_pi_2.4GHz_fixture"
            run.mkdir()
            (run / "metadata.json").write_text(
                json.dumps({
                    "run_id": run.name, "vpn": "ipsec", "client_role": "pi",
                    "wifi_band": "2.4GHz", "stage": "baseline", "delay_ms": None,
                    "loss_pct": None, "mtu": 1500, "cpu_stress": False,
                    "duration_sec": 60,
                }), encoding="utf-8",
            )
            (run / "iperf_udp.json").write_text('{"packets":999}', encoding="utf-8")
            (run / "cpu.json").write_text('[{"timestamp":1}]', encoding="utf-8")
            (run / "ping.log").write_text("64 bytes", encoding="utf-8")
            adapter = StrongSwan2026CatalogAdapter(root)

            self.assertEqual(len(adapter.read()), 1)
            self.assertEqual(tuple(adapter.iter_sessions(limit=1)), ())


if __name__ == "__main__":
    unittest.main()
