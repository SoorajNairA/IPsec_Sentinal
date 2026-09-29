from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
import json
import struct
import unittest

from ipsec_sentinel.analyze.cli import main
from ipsec_sentinel.analyzer.pipeline import analyze_capture
from tests.pcap_helpers import ethernet_ipv4, write_pcap


class AnalyzerCliTest(unittest.TestCase):
    def test_human_output_and_json_contract(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            pcap = root / "capture.pcap"
            output = root / "analysis.json"
            write_pcap(pcap, [(1, ethernet_ipv4("192.0.2.1", "192.0.2.2", 50, struct.pack("!II", 1, 1) + b"x" * 16))])
            stdout = StringIO()
            with redirect_stdout(stdout):
                code = main([str(pcap), "--json", str(output)])
            result = json.loads(output.read_text())
        self.assertEqual(code, 0)
        self.assertIn("IPsec Sentinel Analysis", stdout.getvalue())
        self.assertIn("Payload", stdout.getvalue())
        self.assertEqual(result["analysis_version"], "1.0")
        self.assertFalse(result["esp"]["payload_decrypted"])

    def test_missing_capture_is_structured_without_traceback(self) -> None:
        stderr = StringIO()
        stdout = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["definitely-missing.pcap"])
        self.assertEqual(code, 2)
        self.assertIn("ERROR", stdout.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue() + stdout.getvalue())

    def test_controlled_sidecar_can_verify_pfs_without_relabeling_packet_source(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            pcap = root / "full-evidence.pcap"
            write_pcap(pcap, [(1, ethernet_ipv4("192.0.2.1", "192.0.2.2", 50, struct.pack("!II", 1, 1) + b"x"))])
            (root / "ground_truth.json").write_text(json.dumps({
                "status": "PASS", "run_id": "run-test",
                "capture": {"full_evidence_file": "full-evidence.pcap"},
                "ipsec": {
                    "scenario_id": "secure-baseline",
                    "configured": {"pfs": True, "esp_proposal": "aes256gcm16-ecp384"},
                    "observed": {
                        "esp_proposal": "AES_GCM_16_256/NO_EXT_SEQ",
                        "pfs": {"status": "VERIFIED", "rekey_observed": True,
                                "evidence": ["selected proposal: ESP:AES_GCM_16_256/ECP_384/NO_EXT_SEQ"]},
                    },
                },
            }), encoding="utf-8")
            (root / "verification.json").write_text(json.dumps({"status": "PASS"}), encoding="utf-8")
            result = analyze_capture(pcap)
        self.assertEqual(result["pfs"]["state"], "enabled")
        pfs_evidence = next(item for item in result["evidence"] if item["id"] == "ev-lab-pfs-001")
        self.assertEqual(pfs_evidence["provenance"], "DERIVED")
        self.assertEqual(pfs_evidence["source_component"], "controlled-lab-artifacts")
        self.assertEqual(result["ike"]["encryption"]["provenance"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
