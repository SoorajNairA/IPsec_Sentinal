from pathlib import Path
import os
import unittest

from ipsec_sentinel.analyzer.pipeline import analyze_capture


DATASET = os.environ.get("IPSEC_SENTINEL_REAL_DATASET")
MODEL = os.environ.get("IPSEC_SENTINEL_MODEL_DIR")


@unittest.skipUnless(DATASET, "set IPSEC_SENTINEL_REAL_DATASET for genuine capture tests")
class AnalyzerRealPcapTest(unittest.TestCase):
    def test_four_real_scenarios_retain_crypto_and_pfs_evidence(self) -> None:
        root = Path(DATASET)
        expected = {
            "run_000001": ("AES-256-GCM", "enabled"),
            "run_000043": ("AES-128-GCM", "enabled"),
            "run_000085": ("AES-256-CBC", "enabled"),
            "run_000127": ("AES-256-GCM", "disabled"),
        }
        for run_id, (cipher, pfs) in expected.items():
            with self.subTest(run=run_id):
                result = analyze_capture(root / "runs" / run_id / "full-evidence.pcap")
                self.assertEqual(result["summary"]["status"], "COMPLETE")
                self.assertEqual(result["ike"]["version"], "IKEv2")
                self.assertEqual(result["ike"]["encryption"]["normalized"], cipher)
                self.assertEqual(result["pfs"]["state"], pfs)
                self.assertGreater(result["esp"]["packet_count"], 0)

    @unittest.skipUnless(MODEL, "set IPSEC_SENTINEL_MODEL_DIR for real inference")
    def test_real_encrypted_workload_invokes_existing_model(self) -> None:
        root = Path(DATASET)
        result = analyze_capture(
            root / "runs" / "run_000013" / "encrypted.pcap",
            model_dir=Path(MODEL),
        )
        self.assertEqual(result["traffic_intelligence"]["provenance"], "AI_INFERRED")
        self.assertIn(result["traffic_intelligence"]["predicted_class"], {
            "email", "file_transfer", "icmp", "messaging", "video", "voip", "web"
        })
        self.assertFalse(result["traffic_intelligence"]["payload_decrypted"])


if __name__ == "__main__":
    unittest.main()
