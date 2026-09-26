from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import struct
import unittest

from ipsec_sentinel.analyzer.capture import parse_capture
from ipsec_sentinel.analyzer.esp import analyze_esp
from ipsec_sentinel.analyzer.intelligence import infer_traffic
from ipsec_sentinel.analyzer.pipeline import analyze_capture
from ipsec_sentinel.analyzer.rules import RULE_IDS, assess_security
from tests.pcap_helpers import ethernet_ipv4, write_pcap


def esp(spi: int, sequence: int, size: int = 32) -> bytes:
    return struct.pack("!II", spi, sequence) + b"x" * size


class AnalyzerAssessmentTest(unittest.TestCase):
    def _esp_capture(self, count: int = 12) -> tuple[TemporaryDirectory, Path]:
        temporary = TemporaryDirectory()
        path = Path(temporary.name) / "esp.pcap"
        write_pcap(path, [
            (1_000_000_000 + index * 10_000_000,
             ethernet_ipv4(
                 "192.0.2.1" if index % 2 == 0 else "192.0.2.2",
                 "192.0.2.2" if index % 2 == 0 else "192.0.2.1",
                 50, esp(1 if index % 2 == 0 else 2, index + 1, 24 + index),
             ))
            for index in range(count)
        ])
        return temporary, path

    def test_esp_statistics_reuse_versioned_feature_schema_and_never_decrypt(self) -> None:
        temporary, path = self._esp_capture()
        self.addCleanup(temporary.cleanup)
        result, observations, evidence = analyze_esp(parse_capture(path))
        self.assertEqual(result["packet_count"], 12)
        self.assertGreater(result["bytes"], 0)
        self.assertFalse(result["payload_decrypted"])
        self.assertEqual(result["feature_schema_version"], "ipsec-sentinel.esp-session-features/v1")
        self.assertEqual(result["features"]["packet_count"], 12.0)
        self.assertEqual(len(observations), 12)
        self.assertTrue(evidence)

    def test_inference_is_unknown_for_insufficient_packets_or_missing_model(self) -> None:
        temporary, path = self._esp_capture(4)
        self.addCleanup(temporary.cleanup)
        _, observations, _ = analyze_esp(parse_capture(path))
        insufficient = infer_traffic(observations, Path("missing"), minimum_packets=10)
        self.assertEqual(insufficient["state"], "UNKNOWN")
        self.assertIn("insufficient", insufficient["reason"])
        enough = tuple(observations) * 3
        missing = infer_traffic(enough, Path("missing"), minimum_packets=10)
        self.assertEqual(missing["state"], "UNKNOWN")
        self.assertIn("model", missing["reason"])

    def test_inference_returns_probabilities_and_low_confidence(self) -> None:
        temporary, path = self._esp_capture()
        self.addCleanup(temporary.cleanup)
        _, observations, _ = analyze_esp(parse_capture(path))
        prediction = {
            "inferred_class": "video", "raw_confidence": 0.55,
            "class_probabilities": {"video": 0.55, "web": 0.45},
            "model_schema_version": "ipsec-sentinel.classifier/v1",
            "feature_schema_version": "ipsec-sentinel.esp-session-features/v1",
            "selected_model": "ExtraTreesClassifier",
        }
        with patch("ipsec_sentinel.analyzer.intelligence.predict_observations", return_value=prediction):
            result = infer_traffic(observations, Path("model"), require_model_exists=False)
        self.assertEqual(result["state"], "LOW_CONFIDENCE")
        self.assertEqual(result["provenance"], "AI_INFERRED")
        self.assertEqual(result["probabilities"]["video"], 0.55)
        self.assertFalse(result["payload_decrypted"])
        self.assertEqual(result["confidence_kind"], "raw_uncalibrated")

    def test_rules_score_unknown_without_penalty_and_link_deductions(self) -> None:
        self.assertGreaterEqual(len(RULE_IDS), 10)
        context = {
            "ike": {
                "version": "IKEv2",
                "encryption": {"normalized": "AES-256-GCM", "provenance": "OBSERVED", "evidence_id": "ev-cipher"},
                "integrity": {"normalized": "UNKNOWN", "provenance": "UNKNOWN"},
                "dh_group": {"normalized": "ECP-384", "provenance": "OBSERVED", "evidence_id": "ev-dh"},
            },
            "pfs": {"state": "disabled", "provenance": "DERIVED", "evidence_ids": ["ev-pfs"]},
            "security_associations": [],
            "esp": {"packet_count": 20},
            "traffic_intelligence": {"state": "UNKNOWN"},
        }
        findings, score = assess_security(context)
        pfs = next(item for item in findings if item["rule_id"] == "IPSEC-PFS-002")
        self.assertEqual(pfs["severity"], "MEDIUM")
        self.assertEqual(pfs["evidence_ids"], ["ev-pfs"])
        self.assertLess(score["total"], 100)
        self.assertGreater(score["unassessed_weight"], 0)
        self.assertGreater(score["assessed_weight"], 0)
        self.assertTrue(0 <= score["total"] <= 100)
        for category in score["categories"]:
            self.assertLessEqual(category["achieved_score"], category["maximum_score"])
            for deduction in category["deductions"]:
                self.assertIn("rule_id", deduction)
                self.assertTrue(deduction["evidence_ids"])

    def test_weak_known_crypto_produces_high_severity_evidence_linked_finding(self) -> None:
        context = {
            "ike": {
                "version": "UNKNOWN",
                "encryption": {"normalized": "3DES", "provenance": "OBSERVED", "evidence_id": "ev-weak"},
                "integrity": {"normalized": "UNKNOWN", "provenance": "UNKNOWN"},
                "dh_group": {"normalized": "MODP-1024", "provenance": "OBSERVED", "evidence_id": "ev-dh-weak"},
            },
            "pfs": {"state": "unknown", "provenance": "UNKNOWN", "evidence_ids": []},
            "security_associations": [], "esp": {"packet_count": 0},
            "traffic_intelligence": {"state": "UNKNOWN"},
        }
        findings, score = assess_security(context)
        weak = next(item for item in findings if item["rule_id"] == "IPSEC-CRYPTO-003")
        self.assertEqual(weak["severity"], "HIGH")
        self.assertEqual(weak["evidence_ids"], ["ev-weak"])
        self.assertLess(score["total"], 100)

    def test_pipeline_returns_structured_non_ipsec_and_error_results(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            missing = analyze_capture(root / "missing.pcap")
            self.assertEqual(missing["summary"]["status"], "ERROR")
            self.assertEqual(missing["analysis_version"], "1.0")
            plain = root / "plain.pcap"
            write_pcap(plain, [(1, ethernet_ipv4("10.0.0.1", "10.0.0.2", 1, b"ping"))])
            result = analyze_capture(plain)
            self.assertEqual(result["summary"]["status"], "COMPLETE")
            self.assertFalse(result["protocols"]["ipsec_detected"])
            self.assertEqual(result["traffic_intelligence"]["state"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
