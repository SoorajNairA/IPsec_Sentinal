from pathlib import Path
from tempfile import TemporaryDirectory
import json
import struct
import unittest
from unittest.mock import patch

from ipsec_sentinel.analyzer.contract import ANALYSIS_SCHEMA_ID, validate_analysis
from ipsec_sentinel.analyzer.pipeline import analyze_capture
from tests.pcap_helpers import ethernet_ipv4, write_pcap


class AnalyzerContractTest(unittest.TestCase):
    def test_analysis_has_stable_required_frontend_fields_and_serializes(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "esp.pcap"
            write_pcap(path, [(1, ethernet_ipv4("192.0.2.1", "192.0.2.2", 50, struct.pack("!II", 1, 1) + b"x" * 32))])
            result = analyze_capture(path)
            validate_analysis(result)
            self.assertEqual(result["schema_id"], ANALYSIS_SCHEMA_ID)
            self.assertEqual(set((
                "analysis_version", "schema_id", "capture", "summary", "peers",
                "protocols", "ike", "controlled_evidence", "security_associations", "esp",
                "traffic_intelligence", "evidence", "findings", "security_score",
                "limitations",
            )) - result.keys(), set())
            json.dumps(result)
            evidence_ids = {item["id"] for item in result["evidence"]}
            self.assertTrue(all(set(item["evidence_ids"]) <= evidence_ids for item in result["findings"]))
            schema = json.loads(Path("schemas/ipsec-sentinel-analysis-v1.schema.json").read_text())
            self.assertEqual(schema["$id"], ANALYSIS_SCHEMA_ID)
            self.assertEqual(set(schema["required"]), set(result) - {"pfs"})

    def test_validator_rejects_missing_field_and_bad_provenance(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing required"):
            validate_analysis({"analysis_version": "1.0"})
        with TemporaryDirectory() as directory:
            path = Path(directory) / "esp.pcap"
            write_pcap(path, [(1, ethernet_ipv4("1.1.1.1", "2.2.2.2", 50, struct.pack("!II", 1, 1) + b"x"))])
            result = analyze_capture(path)
            result["evidence"][0]["provenance"] = "GUESSED"
            with self.assertRaisesRegex(ValueError, "provenance"):
                validate_analysis(result)

    def test_omitted_traffic_capture_preserves_existing_contract_semantics(self) -> None:
        path = Path("tests/fixtures/ike-esp.pcap")

        implicit = analyze_capture(path, model_dir=Path("missing-model"))
        explicit = analyze_capture(
            path,
            model_dir=Path("missing-model"),
            traffic_capture_path=None,
        )

        self.assertEqual(implicit, explicit)

    def test_workload_override_changes_only_inference_source(self) -> None:
        full_path = Path("tests/fixtures/ike-esp.pcap")

        def classify(observations, *_args, **_kwargs):
            return {
                "state": "PREDICTED",
                "predicted_class": f"packets-{len(observations)}",
                "raw_confidence": 0.99,
                "confidence_kind": "raw_uncalibrated",
                "probabilities": {},
                "provenance": "AI_INFERRED",
                "model_version": "test",
                "feature_schema_version": "ipsec-sentinel.esp-session-features/v1",
                "payload_decrypted": False,
                "reason": "test classifier",
            }

        with TemporaryDirectory() as directory:
            workload_path = Path(directory) / "workload.pcap"
            write_pcap(workload_path, [
                (
                    index,
                    ethernet_ipv4(
                        "192.0.2.1" if index % 2 else "192.0.2.2",
                        "192.0.2.2" if index % 2 else "192.0.2.1",
                        50,
                        struct.pack("!II", index, index) + b"x" * 32,
                    ),
                )
                for index in range(1, 4)
            ])
            with patch("ipsec_sentinel.analyzer.pipeline.infer_traffic", side_effect=classify):
                full_only = analyze_capture(full_path)
                separated = analyze_capture(
                    full_path,
                    traffic_capture_path=workload_path,
                )

        for field in (
            "capture",
            "summary",
            "peers",
            "protocols",
            "ike",
            "controlled_evidence",
            "security_associations",
            "pfs",
            "esp",
            "findings",
            "security_score",
        ):
            self.assertEqual(separated[field], full_only[field], field)
        self.assertNotEqual(
            separated["traffic_intelligence"]["predicted_class"],
            full_only["traffic_intelligence"]["predicted_class"],
        )
        self.assertEqual(
            separated["traffic_intelligence"]["capture_source"],
            "WORKLOAD_WINDOW",
        )
        self.assertEqual(
            separated["traffic_intelligence"]["capture_path"],
            str(workload_path),
        )
        self.assertIn(
            "TRAFFIC_WINDOW_SCOPE",
            {item["code"] for item in separated["limitations"]},
        )
        traffic_evidence = next(
            item
            for item in separated["evidence"]
            if item["id"] == "ev-traffic-inference-001"
        )
        self.assertIn("workload-only", traffic_evidence["description"])

    def test_invalid_or_non_esp_workload_capture_never_falls_back(self) -> None:
        full_path = Path("tests/fixtures/ike-esp.pcap")
        expected_esp_packets = analyze_capture(full_path)["protocols"]["esp_packets"]
        with TemporaryDirectory() as directory:
            invalid = Path(directory) / "invalid.pcap"
            invalid.write_bytes(b"not a pcap")
            with patch("ipsec_sentinel.analyzer.pipeline.infer_traffic") as infer:
                malformed = analyze_capture(
                    full_path,
                    traffic_capture_path=invalid,
                )
                non_esp = analyze_capture(
                    full_path,
                    traffic_capture_path=Path("tests/fixtures/ike-only.pcap"),
                )
                mixed = analyze_capture(
                    full_path,
                    traffic_capture_path=Path("tests/fixtures/ike-esp.pcap"),
                )

        infer.assert_not_called()
        for result, code in (
            (malformed, "TRAFFIC_CAPTURE_ERROR"),
            (non_esp, "TRAFFIC_CAPTURE_NO_ESP"),
            (mixed, "TRAFFIC_CAPTURE_NO_ESP"),
        ):
            self.assertEqual(result["summary"]["status"], "COMPLETE")
            self.assertEqual(result["protocols"]["esp_packets"], expected_esp_packets)
            self.assertEqual(result["traffic_intelligence"]["state"], "UNKNOWN")
            self.assertEqual(result["traffic_intelligence"]["capture_source"], "WORKLOAD_WINDOW")
            self.assertIn(code, {item["code"] for item in result["limitations"]})
            self.assertFalse(any(
                item["provenance"] == "AI_INFERRED"
                for item in result["evidence"]
            ))


if __name__ == "__main__":
    unittest.main()
