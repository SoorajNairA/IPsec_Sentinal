from pathlib import Path
from tempfile import TemporaryDirectory
import json
import struct
import unittest

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
                "protocols", "ike", "security_associations", "esp",
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


if __name__ == "__main__":
    unittest.main()
