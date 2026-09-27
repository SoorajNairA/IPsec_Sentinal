from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
import unittest

from ipsec_sentinel.analyzer.contract import validate_analysis
from ipsec_sentinel.frontend.xray import XRAY_SCHEMA_ID, XRAY_VERSION
from scripts.generate_frontend_demos import DEMO_SCHEMA_ID, DEMO_VERSION, DEMOS


ROOT = Path(__file__).resolve().parents[1]
DEMO_ROOT = ROOT / "frontend" / "public" / "demos"
ANALYZER_COMMIT = "64b5884edc9cac3ceea321ce785f36cb24132401"


class FrontendDemoTest(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads((DEMO_ROOT / "manifest.json").read_text(encoding="utf-8"))

    def test_manifest_has_only_the_approved_genuine_demos(self) -> None:
        self.assertEqual(self.manifest["schema_id"], DEMO_SCHEMA_ID)
        self.assertEqual(self.manifest["version"], DEMO_VERSION)
        self.assertEqual(self.manifest["analyzer_commit"], ANALYZER_COMMIT)
        self.assertIn("generate_frontend_demos.py", self.manifest["generation_command"])
        expected = {(item.demo_id, item.run_id, item.capture_name) for item in DEMOS}
        actual = {
            (item["id"], item["source"]["run_id"], item["source"]["capture"])
            for item in self.manifest["demos"]
        }
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 5)

    def test_artifacts_are_checksummed_contract_valid_and_path_safe(self) -> None:
        windows_absolute = re.compile(r"^[A-Za-z]:[\\/]")
        for item in self.manifest["demos"]:
            with self.subTest(demo=item["id"]):
                self.assertFalse(windows_absolute.match(item["label"]))
                self.assertFalse(item["label"].startswith("/"))
                demo_dir = DEMO_ROOT / item["id"]
                analysis_path = demo_dir / "analysis.json"
                xray_path = demo_dir / "xray.json"
                self.assertEqual(sha256(analysis_path.read_bytes()).hexdigest(), item["sha256"]["analysis"])
                self.assertEqual(sha256(xray_path.read_bytes()).hexdigest(), item["sha256"]["xray"])

                analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
                xray = json.loads(xray_path.read_text(encoding="utf-8"))
                validate_analysis(analysis)
                self.assertEqual(xray["schema_id"], XRAY_SCHEMA_ID)
                self.assertEqual(xray["version"], XRAY_VERSION)
                self.assertEqual(xray["displayed_packet_count"], len(xray["packets"]))
                self.assertNotRegex(analysis["capture"]["path"], r"^[A-Za-z]:[\\/]")
                self.assertFalse(analysis["capture"]["path"].startswith("/"))


if __name__ == "__main__":
    unittest.main()
