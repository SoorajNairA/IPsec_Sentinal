from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from ipsec_sentinel.analyzer.contract import validate_analysis
from ipsec_sentinel.frontend.xray import XRAY_SCHEMA_ID, XRAY_VERSION
from scripts import generate_frontend_demos as demo_generator


DEMO_SCHEMA_ID = demo_generator.DEMO_SCHEMA_ID
DEMO_VERSION = demo_generator.DEMO_VERSION
DEMOS = demo_generator.DEMOS
generate_demos = demo_generator.generate_demos


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

    def test_generation_rejects_a_falsely_attributed_analyzer_commit(self) -> None:
        with TemporaryDirectory() as directory:
            try:
                generate_demos(
                    dataset_root=ROOT,
                    model_dir=ROOT,
                    output=Path(directory),
                    analyzer_commit="0" * 40,
                )
            except Exception as error:
                self.assertIsInstance(error, ValueError)
                self.assertRegex(str(error), "analyzer commit")
            else:
                self.fail("generation accepted a false analyzer commit")

    def test_generation_rejects_dirty_non_analyzer_dependencies(self) -> None:
        verify_source_revisions = getattr(demo_generator, "_verify_source_revisions", None)
        self.assertIsNotNone(verify_source_revisions)
        with TemporaryDirectory() as directory:
            repository = Path(directory)
            tracked = (
                "ipsec_sentinel/analyzer/core.py",
                "ipsec_sentinel/ml/infer.py",
                "ipsec_sentinel/frontend/xray.py",
                "ipsec_sentinel/pcap.py",
                "ipsec_sentinel/artifacts.py",
                "scripts/generate_frontend_demos.py",
            )
            for relative in tracked:
                path = repository / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("clean\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
            subprocess.run(["git", "config", "user.name", "Sentinel Test"], cwd=repository, check=True)
            subprocess.run(["git", "config", "user.email", "sentinel@example.invalid"], cwd=repository, check=True)
            subprocess.run(["git", "add", "."], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-qm", "fixture"], cwd=repository, check=True)
            commit = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repository,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            (repository / "ipsec_sentinel/pcap.py").write_text("dirty\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "implementation sources"):
                verify_source_revisions(commit, repository=repository)

    def test_git_command_falls_back_for_a_windows_linked_worktree_in_wsl(self) -> None:
        git_executable = getattr(demo_generator, "_git_executable", None)
        self.assertIsNotNone(git_executable)
        native_failure = subprocess.CalledProcessError(128, ["git", "rev-parse"])
        windows_success = subprocess.CompletedProcess(["git.exe", "rev-parse"], 0, "true\n", "")
        with patch.object(demo_generator.subprocess, "run", side_effect=(native_failure, windows_success)):
            self.assertEqual(git_executable(ROOT), "git.exe")


if __name__ == "__main__":
    unittest.main()
