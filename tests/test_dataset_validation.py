from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import json
import unittest

from ipsec_sentinel.artifacts import write_json_atomic
from ipsec_sentinel.dataset.config import DatasetConfig
from ipsec_sentinel.dataset.manifest import Manifest
from ipsec_sentinel.dataset.models import CleanupState, RunState
from ipsec_sentinel.dataset.validation import validate_dataset
from tests.pcap_helpers import ethernet_ipv4, write_pcap


class OfflineValidationTest(unittest.TestCase):
    def build_dataset(self, *, passed: bool = True) -> tuple[TemporaryDirectory, Path]:
        temporary = TemporaryDirectory()
        root = Path(temporary.name)
        manifest = Manifest(root / "manifest.sqlite3")
        config = DatasetConfig(
            "test", "ipsec-sentinel.dataset-ground-truth/v1", 7, ("icmp",),
            ("secure-baseline",), ("clean",), 1, 1, 0,
        )
        manifest.initialize(config, "f" * 64, "matrix.yaml", {"icmp": "1"})
        plan = manifest.next_attempt("run_000001", 0)
        manifest.mark_running(plan.attempt_id, "2026-09-25T00:00:00Z")
        if passed:
            manifest.finish_attempt(
                plan.attempt_id, RunState.PASS, CleanupState.PASS,
                training_ready=True, failure_class=None, failure_message=None,
                traffic_verified=True, ipsec_verified=True, capture_verified=True,
                esp_packets=2, capture_bytes=126,
                finished_at="2026-09-25T00:00:01Z",
                cleanup_started_at="2026-09-25T00:00:00Z",
                cleanup_finished_at="2026-09-25T00:00:01Z",
                cleanup_actions=(), cleanup_error=None, duration_seconds=0.1,
            )
            run_dir = root / plan.artifact_path
            run_dir.mkdir(parents=True)
            records = [
                (1_100_000_000, ethernet_ipv4("192.0.2.1", "192.0.2.2", 50, b"a")),
                (1_200_000_000, ethernet_ipv4("192.0.2.2", "192.0.2.1", 50, b"b")),
            ]
            write_pcap(run_dir / "encrypted.pcap", records)
            write_pcap(run_dir / "full-evidence.pcap", records)
            truth = {
                "schema_version": "ipsec-sentinel.dataset-ground-truth/v1",
                "run_id": plan.attempt_id, "slot_id": plan.slot_id,
                "attempt_number": 1, "status": "PASS", "training_ready": True,
                "cleanup_status": "PASS", "traffic": {
                    "class": "icmp", "seed": plan.seed,
                    "known_training_class": True, "class_role": "supervised",
                    "generator_version": "1",
                },
                "capture": {
                    "workload_started_unix_ns": 1_000_000_000,
                    "workload_finished_unix_ns": 2_000_000_000,
                    "ml_esp_packets": 2, "ml_capture_bytes": 126,
                    "ike_packets": 1, "esp_packets": 2,
                },
                "ipsec": {"observed": {"pfs": {
                    "status": "VERIFIED", "rekey_observed": True,
                }}},
            }
            for name, payload in {
                "ground_truth.json": truth,
                "verification.json": {"run_id": plan.attempt_id, "status": "PASS",
                                      "checks": [{"passed": True}]},
                "traffic.json": {"schema_version": "ipsec-sentinel.traffic/v1",
                                 "class": "icmp", "seed": plan.seed,
                                 "known_training_class": True,
                                 "class_role": "supervised",
                                 "generator_version": "1"},
                "environment.json": {"matrix_fingerprint": "f" * 64,
                                     "random_seed": plan.seed},
            }.items():
                write_json_atomic(run_dir / name, payload)
        else:
            manifest.finish_attempt(
                plan.attempt_id, RunState.FAILED, CleanupState.PASS,
                training_ready=False, failure_class="traffic_generator_failed",
                failure_message="injected", traffic_verified=False,
                ipsec_verified=True, capture_verified=False, esp_packets=0,
                capture_bytes=0, finished_at="2026-09-25T00:00:01Z",
                cleanup_started_at="2026-09-25T00:00:00Z",
                cleanup_finished_at="2026-09-25T00:00:01Z",
                cleanup_actions=(), cleanup_error=None, duration_seconds=0,
            )
        manifest.close()
        return temporary, root

    def test_validates_manifest_training_ready_capture(self) -> None:
        temporary, root = self.build_dataset()
        self.addCleanup(temporary.cleanup)
        report = validate_dataset(root)
        self.assertTrue(report.passed, report.errors)
        self.assertEqual(report.valid_runs, 1)

    def test_rejects_missing_ml_pcap(self) -> None:
        temporary, root = self.build_dataset()
        self.addCleanup(temporary.cleanup)
        (root / "runs/run_000001/encrypted.pcap").unlink()
        report = validate_dataset(root)
        self.assertFalse(report.passed)
        self.assertIn("encrypted.pcap", " ".join(report.errors))

    def test_failed_attempt_is_retained_but_not_training_ready(self) -> None:
        temporary, root = self.build_dataset(passed=False)
        self.addCleanup(temporary.cleanup)
        report = validate_dataset(root)
        self.assertTrue(report.manifest_readable)
        self.assertEqual(report.valid_runs, 0)
        self.assertEqual(report.failed_runs, 1)

    def test_rejects_role_disagreement_between_manifest_and_traffic_json(self) -> None:
        temporary, root = self.build_dataset()
        self.addCleanup(temporary.cleanup)
        path = root / "runs/run_000001/traffic.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["known_training_class"] = False
        write_json_atomic(path, payload)
        report = validate_dataset(root)
        self.assertFalse(report.passed)
        self.assertIn("role mismatch", " ".join(report.errors))


if __name__ == "__main__":
    unittest.main()
