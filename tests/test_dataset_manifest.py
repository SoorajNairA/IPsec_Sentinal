from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from ipsec_sentinel.dataset.config import DatasetConfig
from ipsec_sentinel.dataset.manifest import Manifest, ManifestMismatch
from ipsec_sentinel.dataset.models import CleanupState, RunState


def config_fixture(runs: int = 3) -> DatasetConfig:
    return DatasetConfig(
        name="cipherlens-smoke-v1",
        schema_version="ipsec-sentinel.dataset-ground-truth/v1",
        base_seed=20260924,
        traffic_classes=("icmp", "web", "video"),
        scenarios=("secure-baseline",),
        network_profiles=("clean",),
        runs_per_combination=runs,
        workers=1,
        retry_failed=1,
    )


class ManifestTest(unittest.TestCase):
    def make_manifest_and_claim(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        manifest = Manifest(Path(temporary.name) / "manifest.sqlite3")
        config = replace(config_fixture(runs=1), traffic_classes=("icmp",))
        manifest.initialize(config, "fingerprint", "matrix.yaml", {"icmp": "1"})
        first = manifest.next_attempt("run_000001", retry_failed=1)
        self.assertIsNotNone(first)
        manifest.mark_running(first.attempt_id, "2026-09-24T09:59:59Z")
        return manifest, first

    def test_initialization_materializes_pending_first_attempts(self) -> None:
        with TemporaryDirectory() as directory:
            manifest = Manifest(Path(directory) / "manifest.sqlite3")
            manifest.initialize(
                config_fixture(),
                "fingerprint",
                "configs/smoke-v1.yaml",
                {"icmp": "1", "web": "1", "video": "1"},
            )
            self.assertEqual(len(manifest.slots()), 9)
            attempts = manifest.attempts()
            self.assertEqual(len(attempts), 9)
            self.assertTrue(all(row.state is RunState.PENDING for row in attempts))

    def test_pass_requires_cleanup_and_training_ready(self) -> None:
        manifest, first = self.make_manifest_and_claim()
        with self.assertRaisesRegex(ValueError, "cleanup"):
            manifest.finish_attempt(
                first.attempt_id,
                RunState.PASS,
                CleanupState.FAILED,
                training_ready=True,
                failure_class=None,
                failure_message=None,
                traffic_verified=True,
                ipsec_verified=True,
                capture_verified=True,
                esp_packets=20,
                capture_bytes=4096,
                finished_at="2026-09-24T10:00:01Z",
                cleanup_started_at="2026-09-24T10:00:00Z",
                cleanup_finished_at="2026-09-24T10:00:01Z",
                cleanup_actions=(),
                cleanup_error="injected cleanup failure",
                duration_seconds=1.0,
            )

    def test_stale_running_becomes_incomplete_and_retry_is_independent(self) -> None:
        manifest, first = self.make_manifest_and_claim()
        recovered = manifest.recover_running("2026-09-24T10:00:00Z")
        self.assertEqual(recovered, (first.attempt_id,))
        retry = manifest.next_attempt(first.slot_id, retry_failed=1)
        self.assertEqual(retry.attempt_number, 2)
        self.assertNotEqual(retry.seed, first.seed)
        self.assertEqual(retry.attempt_id, f"{first.slot_id}-attempt02")
        manifest.mark_running(retry.attempt_id, "2026-09-24T10:00:01Z")
        manifest.finish_attempt(
            retry.attempt_id,
            RunState.FAILED,
            CleanupState.PASS,
            training_ready=False,
            failure_class="traffic_generator_failed",
            failure_message="injected",
            traffic_verified=False,
            ipsec_verified=True,
            capture_verified=False,
            esp_packets=0,
            capture_bytes=24,
            finished_at="2026-09-24T10:00:02Z",
            cleanup_started_at="2026-09-24T10:00:01Z",
            cleanup_finished_at="2026-09-24T10:00:02Z",
            cleanup_actions=({"name": "topology_reset", "status": "PASS"},),
            cleanup_error=None,
            duration_seconds=1.0,
        )
        self.assertIsNone(manifest.next_attempt(first.slot_id, retry_failed=1))

    def test_fingerprint_mismatch_fails_before_mutation(self) -> None:
        manifest, _ = self.make_manifest_and_claim()
        with self.assertRaises(ManifestMismatch):
            manifest.assert_compatible("different")

    def test_files_do_not_turn_a_stale_running_attempt_into_pass(self) -> None:
        manifest, attempt = self.make_manifest_and_claim()
        artifact = manifest.path.parent / attempt.artifact_path
        artifact.mkdir(parents=True)
        (artifact / "ground_truth.json").write_text(
            '{"status":"PASS"}', encoding="utf-8"
        )
        manifest.recover_running("2026-09-24T10:00:00Z")
        row = next(
            item for item in manifest.attempts() if item.attempt_id == attempt.attempt_id
        )
        self.assertEqual(row.state, RunState.INCOMPLETE)
        self.assertFalse(row.training_ready)


if __name__ == "__main__":
    unittest.main()
