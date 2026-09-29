from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import json
import sqlite3
import unittest

from ipsec_sentinel.dataset.config import DatasetConfig
from ipsec_sentinel.dataset.manifest import Manifest, ManifestMismatch
from ipsec_sentinel.dataset.models import CleanupState, RunState
from ipsec_sentinel.dataset.summary import build_summary


V1_SCHEMA = """
PRAGMA user_version = 1;
CREATE TABLE datasets (
    name TEXT PRIMARY KEY, schema_version TEXT NOT NULL,
    matrix_fingerprint TEXT NOT NULL, config_path TEXT NOT NULL,
    base_seed INTEGER NOT NULL, generator_versions_json TEXT NOT NULL,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE slots (
    slot_id TEXT PRIMARY KEY, ordinal INTEGER NOT NULL UNIQUE,
    scenario_id TEXT NOT NULL, traffic_class TEXT NOT NULL,
    network_profile TEXT NOT NULL, repetition INTEGER NOT NULL,
    state TEXT NOT NULL, successful_attempt_id TEXT
);
CREATE TABLE attempts (
    attempt_id TEXT PRIMARY KEY, slot_id TEXT NOT NULL,
    attempt_number INTEGER NOT NULL, seed INTEGER NOT NULL,
    state TEXT NOT NULL, started_at TEXT, finished_at TEXT,
    artifact_path TEXT NOT NULL, failure_class TEXT, failure_message TEXT,
    cleanup_status TEXT NOT NULL, cleanup_started_at TEXT,
    cleanup_finished_at TEXT, cleanup_json TEXT NOT NULL DEFAULT '[]',
    cleanup_error TEXT, traffic_verified INTEGER NOT NULL DEFAULT 0,
    ipsec_verified INTEGER NOT NULL DEFAULT 0,
    capture_verified INTEGER NOT NULL DEFAULT 0,
    training_ready INTEGER NOT NULL DEFAULT 0,
    esp_packets INTEGER NOT NULL DEFAULT 0,
    capture_bytes INTEGER NOT NULL DEFAULT 0,
    duration_seconds REAL NOT NULL DEFAULT 0,
    UNIQUE(slot_id, attempt_number)
);
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, attempt_id TEXT NOT NULL,
    occurred_at TEXT NOT NULL, from_state TEXT, to_state TEXT NOT NULL,
    reason TEXT NOT NULL
);
"""


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
        self.addCleanup(manifest.close)
        config = replace(config_fixture(runs=1), traffic_classes=("icmp",))
        manifest.initialize(config, "fingerprint", "matrix.yaml", {"icmp": "1"})
        first = manifest.next_attempt("run_000001", retry_failed=1)
        self.assertIsNotNone(first)
        manifest.mark_running(first.attempt_id, "2026-09-24T09:59:59Z")
        return manifest, first

    def test_initialization_materializes_pending_first_attempts(self) -> None:
        with TemporaryDirectory() as directory:
            manifest = Manifest(Path(directory) / "manifest.sqlite3")
            self.addCleanup(manifest.close)
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

    def test_v1_migration_is_lossless_idempotent_and_populates_compatibility_fields(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.sqlite3"
            connection = sqlite3.connect(path)
            connection.executescript(V1_SCHEMA)
            connection.execute(
                "INSERT INTO datasets VALUES(?,?,?,?,?,?,?,?)",
                (
                    "legacy", "ipsec-sentinel.dataset-ground-truth/v1",
                    "f" * 64, "matrix.yaml", 7,
                    json.dumps({"icmp": "1"}),
                    "2026-09-24T00:00:00Z", "2026-09-24T00:00:00Z",
                ),
            )
            connection.execute(
                "INSERT INTO slots VALUES(?,?,?,?,?,?,?,NULL)",
                ("run_000001", 1, "secure-baseline", "icmp", "clean", 1, "PENDING"),
            )
            connection.execute(
                "INSERT INTO attempts(attempt_id,slot_id,attempt_number,seed,state,artifact_path,cleanup_status) "
                "VALUES(?,?,?,?,?,?,?)",
                ("run_000001", "run_000001", 1, 11, "PENDING", "runs/run_000001", "NOT_STARTED"),
            )
            connection.execute(
                "INSERT INTO events(attempt_id,occurred_at,from_state,to_state,reason) VALUES(?,?,?,?,?)",
                ("run_000001", "2026-09-24T00:00:00Z", None, "PENDING", "initialized"),
            )
            connection.commit()
            connection.close()

            for _ in range(2):
                manifest = Manifest.open_existing(path)
                try:
                    self.assertEqual(
                        manifest.connection.execute("PRAGMA user_version").fetchone()[0],
                        2,
                    )
                    slot = manifest.slots()[0]
                    self.assertTrue(slot.known_training_class)
                    self.assertEqual(slot.class_role, "supervised")
                    self.assertEqual(slot.generator_version, "1")
                    self.assertEqual(
                        slot.scenario_definition_digest,
                        "legacy-secure-baseline/v1",
                    )
                    self.assertEqual(slot.network_profile_version, "clean/v1")
                    self.assertEqual(len(manifest.attempts()), 1)
                    self.assertEqual(
                        manifest.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0],
                        1,
                    )
                finally:
                    manifest.close()

    def test_quality_ready_ood_is_never_supervised_ready_and_summary_is_split(self) -> None:
        manifest, first = self.make_manifest_and_claim()
        manifest.finish_attempt(
            first.attempt_id, RunState.PASS, CleanupState.PASS,
            training_ready=True, failure_class=None, failure_message=None,
            traffic_verified=True, ipsec_verified=True, capture_verified=True,
            esp_packets=10, capture_bytes=500,
            finished_at="2026-09-24T10:00:01Z",
            cleanup_started_at="2026-09-24T10:00:00Z",
            cleanup_finished_at="2026-09-24T10:00:01Z",
            cleanup_actions=(), cleanup_error=None, duration_seconds=1.0,
        )
        manifest.connection.execute(
            "UPDATE slots SET traffic_class=?,known_training_class=0,class_role='ood',generator_version=?",
            ("remote_desktop_like", "1"),
        )
        manifest.connection.commit()
        self.assertEqual(len(manifest.quality_ready_attempts()), 1)
        self.assertEqual(manifest.supervised_ready_attempts(), ())
        summary = build_summary(manifest)
        self.assertEqual(summary.training_ready_runs, 1)
        self.assertEqual(summary.supervised_ready_runs, 0)
        self.assertEqual(summary.ood_ready_runs, 1)
        self.assertEqual(
            summary.ood_class_distribution, {"remote_desktop_like": 1}
        )

    def test_failed_v1_migration_rolls_back_without_partial_columns(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.sqlite3"
            connection = sqlite3.connect(path)
            connection.executescript(V1_SCHEMA)
            connection.execute(
                "INSERT INTO datasets VALUES(?,?,?,?,?,?,?,?)",
                (
                    "legacy", "ipsec-sentinel.dataset-ground-truth/v1",
                    "f" * 64, "matrix.yaml", 7, "not-json",
                    "2026-09-24T00:00:00Z", "2026-09-24T00:00:00Z",
                ),
            )
            connection.execute(
                "INSERT INTO slots VALUES(?,?,?,?,?,?,?,NULL)",
                ("run_000001", 1, "secure-baseline", "icmp", "clean", 1, "PENDING"),
            )
            connection.commit()
            connection.close()

            with self.assertRaises(json.JSONDecodeError):
                Manifest.open_existing(path)
            connection = sqlite3.connect(path)
            try:
                self.assertEqual(
                    connection.execute("PRAGMA user_version").fetchone()[0], 1
                )
                columns = {
                    row[1]
                    for row in connection.execute("PRAGMA table_info(slots)").fetchall()
                }
                self.assertNotIn("known_training_class", columns)
            finally:
                connection.close()


if __name__ == "__main__":
    unittest.main()
