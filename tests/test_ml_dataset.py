from pathlib import Path
from tempfile import TemporaryDirectory
import csv
import json
import unittest

from ipsec_sentinel.artifacts import write_json_atomic
from ipsec_sentinel.dataset.config import DatasetConfig
from ipsec_sentinel.dataset.manifest import Manifest
from ipsec_sentinel.dataset.models import CleanupState, RunState
from ipsec_sentinel.ml.dataset import build_feature_dataset
from ipsec_sentinel.ml.schema import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from tests.pcap_helpers import ethernet_ipv4, write_pcap


def build_valid_source(root: Path, repetitions: int = 6) -> Path:
    dataset_root = root / "source"
    dataset_root.mkdir()
    manifest = Manifest(dataset_root / "manifest.sqlite3")
    config = DatasetConfig(
        "source", "ipsec-sentinel.dataset-ground-truth/v1", 17, ("icmp",),
        ("secure-baseline",), ("clean",), repetitions, 1, 0,
    )
    fingerprint = "a" * 64
    manifest.initialize(config, fingerprint, "matrix.yaml", {"icmp": "1"})
    for slot in manifest.slots():
        plan = manifest.next_attempt(slot.slot_id, 0)
        assert plan is not None
        manifest.mark_running(plan.attempt_id, "2026-09-26T00:00:00Z")
        run_dir = dataset_root / plan.artifact_path
        run_dir.mkdir(parents=True)
        records = [
            (
                1_100_000_000 + slot.ordinal * 1_000_000,
                ethernet_ipv4("192.0.2.1", "192.0.2.2", 50, b"a" * (20 + slot.ordinal)),
            ),
            (
                1_200_000_000 + slot.ordinal * 1_000_000,
                ethernet_ipv4("192.0.2.2", "192.0.2.1", 50, b"b" * (30 + slot.ordinal)),
            ),
        ]
        write_pcap(run_dir / "encrypted.pcap", records)
        write_pcap(run_dir / "full-evidence.pcap", records)
        capture_bytes = (run_dir / "encrypted.pcap").stat().st_size
        payloads = {
            "ground_truth.json": {
                "run_id": plan.attempt_id,
                "slot_id": plan.slot_id,
                "status": "PASS",
                "training_ready": True,
                "cleanup_status": "PASS",
                "traffic": {
                    "class": "icmp", "seed": plan.seed,
                    "known_training_class": True, "class_role": "supervised",
                    "generator_version": "1",
                },
                "capture": {
                    "workload_started_unix_ns": 1_000_000_000,
                    "workload_finished_unix_ns": 2_000_000_000,
                    "ml_esp_packets": 2,
                    "ml_capture_bytes": capture_bytes,
                    "ike_packets": 1,
                    "esp_packets": 2,
                },
                "ipsec": {
                    "configured": {"pfs": True},
                    "observed": {"pfs": {
                        "status": "VERIFIED", "rekey_observed": True,
                    }},
                },
            },
            "verification.json": {
                "run_id": plan.attempt_id, "status": "PASS",
                "checks": [{"passed": True}],
            },
            "traffic.json": {
                "class": "icmp", "seed": plan.seed,
                "known_training_class": True, "class_role": "supervised",
                "generator_version": "1",
            },
            "environment.json": {
                "matrix_fingerprint": fingerprint, "random_seed": plan.seed,
            },
        }
        for name, payload in payloads.items():
            write_json_atomic(run_dir / name, payload)
        manifest.finish_attempt(
            plan.attempt_id, RunState.PASS, CleanupState.PASS,
            training_ready=True, failure_class=None, failure_message=None,
            traffic_verified=True, ipsec_verified=True, capture_verified=True,
            esp_packets=2, capture_bytes=capture_bytes,
            finished_at="2026-09-26T00:00:01Z",
            cleanup_started_at="2026-09-26T00:00:00Z",
            cleanup_finished_at="2026-09-26T00:00:01Z",
            cleanup_actions=(), cleanup_error=None, duration_seconds=0.1,
        )
    manifest.close()
    return dataset_root


class MlDatasetTest(unittest.TestCase):
    def test_builds_only_manifest_approved_rows_with_exact_feature_columns(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = build_valid_source(root)
            first = build_feature_dataset(source, root / "ml-a")
            second = build_feature_dataset(source, root / "ml-b")
            with first.features_csv.open(newline="", encoding="utf-8") as input_file:
                rows = list(csv.DictReader(input_file))
            schema = json.loads(first.feature_schema.read_text(encoding="utf-8"))

        self.assertEqual(len(rows), 6)
        self.assertEqual(
            tuple(rows[0]), ("session_id", "label", "scenario_id", *FEATURE_NAMES)
        )
        self.assertEqual({row["label"] for row in rows}, {"icmp"})
        self.assertEqual({row["scenario_id"] for row in rows}, {"secure-baseline"})
        self.assertEqual(schema["schema_version"], FEATURE_SCHEMA_VERSION)
        self.assertEqual(tuple(schema["feature_names"]), FEATURE_NAMES)
        self.assertEqual(first.dataset_sha256, second.dataset_sha256)

    def test_rejects_a_manifest_pass_whose_ml_capture_is_not_strict_esp(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = build_valid_source(root, repetitions=1)
            write_pcap(
                source / "runs/run_000001/encrypted.pcap",
                [(1_100_000_000, ethernet_ipv4("192.0.2.1", "192.0.2.2", 17, b"x"))],
            )

            with self.assertRaisesRegex(ValueError, "dataset validation failed"):
                build_feature_dataset(source, root / "ml")


if __name__ == "__main__":
    unittest.main()
