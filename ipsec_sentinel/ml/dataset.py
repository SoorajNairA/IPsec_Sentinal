from __future__ import annotations

from dataclasses import dataclass
from io import StringIO
from pathlib import Path
import csv
import hashlib
import json

from ipsec_sentinel.artifacts import write_json_atomic, write_text_atomic
from ipsec_sentinel.dataset.manifest import Manifest
from ipsec_sentinel.dataset.models import WorkloadWindow
from ipsec_sentinel.dataset.validation import validate_dataset
from ipsec_sentinel.ml.features import extract_session_features
from ipsec_sentinel.ml.schema import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from ipsec_sentinel.pcap import read_ml_esp_packets


METADATA_COLUMNS = ("session_id", "label", "scenario_id")


@dataclass(frozen=True)
class FeatureDatasetBuild:
    output_dir: Path
    features_csv: Path
    feature_schema: Path
    metadata: Path
    row_count: int
    dataset_sha256: str


def build_feature_dataset(
    dataset_root: Path,
    output_dir: Path,
    *,
    peers: tuple[str, str] = ("192.0.2.1", "192.0.2.2"),
) -> FeatureDatasetBuild:
    report = validate_dataset(dataset_root)
    if not report.passed:
        raise ValueError("dataset validation failed: " + "; ".join(report.errors))

    manifest = Manifest.open_existing(dataset_root / "manifest.sqlite3")
    try:
        slots = {slot.slot_id: slot for slot in manifest.slots()}
        attempts = manifest.supervised_ready_attempts()
        rows: list[dict[str, object]] = []
        for attempt in attempts:
            slot = slots[attempt.slot_id]
            run_dir = dataset_root / attempt.artifact_path
            truth = json.loads(
                (run_dir / "ground_truth.json").read_text(encoding="utf-8")
            )
            capture = truth["capture"]
            window = WorkloadWindow(
                int(capture["workload_started_unix_ns"]),
                int(capture["workload_finished_unix_ns"]),
            )
            packets = read_ml_esp_packets(
                run_dir / "encrypted.pcap", window, peers
            )
            features = extract_session_features(packets)
            rows.append(
                {
                    "session_id": attempt.attempt_id,
                    "label": slot.traffic_class,
                    "scenario_id": slot.scenario_id,
                    **features,
                }
            )
    finally:
        manifest.close()

    if not rows:
        raise ValueError("dataset has no manifest-approved supervised sessions")
    output_dir.mkdir(parents=True, exist_ok=True)
    buffer = StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=(*METADATA_COLUMNS, *FEATURE_NAMES))
    writer.writeheader()
    writer.writerows(rows)
    csv_text = buffer.getvalue()
    digest = hashlib.sha256(csv_text.encode("utf-8")).hexdigest()

    features_path = output_dir / "features.csv"
    schema_path = output_dir / "feature_schema.json"
    metadata_path = output_dir / "dataset_metadata.json"
    write_text_atomic(features_path, csv_text)
    write_json_atomic(
        schema_path,
        {
            "schema_version": FEATURE_SCHEMA_VERSION,
            "sample_unit": "complete workload-window ESP session",
            "feature_names": list(FEATURE_NAMES),
            "allowed_packet_inputs": [
                "relative_timestamp", "captured_packet_length", "transit_direction"
            ],
            "metadata_columns": list(METADATA_COLUMNS),
        },
    )
    write_json_atomic(
        metadata_path,
        {
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "row_count": len(rows),
            "dataset_sha256": digest,
            "source_dataset_name": dataset_root.name,
            "selection": (
                "manifest PASS + training_ready + known_training_class true + "
                "explicit supervised allowlist"
            ),
        },
    )
    return FeatureDatasetBuild(
        output_dir, features_path, schema_path, metadata_path, len(rows), digest
    )
