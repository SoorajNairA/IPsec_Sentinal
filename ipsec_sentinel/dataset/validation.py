from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from ipsec_sentinel.dataset.manifest import AttemptRecord, Manifest
from ipsec_sentinel.dataset.models import RunState, WorkloadWindow
from ipsec_sentinel.pcap import inspect_ml_pcap


@dataclass(frozen=True)
class DatasetValidationReport:
    passed: bool
    manifest_readable: bool
    valid_runs: int
    failed_runs: int
    incomplete_runs: int
    errors: tuple[str, ...]


def _validate_json_agreement(
    attempt: AttemptRecord,
    traffic_class: str,
    fingerprint: str,
    truth: dict[str, object],
    verification: dict[str, object],
    traffic: dict[str, object],
    environment: dict[str, object],
) -> None:
    if truth.get("run_id") != attempt.attempt_id or truth.get("slot_id") != attempt.slot_id:
        raise ValueError("manifest/ground-truth identity mismatch")
    if truth.get("status") != "PASS" or truth.get("training_ready") is not True:
        raise ValueError("manifest pass has non-training-ready ground truth")
    if truth.get("cleanup_status") != "PASS":
        raise ValueError("training-ready ground truth has incomplete cleanup")
    if verification.get("run_id") != attempt.attempt_id or verification.get("status") != "PASS":
        raise ValueError("manifest/verification status mismatch")
    checks = verification.get("checks")
    if not isinstance(checks, list) or not checks or not all(
        isinstance(check, dict) and check.get("passed") is True for check in checks
    ):
        raise ValueError("verification contains a failed or missing check")
    truth_traffic = truth.get("traffic")
    if not isinstance(truth_traffic, dict) or truth_traffic.get("class") != traffic_class:
        raise ValueError("manifest/ground-truth traffic label mismatch")
    if traffic.get("class") != traffic_class:
        raise ValueError("manifest/traffic label mismatch")
    if truth_traffic.get("seed") != attempt.seed or traffic.get("seed") != attempt.seed:
        raise ValueError("manifest/traffic seed mismatch")
    if environment.get("random_seed") != attempt.seed:
        raise ValueError("manifest/environment seed mismatch")
    if environment.get("matrix_fingerprint") != fingerprint:
        raise ValueError("manifest/environment fingerprint mismatch")
    ipsec = truth.get("ipsec")
    try:
        pfs = ipsec["observed"]["pfs"]  # type: ignore[index]
    except (KeyError, TypeError) as error:
        raise ValueError("ground truth lacks observed PFS evidence") from error
    if pfs.get("status") != "VERIFIED" or pfs.get("rekey_observed") is not True:
        raise ValueError("ground truth PFS rekey is not verified")


def validate_dataset(dataset_root: Path) -> DatasetValidationReport:
    try:
        manifest = Manifest.open_existing(dataset_root / "manifest.sqlite3")
    except (OSError, ValueError) as error:
        return DatasetValidationReport(False, False, 0, 0, 0, (str(error),))
    errors: list[str] = []
    valid_runs = 0
    try:
        dataset = manifest.connection.execute(
            "SELECT matrix_fingerprint FROM datasets"
        ).fetchone()
        fingerprint = dataset[0]
        classes = {slot.slot_id: slot.traffic_class for slot in manifest.slots()}
        for attempt in manifest.training_ready_attempts():
            run_dir = dataset_root / attempt.artifact_path
            try:
                truth = json.loads(
                    (run_dir / "ground_truth.json").read_text(encoding="utf-8")
                )
                verification = json.loads(
                    (run_dir / "verification.json").read_text(encoding="utf-8")
                )
                traffic = json.loads(
                    (run_dir / "traffic.json").read_text(encoding="utf-8")
                )
                environment = json.loads(
                    (run_dir / "environment.json").read_text(encoding="utf-8")
                )
                _validate_json_agreement(
                    attempt,
                    classes[attempt.slot_id],
                    fingerprint,
                    truth,
                    verification,
                    traffic,
                    environment,
                )
                capture = truth["capture"]
                window = WorkloadWindow(
                    capture["workload_started_unix_ns"],
                    capture["workload_finished_unix_ns"],
                )
                summary = inspect_ml_pcap(
                    run_dir / "encrypted.pcap",
                    window,
                    ("192.0.2.1", "192.0.2.2"),
                )
                if summary.packet_count != capture["ml_esp_packets"]:
                    raise ValueError("manifest/ground-truth PCAP count mismatch")
                if summary.packet_count != attempt.esp_packets:
                    raise ValueError("manifest/PCAP ESP count mismatch")
                if summary.capture_bytes != capture["ml_capture_bytes"]:
                    raise ValueError("ground-truth PCAP byte count mismatch")
                if summary.capture_bytes != attempt.capture_bytes:
                    raise ValueError("manifest/PCAP byte count mismatch")
                full = run_dir / "full-evidence.pcap"
                if not full.is_file() or full.stat().st_size <= 24:
                    raise ValueError("full-evidence.pcap is missing or empty")
                if int(capture["ike_packets"]) <= 0 or int(capture["esp_packets"]) <= 0:
                    raise ValueError("full capture lacks recorded IKE/ESP evidence")
                valid_runs += 1
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                errors.append(f"{attempt.attempt_id}: {error}")
        return DatasetValidationReport(
            not errors,
            True,
            valid_runs,
            manifest.count_attempts(RunState.FAILED),
            manifest.count_attempts(RunState.INCOMPLETE),
            tuple(errors),
        )
    finally:
        manifest.close()
