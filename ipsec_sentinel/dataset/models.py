from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from enum import StrEnum
from typing import Any

from ipsec_sentinel.models import Check, ConfiguredPolicy, ObservedState, StageRecord

DATASET_SCHEMA_VERSION = "ipsec-sentinel.dataset-ground-truth/v1"
VERIFICATION_SCHEMA_VERSION = "ipsec-sentinel.dataset-verification/v1"
TRAFFIC_SCHEMA_VERSION = "ipsec-sentinel.traffic/v1"
SCENARIO_SCHEMA_VERSION = "ipsec-sentinel.scenario/v1"
MANIFEST_SCHEMA_VERSION = 1
SEED_DERIVATION_VERSION = "sha256-slot-attempt/v1"
PCAP_DERIVATION_VERSION = "pcap-workload-window-esp/v1"


class RunState(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    PASS = "PASS"
    FAILED = "FAILED"
    INCOMPLETE = "INCOMPLETE"


class CleanupState(StrEnum):
    NOT_STARTED = "NOT_STARTED"
    PASS = "PASS"
    FAILED = "FAILED"


@dataclass(frozen=True)
class WorkloadWindow:
    started_unix_ns: int
    finished_unix_ns: int

    def __post_init__(self) -> None:
        if self.started_unix_ns <= 0 or self.finished_unix_ns < self.started_unix_ns:
            raise ValueError("invalid workload window")


@dataclass(frozen=True)
class ReproducibilityMetadata:
    git_commit_sha: str
    git_dirty: bool
    git_diff_sha256: str | None
    dataset_schema_version: str
    scenario_schema_version: str
    manifest_schema_version: int
    strongswan_version: str
    kernel_release: str
    kernel_version: str
    python_implementation: str
    python_version: str
    platform: str
    architecture: str
    generator: str
    generator_version: str
    seed_derivation_version: str
    random_seed: int
    matrix_fingerprint: str
    run_started_at: str
    run_finished_at: str
    workload_started_unix_ns: int
    workload_finished_unix_ns: int
    collection_errors: tuple[str, ...]


@dataclass(frozen=True)
class DatasetCaptureEvidence:
    full_evidence_file: str
    ml_input_file: str
    workload_started_unix_ns: int
    workload_finished_unix_ns: int
    full_packet_count: int
    ike_packets: int
    esp_packets: int
    ml_esp_packets: int
    ml_capture_bytes: int
    ml_duration_seconds: float
    derivation: str


@dataclass(frozen=True)
class DatasetTrafficEvidence:
    traffic_class: str
    known_training_class: bool
    generator: str
    generator_version: str
    seed: int
    parameters: dict[str, object]
    result: dict[str, object]


@dataclass(frozen=True)
class DatasetValidation:
    traffic_verified: bool
    ipsec_verified: bool
    capture_verified: bool
    cleanup_verified: bool

    @property
    def passed(self) -> bool:
        return all(
            (
                self.traffic_verified,
                self.ipsec_verified,
                self.capture_verified,
                self.cleanup_verified,
            )
        )


@dataclass(frozen=True)
class DatasetGroundTruth:
    schema_version: str
    run_id: str
    slot_id: str
    attempt_number: int
    status: RunState
    training_ready: bool
    traffic: DatasetTrafficEvidence
    scenario_id: str
    scenario_schema_version: str
    configured: ConfiguredPolicy
    observed: ObservedState
    network: dict[str, object]
    capture: DatasetCaptureEvidence
    validation: DatasetValidation
    cleanup_status: CleanupState
    reproducibility: ReproducibilityMetadata

    def __post_init__(self) -> None:
        if self.training_ready and self.status is not RunState.PASS:
            raise ValueError("training_ready requires PASS")
        if self.training_ready and self.cleanup_status is not CleanupState.PASS:
            raise ValueError("training_ready requires cleanup PASS")
        if self.training_ready and not self.validation.passed:
            raise ValueError("training_ready requires all validation")

    def to_dict(self) -> dict[str, object]:
        payload = _json_ready(self)
        payload["traffic"]["class"] = payload["traffic"].pop("traffic_class")
        payload["ipsec"] = {
            "scenario_id": payload.pop("scenario_id"),
            "scenario_schema_version": payload.pop("scenario_schema_version"),
            "configured": payload.pop("configured"),
            "observed": payload.pop("observed"),
        }
        return payload


@dataclass(frozen=True)
class DatasetVerification:
    schema_version: str
    run_id: str
    status: RunState
    stages: tuple[StageRecord, ...]
    checks: tuple[Check, ...]
    cleanup: tuple[dict[str, object], ...]

    def to_dict(self) -> dict[str, object]:
        return _json_ready(self)


@dataclass(frozen=True)
class AttemptOutcome:
    run_id: str
    slot_id: str
    attempt_number: int
    state: RunState
    cleanup_state: CleanupState
    training_ready: bool
    failure_class: str | None
    failure_message: str | None
    artifact_path: str
    started_at: str
    finished_at: str
    cleanup_started_at: str
    cleanup_finished_at: str
    cleanup_actions: tuple[dict[str, object], ...]
    cleanup_error: str | None
    traffic_verified: bool
    ipsec_verified: bool
    capture_verified: bool
    esp_packets: int
    capture_bytes: int
    duration_seconds: float


def _json_ready(value: Any) -> Any:
    if isinstance(value, StrEnum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _json_ready(getattr(value, field.name)) for field in fields(value)
        }
    if isinstance(value, tuple):
        return [_json_ready(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_ready(item) for key, item in value.items()}
    return value
