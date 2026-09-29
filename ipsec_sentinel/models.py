from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from typing import Any


@dataclass(frozen=True)
class PfsObservation:
    status: str
    rekey_observed: bool
    evidence: tuple[str, ...]

    @classmethod
    def not_tested(cls) -> "PfsObservation":
        return cls(status="NOT_TESTED", rekey_observed=False, evidence=())


@dataclass(frozen=True)
class ConfiguredPolicy:
    ike_version: int
    mode: str
    ike_proposal: str
    esp_proposal: str
    pfs: bool
    ip_version: int
    local_subnet: str
    remote_subnet: str
    transit_subnet: str


@dataclass(frozen=True)
class ObservedState:
    ike_version: int
    ike_proposal: str
    esp_proposal: str
    pfs: PfsObservation


@dataclass(frozen=True)
class TrafficEvidence:
    type: str
    sent: int
    received: int
    success: bool


@dataclass(frozen=True)
class CaptureEvidence:
    pcap: str
    packet_count: int
    ike_packets: int
    esp_packets: int
    natt_packets: int
    cleartext_packets: int


@dataclass(frozen=True)
class GroundTruth:
    run_id: str
    scenario_id: str
    status: str
    configured: ConfiguredPolicy
    observed: ObservedState
    traffic: TrafficEvidence
    capture: CaptureEvidence

    def to_dict(self) -> dict[str, object]:
        return _json_ready(self)


@dataclass(frozen=True)
class StageRecord:
    name: str
    status: str
    message: str


@dataclass(frozen=True)
class Check:
    name: str
    passed: bool
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class Verification:
    run_id: str
    status: str
    stages: tuple[StageRecord, ...]
    checks: tuple[Check, ...]

    def to_dict(self) -> dict[str, object]:
        return _json_ready(self)


def _json_ready(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _json_ready(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, tuple):
        return [_json_ready(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_ready(item) for key, item in value.items()}
    return value
