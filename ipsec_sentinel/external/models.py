from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


EXTERNAL_OBSERVATION_SCHEMA_VERSION = "ipsec-sentinel.external-observation/v1"


@dataclass(frozen=True)
class ExternalPacketObservation:
    schema_version: str
    parent_session_id: str
    packet_index: int
    relative_timestamp_us: int
    packet_size_bytes: int
    direction: str
    label: str
    source_dataset: str
    vpn_protocol: str

    def __post_init__(self) -> None:
        if self.schema_version != EXTERNAL_OBSERVATION_SCHEMA_VERSION:
            raise ValueError("unsupported external observation schema")
        for name in ("parent_session_id", "label", "source_dataset", "vpn_protocol"):
            if not getattr(self, name):
                raise ValueError(f"{name} is required")
        if self.packet_index < 0:
            raise ValueError("packet_index must be non-negative")
        if self.relative_timestamp_us < 0:
            raise ValueError("relative_timestamp_us must be non-negative")
        if self.packet_size_bytes <= 0:
            raise ValueError("packet_size_bytes must be positive")
        if self.direction not in ("forward", "reverse"):
            raise ValueError("direction must be forward or reverse")

    @property
    def relative_time_seconds(self) -> float:
        return self.relative_timestamp_us / 1_000_000

    @property
    def length(self) -> int:
        return self.packet_size_bytes


@dataclass(frozen=True)
class ExternalSession:
    observations: tuple[ExternalPacketObservation, ...]
    provenance: Mapping[str, object]
    compatibility: str

    def __post_init__(self) -> None:
        if not self.observations:
            raise ValueError("external session must be non-empty")
        if self.compatibility not in ("compatible", "incompatible"):
            raise ValueError("invalid compatibility state")
        if tuple(item.packet_index for item in self.observations) != tuple(
            range(len(self.observations))
        ):
            raise ValueError("packet indices must be contiguous from zero")
        if any(
            right.relative_timestamp_us < left.relative_timestamp_us
            for left, right in zip(self.observations, self.observations[1:])
        ):
            raise ValueError("observation timestamps must be monotonic")
        for field in (
            "parent_session_id",
            "source_dataset",
            "vpn_protocol",
            "label",
        ):
            if len({getattr(item, field) for item in self.observations}) != 1:
                raise ValueError(f"mixed {field} values in external session")
