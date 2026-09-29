from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


PROVENANCE = frozenset({"OBSERVED", "DERIVED", "AI_INFERRED", "UNKNOWN"})


@dataclass(frozen=True)
class Evidence:
    id: str
    provenance: str
    description: str
    packet_numbers: tuple[int, ...] = ()
    timestamps_ns: tuple[int, ...] = ()
    protocol: str | None = None
    raw_value: Any = None
    normalized_value: Any = None
    source_component: str = "capture"
    confidence: float | None = None

    def __post_init__(self) -> None:
        if self.provenance not in PROVENANCE:
            raise ValueError(f"unsupported provenance: {self.provenance}")

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["packet_numbers"] = list(self.packet_numbers)
        result["timestamps_ns"] = list(self.timestamps_ns)
        return result


@dataclass(frozen=True)
class ParsedPacket:
    number: int
    timestamp_ns: int
    captured_length: int
    original_length: int
    source: str | None
    destination: str | None
    ip_protocol: int | None
    source_port: int | None
    destination_port: int | None
    transport_payload: bytes
    kind: str
    esp_spi: int | None = None
    esp_sequence: int | None = None
    natt: bool = False


@dataclass(frozen=True)
class ParsedCapture:
    path: Path
    capture_format: str
    packet_count: int
    capture_bytes: int
    first_timestamp_ns: int
    last_timestamp_ns: int
    packets: tuple[ParsedPacket, ...]
    warnings: tuple[str, ...]

    @property
    def duration_seconds(self) -> float:
        return (self.last_timestamp_ns - self.first_timestamp_ns) / 1_000_000_000
