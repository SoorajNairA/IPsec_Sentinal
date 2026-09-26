from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from ipsec_sentinel.analyzer.models import Evidence, ParsedCapture
from ipsec_sentinel.ml.features import extract_session_features
from ipsec_sentinel.ml.schema import FEATURE_SCHEMA_VERSION


@dataclass(frozen=True)
class EspObservation:
    relative_time_seconds: float
    length: int
    direction: str


def analyze_esp(capture: ParsedCapture) -> tuple[dict[str, object], tuple[EspObservation, ...], tuple[Evidence, ...]]:
    esp_packets = [packet for packet in capture.packets if packet.kind == "ESP" and packet.source and packet.destination]
    if not esp_packets:
        return ({
            "packet_count": 0, "bytes": 0, "duration_seconds": 0.0,
            "direction_counts": {}, "direction_bytes": {}, "spi_distribution": {},
            "peer_pair": None, "features": None,
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "payload_decrypted": False,
        }, (), ())
    pair_counts = Counter(tuple(sorted((packet.source, packet.destination))) for packet in esp_packets)
    peer_pair = pair_counts.most_common(1)[0][0]
    selected = [packet for packet in esp_packets if tuple(sorted((packet.source, packet.destination))) == peer_pair]
    first_direction = (selected[0].source, selected[0].destination)
    first_timestamp = selected[0].timestamp_ns
    observations = tuple(EspObservation(
        (packet.timestamp_ns - first_timestamp) / 1_000_000_000,
        packet.captured_length,
        "forward" if (packet.source, packet.destination) == first_direction else "reverse",
    ) for packet in selected)
    features = extract_session_features(observations)
    direction_counts = Counter(item.direction for item in observations)
    direction_bytes = Counter()
    for item in observations:
        direction_bytes[item.direction] += item.length
    spi_distribution = Counter(
        f"0x{packet.esp_spi:08x}" if packet.esp_spi is not None else "UNKNOWN"
        for packet in selected
    )
    evidence = Evidence(
        "ev-esp-statistics-001", "DERIVED",
        "ESP packet, byte, timing, direction, and SPI statistics calculated",
        tuple(packet.number for packet in selected),
        tuple(packet.timestamp_ns for packet in selected), "ESP",
        len(selected), len(selected), "esp-analyzer",
    )
    return ({
        "packet_count": len(selected),
        "bytes": sum(item.length for item in observations),
        "duration_seconds": observations[-1].relative_time_seconds,
        "direction_counts": dict(direction_counts),
        "direction_bytes": dict(direction_bytes),
        "spi_distribution": dict(spi_distribution),
        "peer_pair": list(peer_pair),
        "features": features,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "payload_decrypted": False,
    }, observations, (evidence,))
