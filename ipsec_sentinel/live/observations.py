from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
import re

from ipsec_sentinel.analyzer.capture import CaptureError, parse_capture


@dataclass(frozen=True)
class LiveObservation:
    type: str
    reason: str
    data: Mapping[str, Any]


@dataclass(frozen=True)
class EspTotals:
    packet_count: int
    bytes: int

    @classmethod
    def empty(cls) -> EspTotals:
        return cls(0, 0)


@dataclass(frozen=True)
class EspSummary:
    peer_pair: tuple[str, str]
    packet_count: int
    bytes: int
    packet_delta: int
    byte_delta: int
    direction_counts: Mapping[str, int]
    direction_bytes: Mapping[str, int]
    first_timestamp_ns: int
    last_timestamp_ns: int

    @property
    def totals(self) -> EspTotals:
        return EspTotals(self.packet_count, self.bytes)

    def to_dict(self) -> dict[str, object]:
        return {
            "peer_pair": list(self.peer_pair),
            "packet_count": self.packet_count,
            "bytes": self.bytes,
            "packet_delta": self.packet_delta,
            "byte_delta": self.byte_delta,
            "direction_counts": dict(self.direction_counts),
            "direction_bytes": dict(self.direction_bytes),
            "first_timestamp_ns": self.first_timestamp_ns,
            "last_timestamp_ns": self.last_timestamp_ns,
        }


class StrongSwanObservationParser:
    _PROPOSAL = re.compile(r"selected proposal: (IKE:([^\s]+))")
    _CHILD = re.compile(
        r"CHILD_SA\s+([^\s{]+)\{\d+\}\s+established with SPIs "
        r"([0-9a-fA-F]+)_i\s+([0-9a-fA-F]+)_o"
    )

    def __init__(self) -> None:
        self._seen_lines: set[str] = set()

    def feed(self, line: str) -> LiveObservation | None:
        normalized = line.strip()
        if not normalized or normalized in self._seen_lines:
            return None
        observation = self._parse(normalized)
        if observation is not None:
            self._seen_lines.add(normalized)
        return observation

    def _parse(self, line: str) -> LiveObservation | None:
        if "generating IKE_SA_INIT request" in line:
            return LiveObservation(
                "ike.sa_init.request",
                "strongSwan generated an IKE_SA_INIT request",
                {"direction": "outbound"},
            )
        if "parsed IKE_SA_INIT response" in line:
            return LiveObservation(
                "ike.sa_init.response",
                "strongSwan parsed an IKE_SA_INIT response",
                {"direction": "inbound"},
            )
        proposal_match = self._PROPOSAL.search(line)
        if proposal_match is not None:
            raw = proposal_match.group(1)
            parts = proposal_match.group(2).split("/")
            return LiveObservation(
                "ike.proposal.selected",
                "strongSwan selected the negotiated IKE proposal",
                {
                    "raw": raw,
                    "encryption": parts[0] if parts else "UNKNOWN",
                    "prf": next(
                        (part for part in parts if part.startswith("PRF_")),
                        "UNKNOWN",
                    ),
                    "dh_group": next(
                        (
                            part
                            for part in reversed(parts)
                            if part.startswith(("ECP_", "MODP_", "CURVE_"))
                        ),
                        "UNKNOWN",
                    ),
                },
            )
        if "generating IKE_AUTH request" in line:
            return LiveObservation(
                "ike.auth.request",
                "strongSwan generated an IKE_AUTH request",
                {"direction": "outbound"},
            )
        if "parsed IKE_AUTH response" in line:
            return LiveObservation(
                "ike.auth.response",
                "strongSwan parsed an IKE_AUTH response",
                {"direction": "inbound"},
            )
        if "IKE_SA " in line and " established between " in line:
            peers = re.search(r"established between ([^\[]+)\[[^]]+\]\.\.\.([^\[]+)\[", line)
            data: dict[str, object] = {}
            if peers is not None:
                data["initiator"] = peers.group(1)
                data["responder"] = peers.group(2)
            return LiveObservation(
                "ike.sa.established",
                "strongSwan reported an established IKE_SA",
                data,
            )
        child_match = self._CHILD.search(line)
        if child_match is not None:
            return LiveObservation(
                "child_sa.established",
                "strongSwan reported an established CHILD_SA",
                {
                    "name": child_match.group(1),
                    "inbound_spi": f"0x{child_match.group(2).lower()}",
                    "outbound_spi": f"0x{child_match.group(3).lower()}",
                },
            )
        return None


def summarize_esp(
    snapshot_path: Path,
    prior_totals: EspTotals,
    *,
    expected_peers: tuple[str, str] = ("192.0.2.1", "192.0.2.2"),
) -> EspSummary | None:
    try:
        capture = parse_capture(Path(snapshot_path))
    except CaptureError as error:
        message = str(error).lower()
        if "truncated" in message or "zero packets" in message:
            return None
        raise
    packets = [
        packet
        for packet in capture.packets
        if packet.kind == "ESP" and packet.source and packet.destination
    ]
    if not packets:
        return None
    expected_set = frozenset(expected_peers)
    if any(frozenset((packet.source, packet.destination)) != expected_set for packet in packets):
        raise ValueError("ESP observation does not match expected transit peers")
    packet_count = len(packets)
    byte_count = sum(packet.captured_length for packet in packets)
    packet_delta = packet_count - prior_totals.packet_count
    byte_delta = byte_count - prior_totals.bytes
    if packet_delta <= 0 or byte_delta <= 0:
        return None
    direction_counts: Counter[str] = Counter()
    direction_bytes: Counter[str] = Counter()
    for packet in packets:
        direction = (
            "forward"
            if (packet.source, packet.destination) == expected_peers
            else "reverse"
        )
        direction_counts[direction] += 1
        direction_bytes[direction] += packet.captured_length
    return EspSummary(
        peer_pair=expected_peers,
        packet_count=packet_count,
        bytes=byte_count,
        packet_delta=packet_delta,
        byte_delta=byte_delta,
        direction_counts=dict(direction_counts),
        direction_bytes=dict(direction_bytes),
        first_timestamp_ns=packets[0].timestamp_ns,
        last_timestamp_ns=packets[-1].timestamp_ns,
    )
