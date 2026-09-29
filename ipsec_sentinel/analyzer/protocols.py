from __future__ import annotations

from collections import Counter

from ipsec_sentinel.analyzer.models import Evidence, ParsedCapture


def _ev(identifier: str, description: str, packets, protocol: str, value) -> Evidence:
    return Evidence(
        identifier, "OBSERVED", description,
        tuple(packet.number for packet in packets),
        tuple(packet.timestamp_ns for packet in packets), protocol,
        value, value, "protocol-detector",
    )


def analyze_protocols(capture: ParsedCapture) -> tuple[dict[str, object], tuple[Evidence, ...]]:
    groups = {kind: [packet for packet in capture.packets if packet.kind == kind] for kind in ("IKE", "ESP", "AH")}
    natt = [packet for packet in capture.packets if packet.natt]
    peer_pairs = sorted({tuple(sorted((packet.source, packet.destination))) for packet in capture.packets if packet.kind in ("IKE", "ESP", "AH") and packet.source and packet.destination})
    ike_versions = Counter(
        payload[17] >> 4 for payload in (packet.transport_payload for packet in groups["IKE"])
        if len(payload) >= 28
    )
    version = None
    if ike_versions:
        version = "IKEv2" if ike_versions.most_common(1)[0][0] == 2 else f"IKEv{ike_versions.most_common(1)[0][0]}"
    evidence: list[Evidence] = []
    for kind, packets in groups.items():
        if packets:
            evidence.append(_ev(f"ev-protocol-{kind.lower()}-001", f"{kind} traffic observed", packets, kind, len(packets)))
    if natt:
        evidence.append(_ev("ev-protocol-natt-001", "UDP/4500 NAT-T traffic observed", natt, "NAT-T", len(natt)))
    if version:
        evidence.append(_ev("ev-ike-version-001", f"{version} header version observed", groups["IKE"], version, version))
    result = {
        "ipsec_detected": any(groups.values()),
        "ike_detected": bool(groups["IKE"]),
        "ike_version": version or "UNKNOWN",
        "esp_detected": bool(groups["ESP"]),
        "ah_detected": bool(groups["AH"]),
        "natt_detected": bool(natt),
        "ike_packets": len(groups["IKE"]),
        "esp_packets": len(groups["ESP"]),
        "ah_packets": len(groups["AH"]),
        "natt_packets": len(natt),
        "peer_pairs": [list(pair) for pair in peer_pairs],
    }
    return result, tuple(evidence)
