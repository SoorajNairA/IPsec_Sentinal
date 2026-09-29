from __future__ import annotations

from collections import defaultdict

from ipsec_sentinel.analyzer.models import Evidence, ParsedCapture


def reconstruct_security_associations(capture: ParsedCapture) -> tuple[list[dict[str, object]], tuple[Evidence, ...]]:
    grouped: dict[tuple[str, str, int], list] = defaultdict(list)
    for packet in capture.packets:
        if packet.kind == "ESP" and packet.source and packet.destination and packet.esp_spi is not None:
            grouped[(packet.source, packet.destination, packet.esp_spi)].append(packet)
    associations: list[dict[str, object]] = []
    for (source, destination, spi), packets in sorted(grouped.items(), key=lambda item: min(packet.timestamp_ns for packet in item[1])):
        unique = {(packet.esp_sequence, packet.captured_length) for packet in packets}
        associations.append({
            "sa_type": "ESP_CHILD_SA", "source": source, "destination": destination,
            "spi": f"0x{spi:08x}", "first_packet_number": packets[0].number,
            "first_timestamp_ns": min(packet.timestamp_ns for packet in packets),
            "packet_count": len(packets), "unique_packet_count": len(unique),
            "bytes": sum(packet.captured_length for packet in packets),
            "predecessor_spi": None, "successor_spi": None,
            "rekey_provenance": "UNKNOWN",
            "pfs": {"state": "unknown", "provenance": "UNKNOWN"},
        })
    evidence: list[Evidence] = []
    by_direction: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    for association in associations:
        by_direction[(str(association["source"]), str(association["destination"]))].append(association)
    for chain in by_direction.values():
        chain.sort(key=lambda item: int(item["first_timestamp_ns"]))
        for predecessor, successor in zip(chain, chain[1:]):
            predecessor["successor_spi"] = successor["spi"]
            successor["predecessor_spi"] = predecessor["spi"]
            predecessor["rekey_provenance"] = "DERIVED"
            successor["rekey_provenance"] = "DERIVED"
            evidence.append(Evidence(
                f"ev-sa-rekey-{len(evidence) + 1:03d}", "DERIVED",
                f"ESP SPI replacement {predecessor['spi']} to {successor['spi']} observed in one direction",
                (int(predecessor["first_packet_number"]), int(successor["first_packet_number"])),
                (int(predecessor["first_timestamp_ns"]), int(successor["first_timestamp_ns"])),
                "ESP", predecessor["spi"], successor["spi"], "sa-reconstructor",
            ))
    return associations, tuple(evidence)
