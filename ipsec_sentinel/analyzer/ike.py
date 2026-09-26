from __future__ import annotations

import struct

from ipsec_sentinel.analyzer.models import Evidence, ParsedCapture, ParsedPacket


TRANSFORM_NAMES = {
    (1, 12): "ENCR_AES_CBC",
    (1, 20): "ENCR_AES_GCM_16",
    (2, 5): "PRF_HMAC_SHA2_256",
    (3, 12): "AUTH_HMAC_SHA2_256_128",
    (4, 14): "MODP_2048",
    (4, 19): "ECP_256",
    (4, 20): "ECP_384",
}


def normalize_transform(kind: int, transform_id: int, key_bits: int | None) -> tuple[str, str]:
    raw = TRANSFORM_NAMES.get((kind, transform_id), f"TYPE_{kind}_ID_{transform_id}")
    if kind == 1 and transform_id == 20:
        bits = key_bits or 128
        return f"AES_GCM_16_{bits}", f"AES-{bits}-GCM"
    if kind == 1 and transform_id == 12:
        bits = key_bits or 128
        return f"AES_CBC_{bits}", f"AES-{bits}-CBC"
    normalized = {
        "PRF_HMAC_SHA2_256": "PRF-HMAC-SHA-256",
        "AUTH_HMAC_SHA2_256_128": "HMAC-SHA-256",
        "ECP_256": "ECP-256",
        "ECP_384": "ECP-384",
        "MODP_2048": "MODP-2048",
    }.get(raw, raw)
    return raw, normalized


def _payloads(packet: ParsedPacket) -> list[tuple[int, bytes]]:
    data = packet.transport_payload
    if len(data) < 28:
        return []
    next_type = data[16]
    total = min(len(data), int.from_bytes(data[24:28], "big"))
    offset = 28
    result: list[tuple[int, bytes]] = []
    while next_type and offset + 4 <= total:
        following, _, length = struct.unpack("!BBH", data[offset:offset + 4])
        if length < 4 or offset + length > total:
            break
        result.append((next_type, data[offset + 4:offset + length]))
        next_type = following
        offset += length
    return result


def _sa_transforms(body: bytes) -> list[tuple[int, int, int | None]]:
    if len(body) < 8:
        return []
    proposal_length = int.from_bytes(body[2:4], "big")
    spi_size = body[6]
    offset = 8 + spi_size
    end = min(len(body), proposal_length)
    result = []
    while offset + 8 <= end:
        last, _, length, kind, _, transform_id = struct.unpack("!BBHBBH", body[offset:offset + 8])
        if length < 8 or offset + length > end:
            break
        key_bits = None
        attribute = offset + 8
        while attribute + 4 <= offset + length:
            attribute_type, value = struct.unpack("!HH", body[attribute:attribute + 4])
            if attribute_type == 0x800E:
                key_bits = value
            attribute += 4
        result.append((kind, transform_id, key_bits))
        offset += length
        if last == 0:
            break
    return result


def _unknown() -> dict[str, str]:
    return {"raw": "UNKNOWN", "normalized": "UNKNOWN", "provenance": "UNKNOWN"}


def analyze_ike(capture: ParsedCapture) -> tuple[dict[str, object], tuple[Evidence, ...]]:
    ike_packets = [packet for packet in capture.packets if packet.kind == "IKE" and len(packet.transport_payload) >= 28]
    evidence: list[Evidence] = []
    result: dict[str, object] = {
        "detected": bool(ike_packets), "version": "UNKNOWN", "exchanges": [],
        "initiator_spi": "UNKNOWN", "responder_spi": "UNKNOWN",
        "encryption": _unknown(), "integrity": _unknown(), "prf": _unknown(),
        "dh_group": _unknown(), "selection_basis": "UNKNOWN",
        "traffic_selectors": {"value": "UNKNOWN", "provenance": "UNKNOWN"},
    }
    selected: tuple[ParsedPacket, list[tuple[int, int, int | None]]] | None = None
    exchanges = []
    for packet in ike_packets:
        data = packet.transport_payload
        major = data[17] >> 4
        exchange = data[18]
        response = bool(data[19] & 0x20)
        exchanges.append({"packet_number": packet.number, "exchange_type": exchange, "response": response, "message_id": int.from_bytes(data[20:24], "big")})
        if major == 2:
            result["version"] = "IKEv2"
        result["initiator_spi"] = data[:8].hex()
        result["responder_spi"] = data[8:16].hex()
        if exchange == 34 and response:
            for payload_type, body in _payloads(packet):
                if payload_type == 33:
                    transforms = _sa_transforms(body)
                    if transforms:
                        selected = packet, transforms
                        break
    result["exchanges"] = exchanges
    if selected is not None:
        packet, transforms = selected
        result["selection_basis"] = "IKE_SA_INIT responder SA payload"
        slots = {1: "encryption", 2: "prf", 3: "integrity", 4: "dh_group"}
        for kind, transform_id, key_bits in transforms:
            if kind not in slots:
                continue
            raw, normalized = normalize_transform(kind, transform_id, key_bits)
            field = slots[kind]
            result[field] = {"raw": raw, "normalized": normalized, "provenance": "OBSERVED"}
            evidence.append(Evidence(
                f"ev-ike-{field}-001", "OBSERVED",
                f"{normalized} selected in responder IKE_SA_INIT SA payload",
                (packet.number,), (packet.timestamp_ns,), "IKEv2", raw, normalized,
                "ike-parser",
            ))
    return result, tuple(evidence)
