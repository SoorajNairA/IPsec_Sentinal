from __future__ import annotations

import ipaddress
from pathlib import Path
import struct

from ipsec_sentinel.analyzer.models import ParsedCapture, ParsedPacket
from ipsec_sentinel.pcap import MAGIC, PcapFormatError, _read_header, _records


class CaptureError(ValueError):
    """A user-facing capture validation failure."""


def _decode_frame(number: int, timestamp_ns: int, frame: bytes, original: int) -> ParsedPacket:
    if len(frame) < 14:
        raise CaptureError(f"packet {number}: truncated Ethernet frame")
    offset = 14
    ether_type = int.from_bytes(frame[12:14], "big")
    while ether_type in (0x8100, 0x88A8):
        if len(frame) < offset + 4:
            raise CaptureError(f"packet {number}: truncated VLAN header")
        ether_type = int.from_bytes(frame[offset + 2:offset + 4], "big")
        offset += 4
    if ether_type != 0x0800:
        return ParsedPacket(number, timestamp_ns, len(frame), original, None, None, None, None, None, b"", "OTHER")
    if len(frame) < offset + 20 or frame[offset] >> 4 != 4:
        raise CaptureError(f"packet {number}: truncated or invalid IPv4 packet")
    ihl = (frame[offset] & 0x0F) * 4
    if ihl < 20 or len(frame) < offset + ihl:
        raise CaptureError(f"packet {number}: invalid IPv4 header length")
    total_length = int.from_bytes(frame[offset + 2:offset + 4], "big")
    if total_length < ihl or len(frame) < offset + total_length:
        raise CaptureError(f"packet {number}: truncated IPv4 payload")
    source = str(ipaddress.ip_address(frame[offset + 12:offset + 16]))
    destination = str(ipaddress.ip_address(frame[offset + 16:offset + 20]))
    protocol = frame[offset + 9]
    payload = frame[offset + ihl:offset + total_length]
    source_port = destination_port = None
    kind = "IP"
    natt = False
    esp_spi = esp_sequence = None
    transport_payload = payload
    if protocol == 50:
        kind = "ESP"
        if len(payload) >= 8:
            esp_spi, esp_sequence = struct.unpack("!II", payload[:8])
    elif protocol == 51:
        kind = "AH"
    elif protocol == 17:
        if len(payload) < 8:
            raise CaptureError(f"packet {number}: truncated UDP header")
        source_port, destination_port, udp_length, _ = struct.unpack("!HHHH", payload[:8])
        if udp_length < 8 or len(payload) < udp_length:
            raise CaptureError(f"packet {number}: truncated UDP payload")
        transport_payload = payload[8:udp_length]
        if 500 in (source_port, destination_port):
            kind = "IKE"
        elif 4500 in (source_port, destination_port):
            natt = True
            if transport_payload.startswith(b"\0\0\0\0"):
                kind = "IKE"
                transport_payload = transport_payload[4:]
            else:
                kind = "ESP"
                if len(transport_payload) >= 8:
                    esp_spi, esp_sequence = struct.unpack("!II", transport_payload[:8])
        else:
            kind = "UDP"
    return ParsedPacket(
        number, timestamp_ns, len(frame), original, source, destination, protocol,
        source_port, destination_port, transport_payload, kind, esp_spi, esp_sequence, natt,
    )


def parse_capture(path: Path) -> ParsedCapture:
    path = Path(path)
    if not path.exists():
        raise CaptureError(f"capture does not exist: {path}")
    if not path.is_file():
        raise CaptureError(f"capture is not a file: {path}")
    size = path.stat().st_size
    if size == 0:
        raise CaptureError("capture is empty")
    with path.open("rb") as source:
        magic = source.read(4)
        source.seek(0)
        if magic == b"\x0a\x0d\x0d\x0a":
            raise CaptureError("PCAPNG detected but not yet supported")
        if magic not in MAGIC:
            raise CaptureError("unsupported or truncated PCAP header")
        try:
            _, endian, fraction_to_ns = _read_header(source)
            decoded: list[ParsedPacket] = []
            for number, record in enumerate(_records(source, endian, fraction_to_ns), 1):
                original = struct.unpack(f"{endian}IIII", record.header)[3]
                decoded.append(_decode_frame(number, record.timestamp_ns, record.payload, original))
        except (PcapFormatError, struct.error) as error:
            raise CaptureError(str(error)) from error
    if not decoded:
        raise CaptureError("capture contains zero packets")
    warnings: list[str] = []
    if any(right.timestamp_ns < left.timestamp_ns for left, right in zip(decoded, decoded[1:])):
        decoded.sort(key=lambda packet: (packet.timestamp_ns, packet.number))
        warnings.append("timestamps normalized")
    return ParsedCapture(
        path, "pcap", len(decoded), size, decoded[0].timestamp_ns,
        decoded[-1].timestamp_ns, tuple(decoded), tuple(warnings),
    )
