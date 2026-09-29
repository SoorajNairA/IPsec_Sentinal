from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import ipaddress
import os
from pathlib import Path
import struct
import tempfile

from ipsec_sentinel.analyzer.capture import CaptureError, parse_capture
from ipsec_sentinel.models import CaptureEvidence
from ipsec_sentinel.pcap import PcapFormatError, PcapSummary, _read_header, _records


PROVENANCE = "NATT_NORMALIZED_WORKLOAD_WINDOW"
NORMALIZER_VERSION = "1"


@dataclass(frozen=True)
class NattNormalizationReceipt:
    provenance: str
    version: str
    source_sha256: str
    destination_sha256: str
    packet_count: int
    capture_bytes: int
    first_timestamp_ns: int
    last_timestamp_ns: int
    started_unix_ns: int
    ended_unix_ns: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ipv4_layout(frame: bytes) -> tuple[int, int, str, str, int, int]:
    if len(frame) < 34:
        raise PcapFormatError("truncated Ethernet/IPv4 packet")
    offset = 14
    ether_type = int.from_bytes(frame[12:14], "big")
    while ether_type in (0x8100, 0x88A8):
        if len(frame) < offset + 4:
            raise PcapFormatError("truncated VLAN header")
        ether_type = int.from_bytes(frame[offset + 2:offset + 4], "big")
        offset += 4
    if ether_type != 0x0800 or len(frame) < offset + 20 or frame[offset] >> 4 != 4:
        raise PcapFormatError("NAT-T workload contains non-IPv4 traffic")
    ihl = (frame[offset] & 0x0F) * 4
    if ihl < 20 or len(frame) < offset + ihl:
        raise PcapFormatError("invalid IPv4 header")
    flags_fragment = int.from_bytes(frame[offset + 6:offset + 8], "big")
    if flags_fragment & 0x3FFF:
        raise PcapFormatError("NAT-T workload contains fragmented IPv4")
    total_length = int.from_bytes(frame[offset + 2:offset + 4], "big")
    if total_length < ihl or len(frame) < offset + total_length:
        raise PcapFormatError("truncated IPv4 payload")
    return (
        offset,
        ihl,
        str(ipaddress.ip_address(frame[offset + 12:offset + 16])),
        str(ipaddress.ip_address(frame[offset + 16:offset + 20])),
        frame[offset + 9],
        total_length,
    )


def _checksum(header: bytes) -> int:
    if len(header) % 2:
        header += b"\0"
    total = sum(struct.unpack(f"!{len(header) // 2}H", header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _normalize_frame(frame: bytes, peers: tuple[str, str]) -> bytes:
    offset, ihl, source, destination, protocol, total_length = _ipv4_layout(frame)
    if {source, destination} != set(peers):
        raise PcapFormatError("NAT-T workload contains an unexpected peer")
    if protocol != 17:
        raise PcapFormatError("NAT-T workload contains a non-UDP packet")
    udp = frame[offset + ihl:offset + total_length]
    if len(udp) < 8:
        raise PcapFormatError("truncated UDP header")
    source_port, destination_port, udp_length, _ = struct.unpack("!HHHH", udp[:8])
    if 4500 not in (source_port, destination_port):
        raise PcapFormatError("NAT-T workload contains non-UDP/4500 traffic")
    if udp_length < 8 or udp_length > len(udp):
        raise PcapFormatError("invalid UDP length")
    payload = udp[8:udp_length]
    if payload.startswith(b"\0\0\0\0"):
        raise PcapFormatError("NAT-T workload contains an IKE non-ESP marker")
    if payload == b"\xff":
        raise PcapFormatError("NAT-T workload contains a keepalive")
    if len(payload) < 8:
        raise PcapFormatError("NAT-T workload contains truncated ESP")
    spi, sequence = struct.unpack("!II", payload[:8])
    if spi == 0 or sequence == 0:
        raise PcapFormatError("NAT-T workload contains an invalid ESP header")
    header = bytearray(frame[offset:offset + ihl])
    header[2:4] = (ihl + len(payload)).to_bytes(2, "big")
    header[9] = 50
    header[10:12] = b"\0\0"
    header[10:12] = _checksum(bytes(header)).to_bytes(2, "big")
    return frame[:offset] + bytes(header) + payload


def normalize_natt_workload(
    source: Path,
    destination: Path,
    peers: tuple[str, str],
    started_unix_ns: int,
    ended_unix_ns: int,
    *,
    excluded_intervals: tuple[tuple[int, int], ...] = (),
) -> NattNormalizationReceipt:
    if len(peers) != 2 or peers[0] == peers[1]:
        raise ValueError("normalization requires two distinct peers")
    if started_unix_ns >= ended_unix_ns:
        raise ValueError("workload window is empty or reversed")
    if any(start <= ended_unix_ns and end >= started_unix_ns for start, end in excluded_intervals):
        raise PcapFormatError("protected control traffic overlaps the workload window")
    selected: list[tuple[bytes, bytes, int]] = []
    with Path(source).open("rb") as stream:
        global_header, endian, fraction_to_ns = _read_header(stream)
        for record in _records(stream, endian, fraction_to_ns):
            if not started_unix_ns <= record.timestamp_ns <= ended_unix_ns:
                continue
            frame = _normalize_frame(record.payload, peers)
            seconds, fraction, _, _ = struct.unpack(f"{endian}IIII", record.header)
            packet_header = struct.pack(
                f"{endian}IIII", seconds, fraction, len(frame), len(frame)
            )
            selected.append((packet_header, frame, record.timestamp_ns))
    if not selected:
        raise PcapFormatError("NAT-T workload contains zero ESP-in-UDP packets")
    selected.sort(key=lambda item: item[2])
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=destination.parent, prefix=f".{destination.name}.", delete=False
        ) as output:
            temporary_name = output.name
            output.write(global_header)
            for header, frame, _ in selected:
                output.write(header)
                output.write(frame)
            output.flush()
            os.fsync(output.fileno())
        Path(temporary_name).replace(destination)
        temporary_name = None
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)
    timestamps = [item[2] for item in selected]
    return NattNormalizationReceipt(
        PROVENANCE,
        NORMALIZER_VERSION,
        _sha256(Path(source)),
        _sha256(destination),
        len(selected),
        destination.stat().st_size,
        timestamps[0],
        timestamps[-1],
        started_unix_ns,
        ended_unix_ns,
    )


def validate_cloud_full_capture(
    path: Path,
    peers: tuple[str, str],
) -> CaptureEvidence:
    try:
        capture = parse_capture(Path(path))
    except CaptureError as error:
        raise PcapFormatError(str(error)) from error
    packets = [
        packet
        for packet in capture.packets
        if packet.source and packet.destination and {packet.source, packet.destination} == set(peers)
    ]
    ike = sum(packet.kind == "IKE" for packet in packets)
    natt_esp = sum(packet.kind == "ESP" and packet.natt for packet in packets)
    natt = sum(packet.natt for packet in packets)
    if ike == 0:
        raise PcapFormatError("cloud evidence capture is missing IKE")
    if natt_esp == 0:
        raise PcapFormatError("cloud evidence capture is missing ESP-in-UDP")
    return CaptureEvidence(
        Path(path).name,
        len(packets),
        ike,
        natt_esp,
        natt,
        0,
    )


def summary_from_receipt(receipt: NattNormalizationReceipt) -> PcapSummary:
    return PcapSummary(
        receipt.packet_count,
        receipt.capture_bytes,
        receipt.first_timestamp_ns,
        receipt.last_timestamp_ns,
        (receipt.last_timestamp_ns - receipt.first_timestamp_ns) / 1_000_000_000,
    )
