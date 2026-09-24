from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import struct
import tempfile
from typing import BinaryIO, Iterator

from ipsec_sentinel.dataset.models import WorkloadWindow


MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1),
    b"\xa1\xb2\x3c\x4d": (">", 1),
}


class PcapFormatError(ValueError):
    """Raised when a capture is malformed or violates the ML PCAP contract."""


@dataclass(frozen=True)
class PcapSummary:
    packet_count: int
    capture_bytes: int
    first_timestamp_ns: int
    last_timestamp_ns: int
    duration_seconds: float


@dataclass(frozen=True)
class _Record:
    header: bytes
    payload: bytes
    timestamp_ns: int


def _read_header(source: BinaryIO) -> tuple[bytes, str, int]:
    header = source.read(24)
    if len(header) != 24 or header[:4] not in MAGIC:
        raise PcapFormatError("unsupported or truncated legacy PCAP header")
    endian, fraction_to_ns = MAGIC[header[:4]]
    major, minor, _, _, _, link_type = struct.unpack(f"{endian}HHIIII", header[4:])
    if (major, minor) != (2, 4):
        raise PcapFormatError("unsupported PCAP version")
    if link_type != 1:
        raise PcapFormatError(f"unsupported link type: {link_type}")
    return header, endian, fraction_to_ns


def _records(
    source: BinaryIO, endian: str, fraction_to_ns: int
) -> Iterator[_Record]:
    fraction_limit = 1_000_000 if fraction_to_ns == 1_000 else 1_000_000_000
    while True:
        header = source.read(16)
        if not header:
            return
        if len(header) != 16:
            raise PcapFormatError("truncated PCAP record header")
        seconds, fraction, included_length, original_length = struct.unpack(
            f"{endian}IIII", header
        )
        if fraction >= fraction_limit:
            raise PcapFormatError("impossible PCAP timestamp fraction")
        if included_length > original_length:
            raise PcapFormatError("captured length exceeds original length")
        payload = source.read(included_length)
        if len(payload) != included_length:
            raise PcapFormatError("truncated PCAP record payload")
        yield _Record(
            header,
            payload,
            seconds * 1_000_000_000 + fraction * fraction_to_ns,
        )


def _outer_ipv4(frame: bytes) -> tuple[str, str, int] | None:
    if len(frame) < 14:
        raise PcapFormatError("truncated Ethernet frame")
    offset = 14
    ether_type = int.from_bytes(frame[12:14], "big")
    while ether_type in (0x8100, 0x88A8):
        if len(frame) < offset + 4:
            raise PcapFormatError("truncated VLAN header")
        ether_type = int.from_bytes(frame[offset + 2 : offset + 4], "big")
        offset += 4
    if ether_type != 0x0800:
        return None
    if len(frame) < offset + 20 or frame[offset] >> 4 != 4:
        raise PcapFormatError("truncated or invalid IPv4 packet")
    ihl = (frame[offset] & 0x0F) * 4
    if ihl < 20 or len(frame) < offset + ihl:
        raise PcapFormatError("invalid IPv4 header length")
    return (
        str(ipaddress.ip_address(frame[offset + 12 : offset + 16])),
        str(ipaddress.ip_address(frame[offset + 16 : offset + 20])),
        frame[offset + 9],
    )


def _is_peer_esp(frame: bytes, peers: tuple[str, str]) -> bool:
    outer = _outer_ipv4(frame)
    if outer is None:
        return False
    source, destination, protocol = outer
    return protocol == 50 and {source, destination} == set(peers)


def _summary(count: int, size: int, timestamps: list[int]) -> PcapSummary:
    first = timestamps[0] if timestamps else 0
    last = timestamps[-1] if timestamps else 0
    return PcapSummary(
        count,
        size,
        first,
        last,
        0.0 if not timestamps else (last - first) / 1_000_000_000,
    )


def derive_workload_esp(
    source_path: Path,
    destination: Path,
    window: WorkloadWindow,
    peers: tuple[str, str],
) -> PcapSummary:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    timestamps: list[int] = []
    try:
        with source_path.open("rb") as source:
            global_header, endian, fraction_to_ns = _read_header(source)
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=destination.parent, prefix=f".{destination.name}.", delete=False
            ) as output:
                temporary_name = output.name
                output.write(global_header)
                for record in _records(source, endian, fraction_to_ns):
                    if (
                        window.started_unix_ns <= record.timestamp_ns <= window.finished_unix_ns
                        and _is_peer_esp(record.payload, peers)
                    ):
                        output.write(record.header)
                        output.write(record.payload)
                        timestamps.append(record.timestamp_ns)
                output.flush()
                os.fsync(output.fileno())
        Path(temporary_name).replace(destination)
        temporary_name = None
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)
    return _summary(len(timestamps), destination.stat().st_size, timestamps)


def inspect_ml_pcap(
    path: Path, window: WorkloadWindow, peers: tuple[str, str]
) -> PcapSummary:
    timestamps: list[int] = []
    with path.open("rb") as source:
        _, endian, fraction_to_ns = _read_header(source)
        for record in _records(source, endian, fraction_to_ns):
            outer = _outer_ipv4(record.payload)
            if outer is None or outer[2] != 50:
                raise PcapFormatError("ML capture contains a non-ESP packet")
            if {outer[0], outer[1]} != set(peers):
                raise PcapFormatError("ML capture contains a wrong-peer packet")
            if not window.started_unix_ns <= record.timestamp_ns <= window.finished_unix_ns:
                raise PcapFormatError("ML capture contains an out-of-window packet")
            timestamps.append(record.timestamp_ns)
    if not timestamps:
        raise PcapFormatError("ML capture contains zero ESP records")
    return _summary(len(timestamps), path.stat().st_size, timestamps)
