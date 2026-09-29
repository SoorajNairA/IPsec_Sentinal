from pathlib import Path
import ipaddress
import struct


def ethernet_ipv4(
    source: str,
    destination: str,
    protocol: int,
    payload: bytes,
    *,
    vlan: bool = False,
) -> bytes:
    ethernet = b"\x00" * 12
    if vlan:
        ethernet += b"\x81\x00\x00\x01\x08\x00"
    else:
        ethernet += b"\x08\x00"
    total_length = 20 + len(payload)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        0,
        0,
        64,
        protocol,
        0,
        ipaddress.ip_address(source).packed,
        ipaddress.ip_address(destination).packed,
    )
    return ethernet + ipv4 + payload


def write_pcap(
    path: Path,
    records: list[tuple[int, bytes]],
    *,
    nanoseconds: bool = True,
    big_endian: bool = False,
    link_type: int = 1,
) -> None:
    endian = ">" if big_endian else "<"
    magic = {
        (False, False): b"\xd4\xc3\xb2\xa1",
        (False, True): b"\xa1\xb2\xc3\xd4",
        (True, False): b"\x4d\x3c\xb2\xa1",
        (True, True): b"\xa1\xb2\x3c\x4d",
    }[(nanoseconds, big_endian)]
    output = bytearray(magic)
    output.extend(struct.pack(f"{endian}HHIIII", 2, 4, 0, 0, 65535, link_type))
    for timestamp_ns, payload in records:
        seconds, remainder = divmod(timestamp_ns, 1_000_000_000)
        fraction = remainder if nanoseconds else remainder // 1_000
        output.extend(
            struct.pack(f"{endian}IIII", seconds, fraction, len(payload), len(payload))
        )
        output.extend(payload)
    path.write_bytes(bytes(output))
