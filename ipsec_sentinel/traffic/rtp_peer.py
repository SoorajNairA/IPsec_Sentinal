from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import socket
import struct
import threading
import time

from ipsec_sentinel.artifacts import write_json_atomic, write_text_atomic
from ipsec_sentinel.traffic.payload import deterministic_bytes


RTP_HEADER = struct.Struct("!BBHII")
START_TOKEN = b"IPSEC_SENTINEL_RTP_START_V1"


def build_rtp_packet(
    *, payload_type: int, sequence: int, timestamp: int, ssrc: int, payload: bytes
) -> bytes:
    if not 0 <= payload_type <= 127:
        raise ValueError("RTP payload type must fit seven bits")
    return RTP_HEADER.pack(
        0x80,
        payload_type,
        sequence & 0xFFFF,
        timestamp & 0xFFFFFFFF,
        ssrc & 0xFFFFFFFF,
    ) + payload


def parse_rtp_packet(packet: bytes) -> dict[str, object]:
    if len(packet) < RTP_HEADER.size:
        raise ValueError("RTP packet is shorter than the fixed header")
    first, second, sequence, timestamp, ssrc = RTP_HEADER.unpack(
        packet[: RTP_HEADER.size]
    )
    version = first >> 6
    if version != 2:
        raise ValueError(f"unsupported RTP version: {version}")
    if first & 0x3F or second & 0x80:
        raise ValueError("RTP extensions, CSRCs, padding, and markers are unsupported")
    return {
        "version": version,
        "payload_type": second & 0x7F,
        "sequence": sequence,
        "timestamp": timestamp,
        "ssrc": ssrc,
        "payload": packet[RTP_HEADER.size :],
    }


def _record(
    parsed: dict[str, object], source_ip: str, destination_ip: str
) -> dict[str, object]:
    payload = parsed["payload"]
    assert isinstance(payload, bytes)
    return {
        "sequence": parsed["sequence"],
        "timestamp": parsed["timestamp"],
        "ssrc": parsed["ssrc"],
        "payload_type": parsed["payload_type"],
        "payload_bytes": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
    }


def _send_direction(
    transport: socket.socket,
    destination: tuple[str, int],
    source_ip: str,
    direction: dict[str, object],
    seed: int,
    started: float,
    ledger: list[dict[str, object]],
) -> None:
    events = direction["events"]
    assert isinstance(events, list)
    for event in events:
        assert isinstance(event, dict)
        deadline = started + float(event["offset_seconds"])
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
        payload = deterministic_bytes(
            seed,
            f"voip:{direction['name']}:{event['sequence']}",
            int(event["payload_bytes"]),
        )
        packet = build_rtp_packet(
            payload_type=int(direction["payload_type"]),
            sequence=int(event["sequence"]),
            timestamp=int(event["timestamp"]),
            ssrc=int(direction["ssrc"]),
            payload=payload,
        )
        transport.sendto(packet, destination)
        ledger.append(_record(parse_rtp_packet(packet), source_ip, destination[0]))


def _receive_direction(
    transport: socket.socket,
    expected: int,
    expected_source_ip: str,
    destination_ip: str,
    deadline: float,
    ledger: list[dict[str, object]],
) -> None:
    transport.settimeout(0.2)
    while len(ledger) < expected and time.monotonic() < deadline:
        try:
            packet, address = transport.recvfrom(65_535)
        except socket.timeout:
            continue
        if address[0] != expected_source_ip:
            continue
        ledger.append(
            _record(parse_rtp_packet(packet), address[0], destination_ip)
        )


def execute_peer(
    config: dict[str, object], mode: str, ready_path: Path | None
) -> dict[str, object]:
    client = config["client"]
    server = config["server"]
    directions = config["directions"]
    assert isinstance(client, dict) and isinstance(server, dict)
    assert isinstance(directions, dict)
    local = client if mode == "client" else server
    remote = server if mode == "client" else client
    outgoing_name = "client_to_server" if mode == "client" else "server_to_client"
    incoming_name = "server_to_client" if mode == "client" else "client_to_server"
    outgoing = directions[outgoing_name]
    incoming = directions[incoming_name]
    assert isinstance(outgoing, dict) and isinstance(incoming, dict)

    sent: list[dict[str, object]] = []
    received: list[dict[str, object]] = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as transport:
        transport.bind((str(local["ip"]), int(local["port"])))
        if mode == "server":
            if ready_path is None:
                raise ValueError("server mode requires a ready path")
            write_text_atomic(ready_path, "ready\n")
            transport.settimeout(15)
            while True:
                message, address = transport.recvfrom(4096)
                if message == START_TOKEN and address[0] == str(remote["ip"]):
                    break
        else:
            transport.sendto(START_TOKEN, (str(remote["ip"]), int(remote["port"])))

        started = time.monotonic() + 0.1
        incoming_events = incoming["events"]
        assert isinstance(incoming_events, list)
        receive = threading.Thread(
            target=_receive_direction,
            args=(
                transport,
                len(incoming_events),
                str(remote["ip"]),
                str(local["ip"]),
                started + float(config["duration_seconds"]) + 3.0,
                received,
            ),
        )
        send = threading.Thread(
            target=_send_direction,
            args=(
                transport,
                (str(remote["ip"]), int(remote["port"])),
                str(local["ip"]),
                outgoing,
                int(config["seed"]),
                started,
                sent,
            ),
        )
        receive.start()
        send.start()
        send.join()
        receive.join()
        realized = max(0.0, time.monotonic() - started)
    return {
        "mode": mode,
        "sent": sent,
        "received": received,
        "realized_duration_seconds": realized,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("client", "server"), required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ready", type=Path)
    args = parser.parse_args(argv)
    config = json.loads(args.config.read_text(encoding="utf-8"))
    write_json_atomic(args.output, execute_peer(config, args.mode, args.ready))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
