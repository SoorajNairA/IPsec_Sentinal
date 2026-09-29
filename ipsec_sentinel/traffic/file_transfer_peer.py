from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import socket
import time
from typing import Iterator

from ipsec_sentinel.artifacts import write_json_atomic, write_text_atomic
from ipsec_sentinel.traffic.framing import recv_frame, send_frame
from ipsec_sentinel.traffic.payload import deterministic_bytes


def iter_deterministic_chunks(
    seed: int, purpose: str, total_bytes: int, chunk_bytes: int
) -> Iterator[bytes]:
    if total_bytes < 0:
        raise ValueError("transfer size must be nonnegative")
    if chunk_bytes <= 0:
        raise ValueError("transfer chunk size must be positive")
    remaining = total_bytes
    index = 0
    while remaining:
        size = min(chunk_bytes, remaining)
        yield deterministic_bytes(
            seed, f"file-transfer:{purpose}:chunk:{index}", size
        )
        remaining -= size
        index += 1


def expected_record(leg: dict[str, object], seed: int) -> dict[str, object]:
    digest = hashlib.sha256()
    count = 0
    for chunk in iter_deterministic_chunks(
        seed,
        str(leg["transfer_id"]),
        int(leg["payload_bytes"]),
        int(leg["write_bytes"]),
    ):
        digest.update(chunk)
        count += 1
    return {
        "transfer_id": str(leg["transfer_id"]),
        "direction": str(leg["direction"]),
        "payload_bytes": int(leg["payload_bytes"]),
        "payload_sha256": digest.hexdigest(),
        "write_bytes": int(leg["write_bytes"]),
        "writes_per_group": int(leg["writes_per_group"]),
        "group_gap_seconds": float(leg["group_gap_seconds"]),
        "write_count": count,
    }


def _decode_control(payload: bytes) -> dict[str, object]:
    value = json.loads(payload.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("file transfer control frame must be an object")
    return value


def _send_leg(
    connection: socket.socket, leg: dict[str, object], seed: int
) -> dict[str, object]:
    expected = expected_record(leg, seed)
    send_frame(
        connection,
        json.dumps(
            {"kind": "transfer", **expected},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8"),
    )
    group_size = int(leg["writes_per_group"])
    gap = float(leg["group_gap_seconds"])
    chunks = iter_deterministic_chunks(
        seed,
        str(leg["transfer_id"]),
        int(leg["payload_bytes"]),
        int(leg["write_bytes"]),
    )
    for index, chunk in enumerate(chunks, start=1):
        connection.sendall(chunk)
        if gap and index % group_size == 0 and index < int(expected["write_count"]):
            time.sleep(gap)
    completion = _decode_control(recv_frame(connection, max_size=4096))
    if completion != {"kind": "complete", **expected}:
        raise ValueError("file transfer completion does not match sent payload")
    return expected


def _receive_leg(
    connection: socket.socket, leg: dict[str, object], seed: int
) -> dict[str, object]:
    announced = _decode_control(recv_frame(connection, max_size=4096))
    expected = expected_record(leg, seed)
    if announced != {"kind": "transfer", **expected}:
        raise ValueError("file transfer announcement does not match plan")
    remaining = int(leg["payload_bytes"])
    digest = hashlib.sha256()
    received = 0
    while remaining:
        chunk = connection.recv(min(64 * 1024, remaining))
        if not chunk:
            raise EOFError(f"file transfer truncated with {remaining} bytes remaining")
        digest.update(chunk)
        received += len(chunk)
        remaining -= len(chunk)
    if received != expected["payload_bytes"] or digest.hexdigest() != expected["payload_sha256"]:
        raise ValueError("file transfer payload integrity mismatch")
    send_frame(
        connection,
        json.dumps(
            {"kind": "complete", **expected},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8"),
    )
    return expected


def execute_peer(
    config: dict[str, object], mode: str, ready_path: Path | None
) -> dict[str, object]:
    legs = config["legs"]
    if not isinstance(legs, list) or not legs:
        raise ValueError("file transfer plan must contain transfer legs")
    address = (str(config["server_ip"]), int(config["port"]))
    listener: socket.socket | None = None
    if mode == "server":
        if ready_path is None:
            raise ValueError("server mode requires ready path")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(address)
        listener.listen(1)
        write_text_atomic(ready_path, "ready\n")
        connection, _ = listener.accept()
    else:
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.bind((str(config["client_ip"]), 0))
        connection.connect(address)
    connection.settimeout(30)
    sent: list[dict[str, object]] = []
    received: list[dict[str, object]] = []
    started = time.monotonic()
    try:
        for leg in legs:
            if not isinstance(leg, dict):
                raise ValueError("malformed file transfer leg")
            sender = "client" if leg["direction"] == "client_to_server" else "server"
            if mode == sender:
                sent.append(_send_leg(connection, leg, int(config["seed"])))
            else:
                received.append(_receive_leg(connection, leg, int(config["seed"])))
    finally:
        connection.close()
        if listener is not None:
            listener.close()
    return {
        "mode": mode,
        "sent": sent,
        "received": received,
        "connection_count": 1,
        "completion_count": len(legs),
        "realized_duration_seconds": time.monotonic() - started,
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
