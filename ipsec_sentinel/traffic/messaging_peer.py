from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import socket
import time
from typing import Any

from ipsec_sentinel.artifacts import write_json_atomic, write_text_atomic
from ipsec_sentinel.traffic.framing import recv_frame, send_frame
from ipsec_sentinel.traffic.payload import deterministic_bytes


def _value(message: object, name: str) -> Any:
    if isinstance(message, dict):
        return message[name]
    return getattr(message, name)


def build_message_frame(message: object, seed: int) -> bytes:
    message_id = str(_value(message, "message_id"))
    direction = str(_value(message, "direction"))
    size = int(_value(message, "payload_bytes"))
    payload = deterministic_bytes(seed, f"messaging:{message_id}", size)
    header = {
        "message_id": message_id,
        "direction": direction,
        "payload_bytes": size,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
    }
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    ) + b"\n" + payload


def parse_message_frame(frame: bytes) -> dict[str, object]:
    header_bytes, separator, payload = frame.partition(b"\n")
    if not separator:
        raise ValueError("messaging frame lacks header separator")
    header = json.loads(header_bytes.decode("utf-8"))
    required = {"message_id", "direction", "payload_bytes", "payload_sha256"}
    if not isinstance(header, dict) or set(header) != required:
        raise ValueError("malformed messaging frame header")
    if header["direction"] not in {"client_to_server", "server_to_client"}:
        raise ValueError("invalid messaging direction")
    if len(payload) != int(header["payload_bytes"]):
        raise ValueError("messaging payload size mismatch")
    if hashlib.sha256(payload).hexdigest() != header["payload_sha256"]:
        raise ValueError("messaging payload digest mismatch")
    return {
        "message_id": str(header["message_id"]),
        "direction": str(header["direction"]),
        "payload_bytes": len(payload),
        "payload_sha256": str(header["payload_sha256"]),
    }


def execute_peer(
    config: dict[str, object], mode: str, ready_path: Path | None
) -> dict[str, object]:
    messages = config["messages"]
    if not isinstance(messages, list):
        raise ValueError("messaging plan must contain a message list")
    server_address = (str(config["server_ip"]), int(config["port"]))
    listener: socket.socket | None = None
    if mode == "server":
        if ready_path is None:
            raise ValueError("server mode requires ready path")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(server_address)
        listener.listen(1)
        write_text_atomic(ready_path, "ready\n")
        connection, _ = listener.accept()
    else:
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.bind((str(config["client_ip"]), 0))
        connection.connect(server_address)
    connection.settimeout(10)
    connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sent: list[dict[str, object]] = []
    received: list[dict[str, object]] = []
    started = time.monotonic()
    try:
        for message in messages:
            if not isinstance(message, dict):
                raise ValueError("malformed messaging message")
            sender_mode = (
                "client"
                if message["direction"] == "client_to_server"
                else "server"
            )
            if mode == sender_mode:
                time.sleep(float(message["idle_before_seconds"]))
                frame = build_message_frame(message, int(config["seed"]))
                send_frame(connection, frame)
                sent.append(parse_message_frame(frame))
            else:
                received.append(recv_and_parse(connection))
    finally:
        connection.close()
        if listener is not None:
            listener.close()
    return {
        "mode": mode,
        "sent": sent,
        "received": received,
        "connection_count": 1,
        "realized_duration_seconds": time.monotonic() - started,
    }


def recv_and_parse(connection: socket.socket) -> dict[str, object]:
    return parse_message_frame(recv_frame(connection))


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
