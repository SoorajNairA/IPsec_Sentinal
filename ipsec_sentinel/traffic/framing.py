from __future__ import annotations

import socket


MAX_FRAME_BYTES = 16 * 1024 * 1024


def recv_exact(stream: socket.socket, size: int) -> bytes:
    if size < 0:
        raise ValueError("receive size must be nonnegative")
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.recv(remaining)
        if not chunk:
            raise EOFError(f"truncated frame: missing {remaining} bytes")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_frame(stream: socket.socket, payload: bytes) -> None:
    if len(payload) > MAX_FRAME_BYTES:
        raise ValueError("frame exceeds maximum size")
    stream.sendall(len(payload).to_bytes(4, "big") + payload)


def recv_frame(
    stream: socket.socket, *, max_size: int = MAX_FRAME_BYTES
) -> bytes:
    size = int.from_bytes(recv_exact(stream, 4), "big")
    if size > max_size:
        raise ValueError(f"frame size {size} exceeds maximum {max_size}")
    return recv_exact(stream, size)
