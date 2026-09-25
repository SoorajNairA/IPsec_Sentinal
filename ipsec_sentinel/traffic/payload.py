from __future__ import annotations

import hashlib


def deterministic_bytes(seed: int, purpose: str, size: int) -> bytes:
    if not purpose:
        raise ValueError("payload purpose must be nonempty")
    if size < 0:
        raise ValueError("payload size must be nonnegative")
    output = bytearray()
    counter = 0
    while len(output) < size:
        material = (
            f"deterministic-payload/v1:{seed}:{purpose}:{counter}".encode("utf-8")
        )
        output.extend(hashlib.sha256(material).digest())
        counter += 1
    return bytes(output[:size])
