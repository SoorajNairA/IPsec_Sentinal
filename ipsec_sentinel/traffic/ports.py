from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import subprocess
import sys

from ipsec_sentinel.traffic.base import TrafficContext


PORT_MIN = 20_000
PORT_MAX = 29_999


@dataclass(frozen=True)
class PortSelection:
    port: int
    candidate_index: int
    purpose: str
    protocol: str
    rejected_ports: tuple[int, ...] = ()


def select_port_candidates(
    seed: int, purpose: str, protocol: str, count: int = 32
) -> tuple[int, ...]:
    if not purpose:
        raise ValueError("port purpose must be nonempty")
    if protocol not in {"tcp", "udp"}:
        raise ValueError("port protocol must be tcp or udp")
    if count < 1 or count > PORT_MAX - PORT_MIN + 1:
        raise ValueError("invalid port candidate count")
    candidates: list[int] = []
    attempt = 0
    while len(candidates) < count:
        material = (
            f"port-selection/v1:{seed}:{purpose}:{protocol}:{attempt}".encode(
                "utf-8"
            )
        )
        port = PORT_MIN + int.from_bytes(hashlib.sha256(material).digest()[:4], "big") % (
            PORT_MAX - PORT_MIN + 1
        )
        if port not in candidates:
            candidates.append(port)
        attempt += 1
    return tuple(candidates)


def _namespace_port_available(
    context: TrafficContext, port: int, protocol: str
) -> bool:
    argv = [
        "ip",
        "netns",
        "exec",
        context.server_namespace,
        sys.executable,
        "-m",
        "ipsec_sentinel.traffic.port_probe",
        "--address",
        context.server_ip,
        "--port",
        str(port),
        "--protocol",
        protocol,
    ]
    context.log.write("$ " + " ".join(argv) + "\n")
    context.log.flush()
    result = subprocess.run(
        argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=5
    )
    if result.stdout:
        context.log.write(result.stdout)
        context.log.flush()
    if result.returncode == 0:
        return True
    if result.returncode == 2:
        return False
    raise RuntimeError(
        f"port availability probe failed for {protocol}/{port}: "
        f"exit={result.returncode}"
    )


PortProbe = Callable[[TrafficContext, int, str], bool]


def choose_available_port(
    context: TrafficContext,
    seed: int,
    purpose: str,
    protocol: str,
    *,
    probe: PortProbe = _namespace_port_available,
) -> PortSelection:
    rejected: list[int] = []
    for index, port in enumerate(
        select_port_candidates(seed, purpose, protocol)
    ):
        if probe(context, port, protocol):
            return PortSelection(port, index, purpose, protocol, tuple(rejected))
        rejected.append(port)
    raise RuntimeError(
        f"no available {protocol} port for {purpose}; rejected={rejected}"
    )
