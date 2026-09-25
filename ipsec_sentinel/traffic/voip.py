from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import json
from pathlib import Path
from random import Random
import sys
import time

from ipsec_sentinel.artifacts import write_json_atomic
from ipsec_sentinel.command import run_checked
from ipsec_sentinel.traffic.base import (
    TrafficContext,
    TrafficRunResult,
    TrafficValidation,
)
from ipsec_sentinel.traffic.payload import deterministic_bytes
from ipsec_sentinel.traffic.ports import (
    PortSelection,
    choose_available_port,
    select_port_candidates,
)
from ipsec_sentinel.traffic.process import NamespaceServiceProcess


@dataclass(frozen=True)
class RtpEvent:
    offset_seconds: float
    sequence: int
    timestamp: int
    payload_bytes: int


@dataclass(frozen=True)
class RtpDirectionPlan:
    name: str
    payload_type: int
    ssrc: int
    events: tuple[RtpEvent, ...]


@dataclass(frozen=True)
class VoipPlan:
    preferred_client_port: int
    preferred_server_port: int
    packetization_interval_ms: int
    duration_seconds: float
    clock_rate_hz: int
    client_to_server: RtpDirectionPlan
    server_to_client: RtpDirectionPlan


def _direction_plan(
    random: Random,
    name: str,
    interval_ms: int,
    duration_seconds: float,
) -> RtpDirectionPlan:
    initial_sequence = random.randint(0, 65_535)
    initial_timestamp = random.randint(0, 0xFFFFFFFF)
    ssrc = random.randint(1, 0xFFFFFFFF)
    payload_type = random.choice((96, 97, 111))
    payload_center = random.choice((80, 120, 160))
    start_ticks = random.randint(0, 3)
    total_ticks = int(duration_seconds * 1000 / interval_ms)
    active = random.choice((True, False))
    remaining = 0
    sequence = initial_sequence
    events: list[RtpEvent] = []
    for tick in range(start_ticks, total_ticks):
        if remaining == 0:
            active = not active
            remaining = random.randint(12, 45) if active else random.randint(2, 12)
        remaining -= 1
        if not active:
            continue
        payload_bytes = max(48, payload_center + random.choice((-16, -8, 0, 8, 16)))
        events.append(
            RtpEvent(
                offset_seconds=round(tick * interval_ms / 1000, 6),
                sequence=sequence,
                timestamp=(initial_timestamp + tick * interval_ms * 8) & 0xFFFFFFFF,
                payload_bytes=payload_bytes,
            )
        )
        sequence = (sequence + 1) & 0xFFFF
    if not events:
        raise RuntimeError("seeded VoIP plan produced no active packets")
    return RtpDirectionPlan(name, payload_type, ssrc, tuple(events))


def resolve_voip_plan(seed: int) -> VoipPlan:
    random = Random(seed)
    interval_ms = random.choice((10, 20, 30))
    requested_duration = random.uniform(3.5, 5.5)
    ticks = max(1, round(requested_duration * 1000 / interval_ms))
    duration = round(ticks * interval_ms / 1000, 3)
    return VoipPlan(
        preferred_client_port=select_port_candidates(
            seed, "voip-client", "udp"
        )[0],
        preferred_server_port=select_port_candidates(
            seed, "voip-server", "udp"
        )[0],
        packetization_interval_ms=interval_ms,
        duration_seconds=duration,
        clock_rate_hz=8000,
        client_to_server=_direction_plan(
            random, "client_to_server", interval_ms, duration
        ),
        server_to_client=_direction_plan(
            random, "server_to_client", interval_ms, duration
        ),
    )


def _expected_records(
    seed: int,
    direction: RtpDirectionPlan,
    source_ip: str,
    destination_ip: str,
) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for event in direction.events:
        payload = deterministic_bytes(
            seed, f"voip:{direction.name}:{event.sequence}", event.payload_bytes
        )
        records.append(
            {
                "sequence": event.sequence,
                "timestamp": event.timestamp,
                "ssrc": direction.ssrc,
                "payload_type": direction.payload_type,
                "payload_bytes": event.payload_bytes,
                "payload_sha256": hashlib.sha256(payload).hexdigest(),
                "source_ip": source_ip,
                "destination_ip": destination_ip,
            }
        )
    return records


def validate_voip_result(
    plan: VoipPlan,
    client_ledger: dict[str, object],
    server_ledger: dict[str, object],
    *,
    realized_duration_seconds: float,
    seed: int = 401,
) -> TrafficValidation:
    expected_up = _expected_records(
        seed, plan.client_to_server, "10.10.0.2", "10.20.0.2"
    )
    expected_down = _expected_records(
        seed, plan.server_to_client, "10.20.0.2", "10.10.0.2"
    )
    errors: list[str] = []
    if client_ledger.get("sent") != expected_up or server_ledger.get("received") != expected_up:
        errors.append("bidirectional client-to-server RTP delivery mismatch")
    if server_ledger.get("sent") != expected_down or client_ledger.get("received") != expected_down:
        errors.append("bidirectional server-to-client RTP delivery mismatch")
    minimum_duration = plan.duration_seconds * 0.85
    maximum_duration = plan.duration_seconds + 2.0
    if not minimum_duration <= realized_duration_seconds <= maximum_duration:
        errors.append(
            f"realized call duration {realized_duration_seconds:.3f}s outside "
            f"[{minimum_duration:.3f}, {maximum_duration:.3f}]"
        )
    return TrafficValidation(
        not errors,
        {
            "expected_client_to_server_packets": len(expected_up),
            "expected_server_to_client_packets": len(expected_down),
            "received_client_to_server_packets": len(server_ledger.get("received", [])),
            "received_server_to_client_packets": len(client_ledger.get("received", [])),
            "realized_duration_seconds": realized_duration_seconds,
        },
        tuple(errors),
    )


class VoipGenerator:
    name = "voip"
    version = "1"

    def __init__(self, seed: int) -> None:
        self.seed = seed
        self.plan = resolve_voip_plan(seed)
        self.client_port: PortSelection | None = None
        self.server_port: PortSelection | None = None
        self.service: NamespaceServiceProcess | None = None
        self.client_ledger: dict[str, object] = {}
        self.server_ledger: dict[str, object] = {}
        self._result: TrafficRunResult | None = None

    def _paths(self, context: TrafficContext) -> tuple[Path, Path, Path, Path]:
        return (
            context.run_dir / "voip-plan.json",
            context.run_dir / "voip-server.json",
            context.run_dir / "voip-client.json",
            context.run_dir / "voip-ready",
        )

    def prepare(self, context: TrafficContext) -> None:
        self.server_port = choose_available_port(
            context, self.seed, "voip-server", "udp"
        )
        client_context = replace(
            context,
            server_namespace=context.client_namespace,
            server_ip=context.client_ip,
        )
        self.client_port = choose_available_port(
            client_context, self.seed, "voip-client", "udp"
        )
        plan_path, server_output, _, ready = self._paths(context)
        write_json_atomic(
            plan_path,
            {
                "seed": self.seed,
                "duration_seconds": self.plan.duration_seconds,
                "client": {"ip": context.client_ip, "port": self.client_port.port},
                "server": {"ip": context.server_ip, "port": self.server_port.port},
                "directions": {
                    "client_to_server": asdict(self.plan.client_to_server),
                    "server_to_client": asdict(self.plan.server_to_client),
                },
            },
        )
        self.service = NamespaceServiceProcess(
            context,
            module="ipsec_sentinel.traffic.rtp_peer",
            arguments=(
                "--mode", "server", "--config", str(plan_path),
                "--output", str(server_output), "--ready", str(ready),
            ),
            ready_path=ready,
            log_name="voip-server.log",
        )
        self.service.start()

    def run(self, context: TrafficContext) -> TrafficRunResult:
        if self.service is None or self.client_port is None or self.server_port is None:
            raise RuntimeError("VoIP generator is not prepared")
        plan_path, server_output, client_output, _ = self._paths(context)
        command = run_checked(
            [
                "ip", "netns", "exec", context.client_namespace, sys.executable,
                "-m", "ipsec_sentinel.traffic.rtp_peer", "--mode", "client",
                "--config", str(plan_path), "--output", str(client_output),
            ],
            timeout=self.plan.duration_seconds + 10,
            log=context.log,
        )
        deadline = time.monotonic() + 5
        while not server_output.is_file() and time.monotonic() < deadline:
            process = self.service.process
            if process is not None and process.poll() not in (None, 0):
                raise RuntimeError(f"VoIP server exited with {process.returncode}")
            time.sleep(0.05)
        if not server_output.is_file():
            raise TimeoutError("VoIP server result timed out")
        self.client_ledger = json.loads(client_output.read_text(encoding="utf-8"))
        self.server_ledger = json.loads(server_output.read_text(encoding="utf-8"))
        realized = max(
            float(self.client_ledger["realized_duration_seconds"]),
            float(self.server_ledger["realized_duration_seconds"]),
        )
        self._result = TrafficRunResult(
            {
                "client_sent_packets": len(self.client_ledger["sent"]),
                "client_received_packets": len(self.client_ledger["received"]),
                "server_sent_packets": len(self.server_ledger["sent"]),
                "server_received_packets": len(self.server_ledger["received"]),
                "realized_duration_seconds": realized,
                "process_duration_seconds": command.duration_seconds,
            }
        )
        return self._result

    def validate(
        self, context: TrafficContext, result: TrafficRunResult
    ) -> TrafficValidation:
        del context, result
        realized = 0.0 if self._result is None else float(
            self._result.metrics["realized_duration_seconds"]
        )
        return validate_voip_result(
            self.plan,
            self.client_ledger,
            self.server_ledger,
            realized_duration_seconds=realized,
            seed=self.seed,
        )

    def cleanup(self, context: TrafficContext) -> None:
        del context
        if self.service is not None:
            self.service.stop()
            self.service = None

    @staticmethod
    def _selection_metadata(selection: PortSelection | None) -> dict[str, object]:
        if selection is None:
            return {"selected_port": None, "candidate_index": None, "rejected_ports": []}
        return {
            "selected_port": selection.port,
            "candidate_index": selection.candidate_index,
            "rejected_ports": list(selection.rejected_ports),
        }

    def metadata(self) -> dict[str, object]:
        return {
            "class": self.name,
            "known_training_class": True,
            "generator": "synthetic-rtp-like",
            "generator_version": self.version,
            "seed": self.seed,
            "rtp_like_synthetic": True,
            "parameters": {
                **asdict(self.plan),
                "client_port_selection": self._selection_metadata(self.client_port),
                "server_port_selection": self._selection_metadata(self.server_port),
                "expected_packets_total": (
                    len(self.plan.client_to_server.events)
                    + len(self.plan.server_to_client.events)
                ),
            },
            "result": {} if self._result is None else dict(self._result.metrics),
        }
