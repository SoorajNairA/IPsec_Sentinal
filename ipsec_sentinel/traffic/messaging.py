from __future__ import annotations

from dataclasses import asdict, dataclass
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
class MessagePlan:
    message_id: str
    direction: str
    payload_bytes: int
    burst_index: int
    position_in_burst: int
    idle_before_seconds: float
    reply_to: str | None


@dataclass(frozen=True)
class MessagingPlan:
    preferred_port: int
    messages: tuple[MessagePlan, ...]
    expected_duration_seconds: float


def _burst_sizes(random: Random, message_count: int, burst_count: int) -> list[int]:
    sizes = [1] * burst_count
    for _ in range(message_count - burst_count):
        sizes[random.randrange(burst_count)] += 1
    return sizes


def resolve_messaging_plan(seed: int) -> MessagingPlan:
    random = Random(seed)
    message_count = random.randint(12, 24)
    burst_count = random.randint(3, min(6, message_count))
    sizes = _burst_sizes(random, message_count, burst_count)
    direction = random.choice(("client_to_server", "server_to_client"))
    messages: list[MessagePlan] = []
    previous_id: str | None = None
    large_index = random.randrange(message_count)
    ordinal = 0
    for burst_index, burst_size in enumerate(sizes):
        for position in range(burst_size):
            if ordinal and random.random() < 0.58:
                direction = (
                    "server_to_client"
                    if direction == "client_to_server"
                    else "client_to_server"
                )
            payload_bytes = (
                random.randint(640, 2048)
                if ordinal == large_index or random.random() < 0.12
                else random.randint(12, 240)
            )
            message_id = f"msg-{seed}-{ordinal + 1:03d}"
            messages.append(
                MessagePlan(
                    message_id=message_id,
                    direction=direction,
                    payload_bytes=payload_bytes,
                    burst_index=burst_index,
                    position_in_burst=position,
                    idle_before_seconds=(
                        round(random.uniform(0.08, 0.3), 3)
                        if position == 0
                        else round(random.uniform(0.004, 0.025), 3)
                    ),
                    reply_to=(previous_id if ordinal and random.random() < 0.7 else None),
                )
            )
            previous_id = message_id
            ordinal += 1
    directions = {item.direction for item in messages}
    if len(directions) == 1:
        last = messages[-1]
        messages[-1] = MessagePlan(
            last.message_id,
            "server_to_client" if last.direction == "client_to_server" else "client_to_server",
            last.payload_bytes,
            last.burst_index,
            last.position_in_burst,
            last.idle_before_seconds,
            last.reply_to,
        )
    return MessagingPlan(
        preferred_port=select_port_candidates(seed, "messaging", "tcp")[0],
        messages=tuple(messages),
        expected_duration_seconds=round(
            sum(item.idle_before_seconds for item in messages), 6
        ),
    )


def expected_message_records(
    plan: MessagingPlan, seed: int
) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for message in plan.messages:
        payload = deterministic_bytes(
            seed, f"messaging:{message.message_id}", message.payload_bytes
        )
        records.append(
            {
                "message_id": message.message_id,
                "direction": message.direction,
                "payload_bytes": message.payload_bytes,
                "payload_sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    return records


def validate_messaging_result(
    plan: MessagingPlan,
    client_ledger: dict[str, object],
    server_ledger: dict[str, object],
    *,
    realized_duration_seconds: float,
    seed: int,
) -> TrafficValidation:
    expected = expected_message_records(plan, seed)
    expected_up = [item for item in expected if item["direction"] == "client_to_server"]
    expected_down = [item for item in expected if item["direction"] == "server_to_client"]
    errors: list[str] = []
    if client_ledger.get("sent") != expected_up or server_ledger.get("received") != expected_up:
        errors.append("client/server endpoint ledgers disagree for client-to-server messages")
    if server_ledger.get("sent") != expected_down or client_ledger.get("received") != expected_down:
        errors.append("client/server endpoint ledgers disagree for server-to-client messages")
    if client_ledger.get("connection_count") != 1 or server_ledger.get("connection_count") != 1:
        errors.append("messaging workload did not use one persistent connection")
    minimum = plan.expected_duration_seconds * 0.75
    maximum = plan.expected_duration_seconds + 2.0
    if not minimum <= realized_duration_seconds <= maximum:
        errors.append(
            f"realized messaging duration {realized_duration_seconds:.3f}s outside "
            f"[{minimum:.3f}, {maximum:.3f}]"
        )
    return TrafficValidation(
        not errors,
        {
            "planned_messages": len(expected),
            "planned_bursts": len({item.burst_index for item in plan.messages}),
            "client_to_server_messages": len(expected_up),
            "server_to_client_messages": len(expected_down),
            "realized_duration_seconds": realized_duration_seconds,
        },
        tuple(errors),
    )


class MessagingGenerator:
    name = "messaging"
    version = "1"

    def __init__(self, seed: int) -> None:
        self.seed = seed
        self.plan = resolve_messaging_plan(seed)
        self.port_selection: PortSelection | None = None
        self.service: NamespaceServiceProcess | None = None
        self.client_ledger: dict[str, object] = {}
        self.server_ledger: dict[str, object] = {}
        self._result: TrafficRunResult | None = None

    def _paths(self, context: TrafficContext) -> tuple[Path, Path, Path, Path]:
        return (
            context.run_dir / "messaging-plan.json",
            context.run_dir / "messaging-server.json",
            context.run_dir / "messaging-client.json",
            context.run_dir / "messaging-ready",
        )

    def prepare(self, context: TrafficContext) -> None:
        self.port_selection = choose_available_port(
            context, self.seed, "messaging", "tcp"
        )
        plan_path, server_output, _, ready = self._paths(context)
        write_json_atomic(
            plan_path,
            {
                "seed": self.seed,
                "server_ip": context.server_ip,
                "client_ip": context.client_ip,
                "port": self.port_selection.port,
                "messages": [asdict(message) for message in self.plan.messages],
            },
        )
        self.service = NamespaceServiceProcess(
            context,
            module="ipsec_sentinel.traffic.messaging_peer",
            arguments=(
                "--mode", "server", "--config", str(plan_path),
                "--output", str(server_output), "--ready", str(ready),
            ),
            ready_path=ready,
            log_name="messaging-server.log",
        )
        self.service.start()

    def run(self, context: TrafficContext) -> TrafficRunResult:
        if self.service is None or self.port_selection is None:
            raise RuntimeError("Messaging generator is not prepared")
        plan_path, server_output, client_output, _ = self._paths(context)
        command = run_checked(
            [
                "ip", "netns", "exec", context.client_namespace, sys.executable,
                "-m", "ipsec_sentinel.traffic.messaging_peer", "--mode", "client",
                "--config", str(plan_path), "--output", str(client_output),
            ],
            timeout=max(20.0, self.plan.expected_duration_seconds + 10),
            log=context.log,
        )
        deadline = time.monotonic() + 5
        while not server_output.is_file() and time.monotonic() < deadline:
            process = self.service.process
            if process is not None and process.poll() not in (None, 0):
                raise RuntimeError(f"Messaging server exited with {process.returncode}")
            time.sleep(0.05)
        if not server_output.is_file():
            raise TimeoutError("Messaging server result timed out")
        self.client_ledger = json.loads(client_output.read_text(encoding="utf-8"))
        self.server_ledger = json.loads(server_output.read_text(encoding="utf-8"))
        realized = max(
            float(self.client_ledger["realized_duration_seconds"]),
            float(self.server_ledger["realized_duration_seconds"]),
        )
        self._result = TrafficRunResult(
            {
                "client_sent": len(self.client_ledger["sent"]),
                "client_received": len(self.client_ledger["received"]),
                "server_sent": len(self.server_ledger["sent"]),
                "server_received": len(self.server_ledger["received"]),
                "connection_count": 1,
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
        return validate_messaging_result(
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

    def metadata(self) -> dict[str, object]:
        selection = self.port_selection
        return {
            "class": self.name,
            "known_training_class": True,
            "generator": "persistent-length-framed-messaging",
            "generator_version": self.version,
            "seed": self.seed,
            "parameters": {
                "preferred_port": self.plan.preferred_port,
                "selected_port": None if selection is None else selection.port,
                "candidate_index": None if selection is None else selection.candidate_index,
                "rejected_ports": [] if selection is None else list(selection.rejected_ports),
                "messages": [asdict(message) for message in self.plan.messages],
                "expected_duration_seconds": self.plan.expected_duration_seconds,
                "expected_messages_total": len(self.plan.messages),
            },
            "result": {} if self._result is None else dict(self._result.metrics),
        }
