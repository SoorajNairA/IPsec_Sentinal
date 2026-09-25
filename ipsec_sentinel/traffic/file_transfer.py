from __future__ import annotations

from dataclasses import asdict, dataclass
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
from ipsec_sentinel.traffic.file_transfer_peer import expected_record
from ipsec_sentinel.traffic.ports import (
    PortSelection,
    choose_available_port,
    select_port_candidates,
)
from ipsec_sentinel.traffic.process import NamespaceServiceProcess


@dataclass(frozen=True)
class FileTransferLeg:
    transfer_id: str
    direction: str
    payload_bytes: int
    write_bytes: int
    writes_per_group: int
    group_gap_seconds: float


@dataclass(frozen=True)
class FileTransferPlan:
    preferred_port: int
    direction: str
    legs: tuple[FileTransferLeg, ...]
    total_payload_bytes: int


def resolve_file_transfer_plan(seed: int) -> FileTransferPlan:
    random = Random(seed)
    direction = random.choice(("upload", "download", "bidirectional"))
    total_bytes = random.randint(1024, 8192) * 1024
    directions = {
        "upload": ("client_to_server",),
        "download": ("server_to_client",),
        "bidirectional": ("client_to_server", "server_to_client"),
    }[direction]
    if len(directions) == 1:
        sizes = (total_bytes,)
    else:
        first = total_bytes * random.randint(35, 65) // 100
        sizes = (first, total_bytes - first)
    legs = tuple(
        FileTransferLeg(
            transfer_id=f"transfer-{seed}-{index}",
            direction=leg_direction,
            payload_bytes=size,
            write_bytes=random.choice((8192, 16384, 32768, 65536)),
            writes_per_group=random.choice((2, 4, 8, 16)),
            group_gap_seconds=random.choice((0.0, 0.001, 0.002, 0.004)),
        )
        for index, (leg_direction, size) in enumerate(
            zip(directions, sizes, strict=True), start=1
        )
    )
    return FileTransferPlan(
        preferred_port=select_port_candidates(seed, "file_transfer", "tcp")[0],
        direction=direction,
        legs=legs,
        total_payload_bytes=total_bytes,
    )


def expected_transfer_records(
    plan: FileTransferPlan, seed: int
) -> list[dict[str, object]]:
    return [expected_record(asdict(leg), seed) for leg in plan.legs]


def validate_file_transfer_result(
    plan: FileTransferPlan,
    client_ledger: dict[str, object],
    server_ledger: dict[str, object],
    *,
    seed: int,
) -> TrafficValidation:
    expected = expected_transfer_records(plan, seed)
    uploads = [item for item in expected if item["direction"] == "client_to_server"]
    downloads = [item for item in expected if item["direction"] == "server_to_client"]
    errors: list[str] = []
    if client_ledger.get("sent") != uploads or server_ledger.get("received") != uploads:
        errors.append("upload byte count or integrity evidence does not match plan")
    if server_ledger.get("sent") != downloads or client_ledger.get("received") != downloads:
        errors.append("download byte count or integrity evidence does not match plan")
    if client_ledger.get("connection_count") != 1 or server_ledger.get("connection_count") != 1:
        errors.append("file transfer did not use one persistent connection")
    if (
        client_ledger.get("completion_count") != len(expected)
        or server_ledger.get("completion_count") != len(expected)
    ):
        errors.append("file transfer completion evidence is incomplete")
    return TrafficValidation(
        not errors,
        {
            "direction": plan.direction,
            "planned_transfers": len(expected),
            "planned_payload_bytes": plan.total_payload_bytes,
            "upload_bytes": sum(int(item["payload_bytes"]) for item in uploads),
            "download_bytes": sum(int(item["payload_bytes"]) for item in downloads),
        },
        tuple(errors),
    )


class FileTransferGenerator:
    name = "file_transfer"
    version = "1"

    def __init__(self, seed: int) -> None:
        self.seed = seed
        self.plan = resolve_file_transfer_plan(seed)
        self.port_selection: PortSelection | None = None
        self.service: NamespaceServiceProcess | None = None
        self.client_ledger: dict[str, object] = {}
        self.server_ledger: dict[str, object] = {}
        self._result: TrafficRunResult | None = None

    def _paths(self, context: TrafficContext) -> tuple[Path, Path, Path, Path]:
        return (
            context.run_dir / "file-transfer-plan.json",
            context.run_dir / "file-transfer-server.json",
            context.run_dir / "file-transfer-client.json",
            context.run_dir / "file-transfer-ready",
        )

    def prepare(self, context: TrafficContext) -> None:
        self.port_selection = choose_available_port(
            context, self.seed, "file_transfer", "tcp"
        )
        plan_path, server_output, _, ready = self._paths(context)
        write_json_atomic(
            plan_path,
            {
                "seed": self.seed,
                "server_ip": context.server_ip,
                "client_ip": context.client_ip,
                "port": self.port_selection.port,
                "legs": [asdict(leg) for leg in self.plan.legs],
            },
        )
        self.service = NamespaceServiceProcess(
            context,
            module="ipsec_sentinel.traffic.file_transfer_peer",
            arguments=(
                "--mode", "server", "--config", str(plan_path),
                "--output", str(server_output), "--ready", str(ready),
            ),
            ready_path=ready,
            log_name="file-transfer-server.log",
        )
        self.service.start()

    def run(self, context: TrafficContext) -> TrafficRunResult:
        if self.service is None or self.port_selection is None:
            raise RuntimeError("File Transfer generator is not prepared")
        plan_path, server_output, client_output, _ = self._paths(context)
        command = run_checked(
            [
                "ip", "netns", "exec", context.client_namespace, sys.executable,
                "-m", "ipsec_sentinel.traffic.file_transfer_peer", "--mode", "client",
                "--config", str(plan_path), "--output", str(client_output),
            ],
            timeout=60,
            log=context.log,
        )
        deadline = time.monotonic() + 5
        while not server_output.is_file() and time.monotonic() < deadline:
            process = self.service.process
            if process is not None and process.poll() not in (None, 0):
                raise RuntimeError(f"File Transfer server exited with {process.returncode}")
            time.sleep(0.05)
        if not server_output.is_file():
            raise TimeoutError("File Transfer server result timed out")
        self.client_ledger = json.loads(client_output.read_text(encoding="utf-8"))
        self.server_ledger = json.loads(server_output.read_text(encoding="utf-8"))
        realized = max(
            float(self.client_ledger["realized_duration_seconds"]),
            float(self.server_ledger["realized_duration_seconds"]),
        )
        records = expected_transfer_records(self.plan, self.seed)
        self._result = TrafficRunResult(
            {
                "direction": self.plan.direction,
                "payload_bytes": self.plan.total_payload_bytes,
                "write_count": sum(int(item["write_count"]) for item in records),
                "completion_count": len(records),
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
        return validate_file_transfer_result(
            self.plan, self.client_ledger, self.server_ledger, seed=self.seed
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
            "generator": "checksum-verified-bulk-tcp",
            "generator_version": self.version,
            "seed": self.seed,
            "parameters": {
                "preferred_port": self.plan.preferred_port,
                "selected_port": None if selection is None else selection.port,
                "candidate_index": None if selection is None else selection.candidate_index,
                "rejected_ports": [] if selection is None else list(selection.rejected_ports),
                "direction": self.plan.direction,
                "total_payload_bytes": self.plan.total_payload_bytes,
                "legs": [asdict(leg) for leg in self.plan.legs],
            },
            "result": {} if self._result is None else dict(self._result.metrics),
        }
