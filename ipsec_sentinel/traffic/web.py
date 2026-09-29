from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
from random import Random
import sys

from ipsec_sentinel.artifacts import write_json_atomic
from ipsec_sentinel.command import run_checked
from ipsec_sentinel.traffic.base import (
    TrafficContext,
    TrafficRunResult,
    TrafficValidation,
)
from ipsec_sentinel.traffic.http_service import HttpServiceProcess
from ipsec_sentinel.traffic.ports import (
    PortSelection,
    choose_available_port,
    select_port_candidates,
)


@dataclass(frozen=True)
class WebRequest:
    path: str
    expected_bytes: int
    content_type: str
    think_seconds: float


@dataclass(frozen=True)
class WebPlan:
    preferred_port: int
    requests: tuple[WebRequest, ...]


def resolve_web_plan(seed: int) -> WebPlan:
    random = Random(seed)
    pages = [
        ("/pages/home.html", random.choice((4096, 6144, 8192)), "text/html"),
        ("/pages/about.html", random.choice((3072, 5120, 7168)), "text/html"),
        ("/assets/app.css", random.choice((8192, 12288, 16384)), "text/css"),
        (
            "/assets/app.js",
            random.choice((16384, 24576, 32768)),
            "application/javascript",
        ),
        (
            "/assets/hero.bin",
            random.choice((65536, 98304, 131072)),
            "application/octet-stream",
        ),
        (
            "/assets/icon.bin",
            random.choice((4096, 8192, 12288)),
            "application/octet-stream",
        ),
    ]
    random.shuffle(pages)
    request_count = random.randint(6, len(pages))
    requests = tuple(
        WebRequest(path, size, content_type, random.choice((0.02, 0.05, 0.1)))
        for path, size, content_type in pages[:request_count]
    )
    return WebPlan(
        preferred_port=select_port_candidates(seed, "web", "tcp")[0],
        requests=requests,
    )


def _core(record: dict[str, object]) -> dict[str, object]:
    return {key: record.get(key) for key in ("path", "status", "bytes")}


def validate_web_result(
    plan: WebPlan,
    client_records: list[dict[str, object]],
    server_receipts: list[dict[str, object]],
) -> TrafficValidation:
    expected = [
        {"path": item.path, "status": 200, "bytes": item.expected_bytes}
        for item in plan.requests
    ]
    client = [_core(item) for item in client_records]
    receipts = [_core(item) for item in server_receipts]
    errors: list[str] = []
    if client != expected:
        errors.append("client records do not match the planned web workload")
    if receipts != expected:
        errors.append("server receipt records do not match the planned web workload")
    return TrafficValidation(
        not errors,
        {
            "planned_requests": len(expected),
            "client_records": len(client),
            "server_receipts": len(receipts),
        },
        tuple(errors),
    )


class WebGenerator:
    name = "web"
    version = "2"

    def __init__(self, seed: int) -> None:
        self.seed = seed
        self.plan = resolve_web_plan(seed)
        self.service: HttpServiceProcess | None = None
        self.port_selection: PortSelection | None = None
        self.client_records: list[dict[str, object]] = []
        self.server_receipts: list[dict[str, object]] = []
        self._result: TrafficRunResult | None = None

    def _paths(self, context: TrafficContext) -> tuple[Path, Path, Path, Path, Path]:
        return (
            context.run_dir / "http-service.json",
            context.run_dir / "http-receipts.jsonl",
            context.run_dir / "http-ready",
            context.run_dir / "http-client.json",
            context.run_dir / "http-results.json",
        )

    def prepare(self, context: TrafficContext) -> None:
        service_path, receipts, ready, _, _ = self._paths(context)
        self.port_selection = choose_available_port(
            context, self.seed, "web", "tcp"
        )
        write_json_atomic(
            service_path,
            {
                "bind_address": context.server_ip,
                "port": self.port_selection.port,
                "seed": self.seed,
                "resources": [
                    {
                        "path": request.path,
                        "size": request.expected_bytes,
                        "content_type": request.content_type,
                    }
                    for request in self.plan.requests
                ],
            },
        )
        self.service = HttpServiceProcess(context, service_path, receipts, ready)
        self.service.start()

    def run(self, context: TrafficContext) -> TrafficRunResult:
        if self.port_selection is None:
            raise RuntimeError("web generator is not prepared")
        _, receipts, _, client_path, results_path = self._paths(context)
        write_json_atomic(
            client_path,
            {
                "server_ip": context.server_ip,
                "port": self.port_selection.port,
                "timeout_seconds": 5,
                "requests": [asdict(request) for request in self.plan.requests],
            },
        )
        command = run_checked(
            [
                "ip",
                "netns",
                "exec",
                context.client_namespace,
                sys.executable,
                "-m",
                "ipsec_sentinel.traffic.http_client",
                "--plan",
                str(client_path),
                "--output",
                str(results_path),
            ],
            timeout=30,
            log=context.log,
        )
        self.client_records = list(
            json.loads(results_path.read_text(encoding="utf-8"))["records"]
        )
        self.server_receipts = [
            json.loads(line)
            for line in receipts.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self._result = TrafficRunResult(
            {
                "client_records": self.client_records,
                "server_receipts": self.server_receipts,
                "duration_seconds": command.duration_seconds,
            }
        )
        return self._result

    def validate(
        self, context: TrafficContext, result: TrafficRunResult
    ) -> TrafficValidation:
        del context, result
        return validate_web_result(self.plan, self.client_records, self.server_receipts)

    def cleanup(self, context: TrafficContext) -> None:
        del context
        if self.service is not None:
            self.service.stop()
            self.service = None

    def metadata(self) -> dict[str, object]:
        return {
            "class": self.name,
            "known_training_class": True,
            "generator": "local-http",
            "generator_version": self.version,
            "seed": self.seed,
            "parameters": {
                "preferred_port": self.plan.preferred_port,
                "selected_port": None if self.port_selection is None else self.port_selection.port,
                "candidate_index": None if self.port_selection is None else self.port_selection.candidate_index,
                "rejected_ports": [] if self.port_selection is None else list(self.port_selection.rejected_ports),
                "requests": [asdict(request) for request in self.plan.requests],
            },
            "result": {} if self._result is None else dict(self._result.metrics),
        }
