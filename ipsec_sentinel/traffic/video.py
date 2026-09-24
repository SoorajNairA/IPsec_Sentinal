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


@dataclass(frozen=True)
class VideoProfile:
    name: str
    bitrate_bps: int
    segment_duration_seconds: float


@dataclass(frozen=True)
class VideoSegment:
    sequence: int
    path: str
    expected_bytes: int
    pace_after_seconds: float


@dataclass(frozen=True)
class VideoPlan:
    port: int
    profile: VideoProfile
    target_duration_seconds: float
    segments: tuple[VideoSegment, ...]


PROFILES = (
    VideoProfile("low", 600_000, 1.0),
    VideoProfile("medium", 1_000_000, 1.0),
    VideoProfile("high", 1_500_000, 1.0),
)


def resolve_video_plan(seed: int) -> VideoPlan:
    random = Random(seed)
    profile = random.choice(PROFILES)
    segment_count = random.randint(5, 7)
    sequence_start = random.randint(0, 200)
    segments = tuple(
        VideoSegment(
            sequence=sequence_start + index,
            path=f"/video/segment-{sequence_start + index:04d}.bin",
            expected_bytes=max(
                1,
                round(
                    profile.bitrate_bps
                    * profile.segment_duration_seconds
                    / 8
                    * random.uniform(0.9, 1.1)
                ),
            ),
            pace_after_seconds=(
                profile.segment_duration_seconds if index < segment_count - 1 else 0.0
            ),
        )
        for index in range(segment_count)
    )
    return VideoPlan(
        8081,
        profile,
        sum(segment.pace_after_seconds for segment in segments),
        segments,
    )


def _core(record: dict[str, object]) -> dict[str, object]:
    return {key: record.get(key) for key in ("path", "status", "bytes")}


def validate_video_result(
    plan: VideoPlan,
    client_records: list[dict[str, object]],
    server_receipts: list[dict[str, object]],
    *,
    realized_duration_seconds: float,
) -> TrafficValidation:
    expected = [
        {"path": item.path, "status": 200, "bytes": item.expected_bytes}
        for item in plan.segments
    ]
    client = [_core(item) for item in client_records]
    receipts = [_core(item) for item in server_receipts]
    errors: list[str] = []
    if len(client) < 5 or client != expected:
        errors.append("client segment records do not match the video plan")
    if len(receipts) < 5 or receipts != expected:
        errors.append("server segment receipts do not match the video plan")
    minimum = plan.target_duration_seconds * 0.8
    maximum = plan.target_duration_seconds * 1.5
    if not minimum <= realized_duration_seconds <= maximum:
        errors.append(
            f"realized video duration {realized_duration_seconds:.3f}s outside "
            f"[{minimum:.3f}, {maximum:.3f}]"
        )
    return TrafficValidation(
        not errors,
        {
            "planned_segments": len(expected),
            "client_segments": len(client),
            "server_segments": len(receipts),
            "expected_bytes": sum(item.expected_bytes for item in plan.segments),
            "realized_duration_seconds": realized_duration_seconds,
        },
        tuple(errors),
    )


class VideoGenerator:
    name = "video"
    version = "1"

    def __init__(self, seed: int) -> None:
        self.seed = seed
        self.plan = resolve_video_plan(seed)
        self.service: HttpServiceProcess | None = None
        self.client_records: list[dict[str, object]] = []
        self.server_receipts: list[dict[str, object]] = []
        self.realized_duration_seconds = 0.0
        self._result: TrafficRunResult | None = None

    def _paths(self, context: TrafficContext) -> tuple[Path, Path, Path, Path, Path]:
        return (
            context.run_dir / "video-service.json",
            context.run_dir / "video-receipts.jsonl",
            context.run_dir / "video-ready",
            context.run_dir / "video-client.json",
            context.run_dir / "video-results.json",
        )

    def prepare(self, context: TrafficContext) -> None:
        service_path, receipts, ready, _, _ = self._paths(context)
        write_json_atomic(
            service_path,
            {
                "bind_address": context.server_ip,
                "port": self.plan.port,
                "seed": self.seed,
                "resources": [
                    {
                        "path": segment.path,
                        "size": segment.expected_bytes,
                        "content_type": "video/mp2t",
                    }
                    for segment in self.plan.segments
                ],
            },
        )
        self.service = HttpServiceProcess(context, service_path, receipts, ready)
        self.service.start()

    def run(self, context: TrafficContext) -> TrafficRunResult:
        _, receipts, _, client_path, results_path = self._paths(context)
        write_json_atomic(
            client_path,
            {
                "server_ip": context.server_ip,
                "port": self.plan.port,
                "timeout_seconds": 5,
                "requests": [
                    {
                        "path": segment.path,
                        "expected_bytes": segment.expected_bytes,
                        "think_seconds": segment.pace_after_seconds,
                    }
                    for segment in self.plan.segments
                ],
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
            timeout=max(30.0, self.plan.target_duration_seconds * 2.0),
            log=context.log,
        )
        payload = json.loads(results_path.read_text(encoding="utf-8"))
        self.client_records = list(payload["records"])
        self.realized_duration_seconds = float(payload["duration_seconds"])
        self.server_receipts = [
            json.loads(line)
            for line in receipts.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self._result = TrafficRunResult(
            {
                "client_records": self.client_records,
                "server_receipts": self.server_receipts,
                "realized_duration_seconds": self.realized_duration_seconds,
                "process_duration_seconds": command.duration_seconds,
            }
        )
        return self._result

    def validate(
        self, context: TrafficContext, result: TrafficRunResult
    ) -> TrafficValidation:
        del context, result
        return validate_video_result(
            self.plan,
            self.client_records,
            self.server_receipts,
            realized_duration_seconds=self.realized_duration_seconds,
        )

    def cleanup(self, context: TrafficContext) -> None:
        del context
        if self.service is not None:
            self.service.stop()
            self.service = None

    def metadata(self) -> dict[str, object]:
        return {
            "class": self.name,
            "known_training_class": True,
            "generator": "local-segmented-video",
            "generator_version": self.version,
            "seed": self.seed,
            "parameters": {
                "port": self.plan.port,
                "profile": asdict(self.plan.profile),
                "target_duration_seconds": self.plan.target_duration_seconds,
                "segments": [asdict(segment) for segment in self.plan.segments],
            },
            "result": {} if self._result is None else dict(self._result.metrics),
        }
