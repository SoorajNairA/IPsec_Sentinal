from __future__ import annotations

from dataclasses import asdict, dataclass
from random import Random

from ipsec_sentinel.command import run_checked
from ipsec_sentinel.evidence import parse_ping
from ipsec_sentinel.traffic.base import (
    TrafficContext,
    TrafficRunResult,
    TrafficValidation,
)


@dataclass(frozen=True)
class IcmpPlan:
    count: int
    interval_seconds: float
    payload_bytes: int


def resolve_icmp_plan(seed: int) -> IcmpPlan:
    random = Random(seed)
    return IcmpPlan(
        count=random.choice((5, 7, 9)),
        interval_seconds=random.choice((0.1, 0.2, 0.3)),
        payload_bytes=random.choice((56, 128, 512)),
    )


class IcmpGenerator:
    name = "icmp"
    version = "1"

    def __init__(self, seed: int) -> None:
        self.seed = seed
        self.plan = resolve_icmp_plan(seed)
        self._result: TrafficRunResult | None = None

    def prepare(self, context: TrafficContext) -> None:
        return None

    def run(self, context: TrafficContext) -> TrafficRunResult:
        result = run_checked(
            [
                "ip",
                "netns",
                "exec",
                context.client_namespace,
                "ping",
                "-I",
                context.client_ip,
                "-c",
                str(self.plan.count),
                "-i",
                str(self.plan.interval_seconds),
                "-s",
                str(self.plan.payload_bytes),
                "-W",
                "2",
                context.server_ip,
            ],
            timeout=max(15.0, self.plan.count * (self.plan.interval_seconds + 2.0)),
            log=context.log,
        )
        self._result = TrafficRunResult(
            {"stdout": result.stdout, "duration_seconds": result.duration_seconds}
        )
        return self._result

    def validate_output(self, stdout: str) -> TrafficValidation:
        evidence = parse_ping(stdout)
        passed = (
            evidence.sent == self.plan.count
            and evidence.received == self.plan.count
            and evidence.success
        )
        errors = (
            ()
            if passed
            else (
                f"expected {self.plan.count} replies, received {evidence.received}",
            )
        )
        return TrafficValidation(
            passed,
            {
                "sent": evidence.sent,
                "received": evidence.received,
                "success": evidence.success,
            },
            errors,
        )

    def validate(
        self, context: TrafficContext, result: TrafficRunResult
    ) -> TrafficValidation:
        return self.validate_output(str(result.metrics["stdout"]))

    def cleanup(self, context: TrafficContext) -> None:
        return None

    def metadata(self) -> dict[str, object]:
        return {
            "class": self.name,
            "known_training_class": True,
            "generator": "ping",
            "generator_version": self.version,
            "seed": self.seed,
            "parameters": asdict(self.plan),
            "result": {} if self._result is None else dict(self._result.metrics),
        }
