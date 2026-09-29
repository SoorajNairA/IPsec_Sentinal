from dataclasses import dataclass
from typing import TextIO

from ipsec_sentinel.command import run_checked


@dataclass(frozen=True)
class CleanNetworkProfile:
    name: str = "clean"

    def apply(self, log: TextIO) -> None:
        return None

    def verify(self, log: TextIO) -> dict[str, object]:
        for namespace in ("ips-gwa", "ips-gwb"):
            result = run_checked(
                ["ip", "netns", "exec", namespace, "tc", "qdisc", "show"], 5, log
            )
            if "netem" in result.stdout:
                raise RuntimeError(f"unexpected netem state in {namespace}")
        return {
            "profile": "clean",
            "latency_ms": 0,
            "jitter_ms": 0,
            "packet_loss_percent": 0,
            "bandwidth_limit_bps": None,
        }

    def cleanup(self, log: TextIO) -> None:
        return None
