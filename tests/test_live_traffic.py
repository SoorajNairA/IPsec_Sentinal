from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Callable
import json
import unittest

from ipsec_sentinel.live.models import LiveProblem, SessionState
from ipsec_sentinel.live.observations import EspSummary
from ipsec_sentinel.live.orchestrator import LiveLabOrchestrator
from ipsec_sentinel.live.provider import LocalLabProvider
from ipsec_sentinel.traffic.base import TrafficRunResult, TrafficValidation
from tests.test_live_orchestrator import FakeSession, InlineExecutor


class TrafficSession(FakeSession):
    def capture_snapshot(self, destination: Path) -> Path:
        self._call("capture_snapshot")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(b"pcap snapshot")
        return destination

    def refresh_sas(self) -> dict[str, str]:
        self._call("refresh_sas")
        return self.sas


class FakeGenerator:
    name = "controlled"
    version = "test/v1"

    def __init__(
        self,
        workload_id: str,
        seed: int,
        calls: list[object],
        *,
        fail_run: bool = False,
        validation_passed: bool = True,
    ) -> None:
        self.workload_id = workload_id
        self.seed = seed
        self.calls = calls
        self.fail_run = fail_run
        self.validation_passed = validation_passed

    def prepare(self, _context: object) -> None:
        self.calls.append((self.workload_id, "prepare", self.seed))

    def run(self, _context: object) -> TrafficRunResult:
        self.calls.append((self.workload_id, "run", self.seed))
        if self.fail_run:
            raise RuntimeError(f"{self.workload_id} injected run failure")
        return TrafficRunResult({"delivered": 7})

    def validate(
        self, _context: object, _result: TrafficRunResult
    ) -> TrafficValidation:
        self.calls.append((self.workload_id, "validate", self.seed))
        return TrafficValidation(
            self.validation_passed,
            {"receipts": 7},
            () if self.validation_passed else ("receipt mismatch",),
        )

    def cleanup(self, _context: object) -> None:
        self.calls.append((self.workload_id, "cleanup", self.seed))

    def metadata(self) -> dict[str, object]:
        return {
            "generator": self.workload_id,
            "version": self.version,
            "parameters": {
                "selected_size": 1000 + self.seed,
                "selected_pattern": f"pattern-{self.seed % 3}",
            },
        }


def esp_summary(total: int) -> EspSummary:
    return EspSummary(
        peer_pair=("192.0.2.1", "192.0.2.2"),
        packet_count=total,
        bytes=total * 154,
        packet_delta=10,
        byte_delta=1540,
        direction_counts={"forward": total // 2, "reverse": total // 2},
        direction_bytes={"forward": total * 77, "reverse": total * 77},
        first_timestamp_ns=1_000_000_000,
        last_timestamp_ns=2_000_000_000,
    )


class LiveTrafficTest(unittest.TestCase):
    def make_connected(
        self,
        directory: str,
        *,
        generator_builder: Callable[[str, int], FakeGenerator],
        summaries: list[EspSummary | None] | None = None,
        seeds: list[int] | None = None,
    ) -> tuple[LiveLabOrchestrator, str, list[TrafficSession]]:
        sessions: list[TrafficSession] = []

        def session_factory(run_dir: Path, log: object, **_kwargs: object) -> TrafficSession:
            session = TrafficSession(run_dir, log)
            sessions.append(session)
            return session

        seed_values = iter(seeds or [101, 202, 303, 404])
        time_values = iter(
            [
                1_799_501_534_000_000_000,
                1_799_501_538_000_000_000,
                1_799_501_540_000_000_000,
                1_799_501_544_000_000_000,
                1_799_501_546_000_000_000,
                1_799_501_550_000_000_000,
            ]
        )
        summary_values = iter(summaries or [esp_summary(10), esp_summary(20), esp_summary(30)])

        def summarize(_path: Path, _prior: object) -> EspSummary | None:
            return next(summary_values)

        orchestrator = LiveLabOrchestrator(
            Path(directory),
            session_factory=session_factory,
            provider_factory=LocalLabProvider,
            executor=InlineExecutor(),
            id_factory=lambda: "SNT-8A31D2F0",
            generator_factory=generator_builder,
            seed_factory=lambda: next(seed_values),
            time_ns=lambda: next(time_values),
            esp_summarizer=summarize,
        )
        self.addCleanup(orchestrator.close)
        created = orchestrator.create_session("secure-baseline")
        orchestrator.submit(created.session_id, "CONNECT", {}).result()
        return orchestrator, created.session_id, sessions

    def test_successful_workload_runs_full_generator_lifecycle_and_persists_seed(self) -> None:
        with TemporaryDirectory() as directory:
            calls: list[object] = []
            orchestrator, session_id, _ = self.make_connected(
                directory,
                generator_builder=lambda name, seed: FakeGenerator(name, seed, calls),
                seeds=[8391],
            )

            orchestrator.run_traffic(session_id, "icmp").result()

            self.assertEqual(
                calls,
                [
                    ("icmp", "prepare", 8391),
                    ("icmp", "run", 8391),
                    ("icmp", "validate", 8391),
                    ("icmp", "cleanup", 8391),
                ],
            )
            snapshot = orchestrator.get_session(session_id)
            self.assertEqual(snapshot.state, SessionState.TUNNEL_ACTIVE)
            self.assertEqual(snapshot.latest_completed_workload_sequence, 1)
            window = snapshot.completed_workloads[0]
            self.assertEqual((window.workload_id, window.seed), ("icmp", 8391))
            payload = json.loads(
                (
                    Path(directory)
                    / session_id
                    / "traffic"
                    / "0001"
                    / "traffic.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(payload["seed"], 8391)
            self.assertEqual(payload["parameters"]["selected_size"], 9391)
            self.assertEqual(payload["validation"]["passed"], True)
            self.assertEqual(payload["status"], "PASS")

    def test_icmp_then_video_selects_video_and_later_failure_does_not_replace_it(self) -> None:
        with TemporaryDirectory() as directory:
            calls: list[object] = []

            def build(name: str, seed: int) -> FakeGenerator:
                return FakeGenerator(
                    name,
                    seed,
                    calls,
                    validation_passed=name != "email",
                )

            orchestrator, session_id, _ = self.make_connected(
                directory,
                generator_builder=build,
                seeds=[11, 22, 33],
            )
            orchestrator.run_traffic(session_id, "icmp").result()
            orchestrator.run_traffic(session_id, "video").result()
            with self.assertRaisesRegex(RuntimeError, "receipt mismatch"):
                orchestrator.run_traffic(session_id, "email").result()

            snapshot = orchestrator.get_session(session_id)
            self.assertEqual(snapshot.state, SessionState.TUNNEL_ACTIVE)
            self.assertEqual(
                [window.workload_id for window in snapshot.completed_workloads],
                ["icmp", "video"],
            )
            self.assertEqual(snapshot.latest_completed_workload_sequence, 2)
            self.assertEqual(snapshot.completed_workloads[-1].seed, 22)
            self.assertIn(("email", "cleanup", 33), calls)
            failed = json.loads(
                (
                    Path(directory)
                    / session_id
                    / "traffic"
                    / "0003"
                    / "traffic.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(failed["status"], "FAILED")

    def test_run_failure_still_cleans_generator_and_preserves_tunnel(self) -> None:
        with TemporaryDirectory() as directory:
            calls: list[object] = []
            orchestrator, session_id, _ = self.make_connected(
                directory,
                generator_builder=lambda name, seed: FakeGenerator(
                    name, seed, calls, fail_run=True
                ),
            )
            with self.assertRaisesRegex(RuntimeError, "injected run failure"):
                orchestrator.run_traffic(session_id, "video").result()
            self.assertIn(("video", "cleanup", 101), calls)
            snapshot = orchestrator.get_session(session_id)
            self.assertEqual(snapshot.state, SessionState.TUNNEL_ACTIVE)
            self.assertEqual(snapshot.completed_workloads, ())

    def test_workload_allowlist_and_active_tunnel_are_enforced(self) -> None:
        with TemporaryDirectory() as directory:
            calls: list[object] = []
            orchestrator, session_id, _ = self.make_connected(
                directory,
                generator_builder=lambda name, seed: FakeGenerator(name, seed, calls),
            )
            with self.assertRaises(LiveProblem) as caught:
                orchestrator.run_traffic(session_id, "database_query_like")
            self.assertEqual(caught.exception.code, "WORKLOAD_NOT_ALLOWED")
            self.assertEqual(calls, [])

        with TemporaryDirectory() as directory:
            sessions: list[TrafficSession] = []

            def factory(run_dir: Path, log: object, **_kwargs: object) -> TrafficSession:
                session = TrafficSession(run_dir, log)
                sessions.append(session)
                return session

            orchestrator = LiveLabOrchestrator(
                Path(directory),
                session_factory=factory,
                executor=InlineExecutor(),
                id_factory=lambda: "SNT-IDLE0001",
                generator_factory=lambda name, seed: FakeGenerator(name, seed, calls),
            )
            self.addCleanup(orchestrator.close)
            idle = orchestrator.create_session("secure-baseline")
            with self.assertRaises(LiveProblem) as caught:
                orchestrator.run_traffic(idle.session_id, "icmp")
            self.assertEqual(caught.exception.code, "TUNNEL_NOT_ACTIVE")

    def test_esp_events_emit_only_for_positive_capture_deltas(self) -> None:
        with TemporaryDirectory() as directory:
            calls: list[object] = []
            orchestrator, session_id, _ = self.make_connected(
                directory,
                generator_builder=lambda name, seed: FakeGenerator(name, seed, calls),
                summaries=[esp_summary(10), None],
                seeds=[1, 2],
            )
            orchestrator.run_traffic(session_id, "icmp").result()
            orchestrator.run_traffic(session_id, "video").result()
            events = orchestrator.events(session_id, 0)
            esp_events = [event for event in events if event.type == "esp.observed"]
            self.assertEqual(len(esp_events), 1)
            self.assertEqual(esp_events[0].data["packet_delta"], 10)
            self.assertEqual(esp_events[0].data["byte_delta"], 1540)


if __name__ == "__main__":
    unittest.main()
