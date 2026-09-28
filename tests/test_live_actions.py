from __future__ import annotations

from pathlib import Path
from shutil import copyfile
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import Callable
import json
import unittest

from ipsec_sentinel.live.models import (
    CaptureStatus,
    CleanupStatus,
    LiveAction,
    LiveProblem,
    SessionState,
    TunnelStatus,
)
from ipsec_sentinel.live.orchestrator import LiveLabOrchestrator
from ipsec_sentinel.live.provider import LocalLabProvider
from ipsec_sentinel.models import CaptureEvidence, PfsObservation
from ipsec_sentinel.pcap import PcapFormatError, inspect_ml_pcap
from ipsec_sentinel.scenario import Scenario, scenario_path
from tests.test_live_orchestrator import InlineExecutor
from tests.test_live_traffic import FakeGenerator, TrafficSession, esp_summary


FIXTURES = Path("tests/fixtures")


class ActionSession(TrafficSession):
    def __init__(
        self,
        run_dir: Path,
        log: object,
        *,
        pfs_status: str = "VERIFIED",
        cleanup_error: bool = False,
    ) -> None:
        super().__init__(run_dir, log)
        self.pfs_status = pfs_status
        self.cleanup_error = cleanup_error
        self.scenario: Scenario | None = None
        self.pfs = PfsObservation.not_tested()
        self.sas = {
            "gateway-a": (FIXTURES / "swanctl-gateway-a.txt").read_text(encoding="utf-8"),
            "gateway-b": (FIXTURES / "swanctl-gateway-b.txt").read_text(encoding="utf-8"),
        }
        self.xfrm = {
            "gateway-a": (FIXTURES / "xfrm-gateway-a.txt").read_text(encoding="utf-8"),
            "gateway-b": (FIXTURES / "xfrm-gateway-b.txt").read_text(encoding="utf-8"),
        }
        self.stop_count = 0

    def load_scenario(self, scenario_id: str) -> Scenario:
        self.calls.append(("load_scenario", scenario_id))
        path = scenario_path(scenario_id)
        self.scenario_yaml = path.read_text(encoding="utf-8")
        self.scenario = Scenario.load(path)
        return self.scenario

    def wait_for_sa(self) -> dict[str, str]:
        self._call("wait_for_sa")
        return self.sas

    def refresh_sas(self) -> dict[str, str]:
        self._call("refresh_sas")
        return self.sas

    def collect_xfrm(self) -> dict[str, str]:
        self._call("collect_xfrm")
        return self.xfrm

    def rekey(self) -> PfsObservation:
        self._call("rekey")
        before = dict(self.sas)
        replacements = {
            "c2ad5304": "11111111",
            "cbecd5e6": "22222222",
        }
        for old, new in replacements.items():
            self.sas = {name: text.replace(old, new) for name, text in self.sas.items()}
            self.xfrm = {name: text.replace(old, new) for name, text in self.xfrm.items()}
        self.rekey_evidence = SimpleNamespace(
            before_sas=before,
            after_sas=dict(self.sas),
            log_segment="selected proposal from controlled test",
            attempted=True,
            completed=True,
        )
        self.pfs = PfsObservation(
            self.pfs_status,
            True,
            ("fresh CHILD-SA evidence",),
        )
        return self.pfs

    def stop_captures(self) -> None:
        self._call("stop_captures")
        self.stop_count += 1
        copyfile(FIXTURES / "ike-esp.pcap", self.run_dir / "full-evidence.pcap")

    def validate_captures(self) -> CaptureEvidence:
        self._call("validate_captures")
        return CaptureEvidence("full-evidence.pcap", 14, 4, 10, 0, 0)

    def cleanup(self) -> None:
        self._call("cleanup")
        if self.cleanup_error:
            self.cleanup_error = False
            raise RuntimeError("injected cleanup failure")


def fake_analysis(*_args: object, **_kwargs: object) -> dict[str, object]:
    return {
        "analysis": {
            "schema_id": "ipsec-sentinel.analysis/v1",
            "summary": {"status": "COMPLETE", "ipsec": "DETECTED"},
            "controlled_evidence": {
                "available": True,
                "scenario_id": "no-pfs",
                "configured": {"pfs": False},
            },
            "ike": {"encryption": {"normalized": "AES-256-GCM", "provenance": "OBSERVED"}},
            "pfs": {"state": "disabled", "provenance": "DERIVED"},
            "traffic_intelligence": {
                "state": "PREDICTED",
                "predicted_class": "video",
                "provenance": "AI_INFERRED",
            },
            "security_score": {"total": 88},
        },
        "xray": {"total_packet_count": 12, "packets": []},
    }


class LiveActionTest(unittest.TestCase):
    def make_connected(
        self,
        directory: str,
        *,
        scenario: str = "secure-baseline",
        mystery: bool = False,
        pfs_status: str | None = None,
        cleanup_error: bool = False,
        capture_deriver: Callable[..., object] | None = None,
        capture_inspector: Callable[..., object] | None = None,
    ) -> tuple[LiveLabOrchestrator, str, ActionSession, list[object]]:
        sessions: list[ActionSession] = []
        generator_calls: list[object] = []

        def factory(run_dir: Path, log: object, **_kwargs: object) -> ActionSession:
            effective_status = pfs_status
            if effective_status is None:
                effective_status = "VERIFIED_DISABLED" if scenario == "no-pfs" else "VERIFIED"
            session = ActionSession(
                run_dir,
                log,
                pfs_status=effective_status,
                cleanup_error=cleanup_error,
            )
            sessions.append(session)
            return session

        captured_windows: list[object] = []

        def derive(_source: Path, destination: Path, window: object, _peers: object):
            captured_windows.append(window)
            destination.write_bytes(b"ESP-only test capture")
            return SimpleNamespace(packet_count=12, capture_bytes=128, duration_seconds=2.0)

        def inspect(_path: Path, _window: object, _peers: object):
            return SimpleNamespace(packet_count=12, capture_bytes=128, duration_seconds=2.0)

        orchestrator = LiveLabOrchestrator(
            Path(directory),
            session_factory=factory,
            provider_factory=LocalLabProvider,
            executor=InlineExecutor(),
            id_factory=lambda: "SNT-ACTION01",
            mystery_selector=lambda _choices: scenario,
            generator_factory=lambda name, seed: FakeGenerator(name, seed, generator_calls),
            seed_factory=iter((101, 202, 303)).__next__,
            time_ns=iter((100, 200, 300, 400, 500, 600)).__next__,
            esp_summarizer=lambda _path, _prior: esp_summary(10),
            capture_deriver=capture_deriver or derive,
            capture_inspector=capture_inspector or inspect,
            analysis_runner=fake_analysis,
            model_dir=Path("missing-model"),
        )
        self.addCleanup(orchestrator.close)
        created = orchestrator.create_session("mystery" if mystery else scenario)
        orchestrator.submit(created.session_id, LiveAction.CONNECT, {}).result()
        orchestrator._test_captured_windows = captured_windows  # type: ignore[attr-defined]
        return orchestrator, created.session_id, sessions[0], generator_calls

    def test_rekey_emits_spi_transition_and_preserves_pfs_semantics(self) -> None:
        cases = (
            ("secure-baseline", "VERIFIED", True, "enabled"),
            ("no-pfs", "VERIFIED_DISABLED", False, "disabled"),
            ("secure-baseline", "NOT_VERIFIED", True, "unknown"),
        )
        for scenario, status, configured, observed in cases:
            with self.subTest(scenario=scenario, status=status), TemporaryDirectory() as directory:
                orchestrator, session_id, _, _ = self.make_connected(
                    directory,
                    scenario=scenario,
                    pfs_status=status,
                )

                orchestrator.trigger_rekey(session_id).result()

                snapshot = orchestrator.get_session(session_id)
                self.assertEqual(snapshot.state, SessionState.TUNNEL_ACTIVE)
                event = next(
                    item
                    for item in reversed(orchestrator.events(session_id, 0))
                    if item.type == "child_sa.rekeyed"
                )
                self.assertNotEqual(event.data["before_spis"], event.data["after_spis"])
                self.assertEqual(event.data["configured"]["pfs"], configured)
                self.assertEqual(event.data["observed"]["status"], status)
                self.assertEqual(event.data["verification_state"], observed)

    def test_rekey_requires_an_established_child_sa(self) -> None:
        with TemporaryDirectory() as directory:
            orchestrator = LiveLabOrchestrator(
                Path(directory),
                session_factory=lambda run_dir, log, **_kwargs: ActionSession(run_dir, log),
                executor=InlineExecutor(),
                id_factory=lambda: "SNT-IDLE0002",
            )
            self.addCleanup(orchestrator.close)
            session = orchestrator.create_session("secure-baseline")
            with self.assertRaises(LiveProblem) as caught:
                orchestrator.trigger_rekey(session.session_id)
            self.assertEqual(caught.exception.code, "TUNNEL_NOT_ACTIVE")

    def test_analysis_seals_once_and_uses_only_latest_workload_window(self) -> None:
        with TemporaryDirectory() as directory:
            orchestrator, session_id, session, _ = self.make_connected(directory)
            orchestrator.run_traffic(session_id, "icmp").result()
            orchestrator.run_traffic(session_id, "video").result()

            orchestrator.analyze(session_id).result()

            snapshot = orchestrator.get_session(session_id)
            self.assertEqual(snapshot.state, SessionState.READY)
            self.assertEqual(snapshot.capture_status, CaptureStatus.SEALED)
            self.assertTrue(snapshot.analysis_available)
            self.assertEqual(session.stop_count, 1)
            windows = orchestrator._test_captured_windows  # type: ignore[attr-defined]
            self.assertEqual(len(windows), 1)
            self.assertEqual((windows[0].started_unix_ns, windows[0].finished_unix_ns), (300, 400))
            self.assertTrue((Path(directory) / session_id / "analysis.json").is_file())
            with self.assertRaises(LiveProblem) as caught:
                orchestrator.run_traffic(session_id, "email")
            self.assertEqual(caught.exception.code, "CAPTURE_SEALED")
            with self.assertRaises(LiveProblem) as caught:
                orchestrator.analyze(session_id)
            self.assertEqual(caught.exception.code, "CAPTURE_SEALED")

    def test_strict_ml_validation_rejects_a_mixed_capture(self) -> None:
        def contaminate(source: Path, destination: Path, *_args: object) -> object:
            copyfile(source, destination)
            return object()

        with TemporaryDirectory() as directory:
            orchestrator, session_id, _, _ = self.make_connected(
                directory,
                capture_deriver=contaminate,
                capture_inspector=inspect_ml_pcap,
            )
            orchestrator.run_traffic(session_id, "icmp").result()

            with self.assertRaises(PcapFormatError):
                orchestrator.analyze(session_id).result()

            failed = orchestrator.get_session(session_id)
            self.assertEqual(failed.state, SessionState.FAILED)
            self.assertFalse(failed.analysis_available)

    def test_mystery_reveal_then_disconnect_is_persisted_and_idempotent(self) -> None:
        with TemporaryDirectory() as directory:
            orchestrator, session_id, session, _ = self.make_connected(
                directory,
                scenario="no-pfs",
                mystery=True,
            )
            orchestrator.run_traffic(session_id, "video").result()
            orchestrator.trigger_rekey(session_id).result()
            orchestrator.analyze(session_id).result()

            unrevealed_events = json.dumps([
                item.to_dict() for item in orchestrator.events(session_id, 0)
            ])
            self.assertNotIn("no-pfs", unrevealed_events)
            self.assertNotIn('"scenario_id"', unrevealed_events)
            self.assertNotIn('"configured":', unrevealed_events)

            orchestrator.reveal(session_id).result()
            revealed = orchestrator.get_session(session_id)
            self.assertTrue(revealed.revealed)
            reveal_event = next(
                item
                for item in reversed(orchestrator.events(session_id, 0))
                if item.type == "mystery.revealed"
            )
            self.assertEqual(reveal_event.data["ground_truth"]["scenario_id"], "no-pfs")
            self.assertEqual(reveal_event.data["comparison"]["pfs_match"], True)
            self.assertEqual(reveal_event.data["sentinel"]["pfs"]["provenance"], "DERIVED")

            orchestrator.disconnect(session_id).result()
            orchestrator.disconnect(session_id).result()
            completed = orchestrator.get_session(session_id)
            self.assertEqual(completed.state, SessionState.COMPLETE)
            self.assertEqual(completed.tunnel_status, TunnelStatus.DISCONNECTED)
            self.assertEqual(completed.cleanup_status, CleanupStatus.SUCCEEDED)
            self.assertEqual(session.calls.count("cleanup"), 1)

    def test_disconnect_records_cleanup_failure_separately(self) -> None:
        with TemporaryDirectory() as directory:
            orchestrator, session_id, _, _ = self.make_connected(
                directory,
                cleanup_error=True,
            )

            orchestrator.disconnect(session_id).result()

            failed = orchestrator.get_session(session_id)
            self.assertEqual(failed.state, SessionState.FAILED)
            self.assertEqual(failed.cleanup_status, CleanupStatus.FAILED)
            self.assertEqual(failed.failure["operation"], "DISCONNECT")  # type: ignore[index]
            cleanup_event = next(
                item
                for item in reversed(orchestrator.events(session_id, 0))
                if item.type == "cleanup.failed"
            )
            self.assertEqual(cleanup_event.data["exception_type"], "RuntimeError")
            action_event = orchestrator.events(session_id, 0)[-1]
            self.assertEqual(action_event.type, "action.failed")
            self.assertEqual(action_event.data["action"], "DISCONNECT")


if __name__ == "__main__":
    unittest.main()
