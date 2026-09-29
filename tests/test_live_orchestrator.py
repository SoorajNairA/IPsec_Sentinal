from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier, BrokenBarrierError
from types import SimpleNamespace
from typing import Callable
import json
import itertools
import unittest
from unittest.mock import patch

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
from ipsec_sentinel.scenario import Scenario, scenario_path


FIXTURES = Path("tests/fixtures")


IKE_LINES = (
    "08[ENC] <secure-baseline|1> generating IKE_SA_INIT request 0 [ SA KE No ]",
    "14[ENC] <secure-baseline|1> parsed IKE_SA_INIT response 0 [ SA KE No ]",
    "14[CFG] <secure-baseline|1> selected proposal: IKE:AES_GCM_16_256/PRF_HMAC_SHA2_384/ECP_384",
    "14[ENC] <secure-baseline|1> generating IKE_AUTH request 1 [ IDi AUTH SA ]",
    "11[ENC] <secure-baseline|1> parsed IKE_AUTH response 1 [ IDr AUTH SA ]",
    "11[IKE] <secure-baseline|1> IKE_SA secure-baseline[1] established between 192.0.2.1[gateway-a]...192.0.2.2[gateway-b]",
    "11[IKE] <secure-baseline|1> CHILD_SA protected-nets{1} established with SPIs c8be46f5_i c8ec6a73_o and TS 10.10.0.0/24 === 10.20.0.0/24",
)


class InlineExecutor:
    def submit(self, function: Callable[[], object]) -> Future[object]:
        future: Future[object] = Future()
        try:
            future.set_result(function())
        except BaseException as error:
            future.set_exception(error)
        return future


class HoldingExecutor:
    def __init__(self) -> None:
        self.function: Callable[[], object] | None = None
        self.future: Future[object] | None = None
        self.submission_count = 0

    def submit(self, function: Callable[[], object]) -> Future[object]:
        self.submission_count += 1
        self.function = function
        self.future = Future()
        return self.future

    def run(self) -> None:
        assert self.function is not None and self.future is not None
        try:
            self.future.set_result(self.function())
        except BaseException as error:
            self.future.set_exception(error)


class FakeSession:
    def __init__(
        self,
        run_dir: Path,
        _log: object,
        *,
        fail_at: str | None = None,
        empty_evidence: bool = False,
    ) -> None:
        self.run_dir = run_dir
        self.log = _log
        self.fail_at = fail_at
        self.empty_evidence = empty_evidence
        self.scenario: Scenario | None = None
        self.sas: dict[str, str] = {}
        self.xfrm: dict[str, str] = {}
        self.calls: list[object] = []
        self.log_path = run_dir / "charon.log"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.write_text("", encoding="utf-8")
        self.pair = SimpleNamespace(
            files={"gateway-a": SimpleNamespace(log=self.log_path)}
        )
        self.captures = {"primary": SimpleNamespace(running=True, pid=None)}

    def _call(self, name: str) -> None:
        self.calls.append(name)
        if self.fail_at == name:
            raise RuntimeError(f"private scenario no-pfs failed at {name}")

    def preflight(self) -> None:
        self._call("preflight")

    def reset(self) -> None:
        self._call("reset")

    def load_scenario(self, scenario_id: str) -> object:
        self.calls.append(("load_scenario", scenario_id))
        if self.fail_at == "load_scenario":
            raise RuntimeError(f"private scenario {scenario_id} failed")
        self.scenario = Scenario.load(scenario_path(scenario_id))
        return self.scenario

    def setup_topology(self) -> None:
        self._call("setup_topology")

    def start_daemons(self) -> None:
        self._call("start_daemons")

    def start_captures(self) -> None:
        self._call("start_captures")

    def load_configuration(self) -> dict[str, str]:
        self._call("load_configuration")
        return {"gateway-a": "loaded", "gateway-b": "loaded"}

    def initiate(self) -> str:
        self._call("initiate")
        with self.log_path.open("a", encoding="utf-8") as stream:
            for line in IKE_LINES:
                stream.write(line + "\n")
            stream.flush()
        return "initiated"

    def wait_for_sa(self) -> dict[str, str]:
        self._call("wait_for_sa")
        if self.empty_evidence:
            self.sas = {"gateway-a": "", "gateway-b": ""}
        else:
            self.sas = {
                gateway: (FIXTURES / f"swanctl-{gateway}.txt").read_text(encoding="utf-8")
                for gateway in ("gateway-a", "gateway-b")
            }
        return self.sas

    def collect_xfrm(self) -> dict[str, str]:
        self._call("collect_xfrm")
        if self.empty_evidence:
            self.xfrm = {"gateway-a": "STATE\nPOLICY\n", "gateway-b": "STATE\nPOLICY\n"}
        else:
            self.xfrm = {
                gateway: (FIXTURES / f"xfrm-{gateway}.txt").read_text(encoding="utf-8")
                for gateway in ("gateway-a", "gateway-b")
            }
        return self.xfrm

    def cleanup(self) -> None:
        self._call("cleanup")


class LiveLabOrchestratorTest(unittest.TestCase):
    def make_orchestrator(
        self,
        directory: str,
        *,
        executor: object | None = None,
        fail_at: str | None = None,
        mystery_scenario: str = "no-pfs",
        empty_evidence: bool = False,
    ) -> tuple[LiveLabOrchestrator, list[FakeSession]]:
        sessions: list[FakeSession] = []

        def factory(run_dir: Path, log: object, **_kwargs: object) -> FakeSession:
            session = FakeSession(
                run_dir,
                log,
                fail_at=fail_at,
                empty_evidence=empty_evidence,
            )
            sessions.append(session)
            return session

        orchestrator = LiveLabOrchestrator(
                Path(directory),
                session_factory=factory,
                provider_factory=LocalLabProvider,
                executor=executor or InlineExecutor(),
                id_factory=lambda: "SNT-8A31D2F0",
                mystery_selector=lambda _choices: mystery_scenario,
            )
        self.addCleanup(orchestrator.close)
        return orchestrator, sessions

    def test_create_persists_idle_session_and_rejects_second_active_session(self) -> None:
        with TemporaryDirectory() as directory:
            orchestrator, _ = self.make_orchestrator(directory)
            created = orchestrator.create_session("secure-baseline")
            self.assertEqual(created.state, SessionState.IDLE)
            self.assertEqual(created.display_name, "Secure Baseline")
            self.assertEqual(created.latest_event_id, 1)
            self.assertEqual(orchestrator.get_session(created.session_id), created)
            with self.assertRaises(LiveProblem) as caught:
                orchestrator.create_session("aes128-gcm")
            self.assertEqual(caught.exception.code, "ACTIVE_SESSION_EXISTS")

    def test_action_lock_rejects_a_second_command_instead_of_queueing(self) -> None:
        with TemporaryDirectory() as directory:
            executor = HoldingExecutor()
            orchestrator, _ = self.make_orchestrator(directory, executor=executor)
            session = orchestrator.create_session("secure-baseline")
            future = orchestrator.submit(session.session_id, LiveAction.CONNECT, {})
            self.assertFalse(future.done())
            with self.assertRaises(LiveProblem) as caught:
                orchestrator.submit(session.session_id, LiveAction.CONNECT, {})
            self.assertEqual(caught.exception.code, "SESSION_BUSY")
            executor.run()
            self.assertIsNone(future.result())

    def test_simultaneous_commands_commit_only_one_acceptance(self) -> None:
        with TemporaryDirectory() as directory:
            executor = HoldingExecutor()
            orchestrator, _ = self.make_orchestrator(directory, executor=executor)
            session = orchestrator.create_session("secure-baseline")
            barrier = Barrier(2)
            from ipsec_sentinel.live import orchestrator as orchestrator_module
            original = orchestrator_module.validate_action

            def synchronized_validation(snapshot, action):
                try:
                    barrier.wait(timeout=0.2)
                except BrokenBarrierError:
                    pass
                return original(snapshot, action)

            def submit() -> object:
                try:
                    return orchestrator.submit(session.session_id, LiveAction.CONNECT, {})
                except LiveProblem as error:
                    return error

            with patch(
                "ipsec_sentinel.live.orchestrator.validate_action",
                side_effect=synchronized_validation,
            ), ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = [future.result() for future in (pool.submit(submit), pool.submit(submit))]

            accepted = [item for item in outcomes if isinstance(item, Future)]
            rejected = [item for item in outcomes if isinstance(item, LiveProblem)]
            self.assertEqual((len(accepted), len(rejected), executor.submission_count), (1, 1, 1))
            self.assertEqual(rejected[0].code, "SESSION_BUSY")

    def test_simultaneous_session_creation_reserves_only_one_testbed(self) -> None:
        with TemporaryDirectory() as directory:
            ids = (f"SNT-RACE{index:04d}" for index in itertools.count(1))
            orchestrator, _ = self.make_orchestrator(directory)
            orchestrator._id_factory = lambda: next(ids)  # type: ignore[attr-defined]
            barrier = Barrier(2)
            original = orchestrator._active_record  # type: ignore[attr-defined]

            def synchronized_active_record():
                current = original()
                try:
                    barrier.wait(timeout=0.2)
                except BrokenBarrierError:
                    pass
                return current

            def create() -> object:
                try:
                    return orchestrator.create_session("secure-baseline")
                except LiveProblem as error:
                    return error

            with patch.object(
                orchestrator,
                "_active_record",
                side_effect=synchronized_active_record,
            ), ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = [future.result() for future in (pool.submit(create), pool.submit(create))]

            created = [item for item in outcomes if not isinstance(item, LiveProblem)]
            rejected = [item for item in outcomes if isinstance(item, LiveProblem)]
            self.assertEqual((len(created), len(rejected)), (1, 1))
            self.assertEqual(rejected[0].code, "ACTIVE_SESSION_EXISTS")

    def test_connect_orders_real_lifecycle_and_evidence_before_tunnel_active(self) -> None:
        with TemporaryDirectory() as directory:
            orchestrator, sessions = self.make_orchestrator(directory)
            created = orchestrator.create_session("secure-baseline")

            orchestrator.submit(created.session_id, LiveAction.CONNECT, {}).result()

            calls = sessions[0].calls
            self.assertLess(calls.index("start_captures"), calls.index("initiate"))
            self.assertLess(calls.index("wait_for_sa"), calls.index("collect_xfrm"))
            final = orchestrator.get_session(created.session_id)
            self.assertEqual(final.state, SessionState.TUNNEL_ACTIVE)
            self.assertEqual(final.tunnel_status, TunnelStatus.ACTIVE)
            self.assertEqual(final.capture_status, CaptureStatus.RUNNING)
            self.assertTrue(final.child_sa_established)
            self.assertIsNone(final.active_action)

            events = orchestrator.events(created.session_id, 0)
            compressed_states: list[str] = []
            for event in events:
                if not compressed_states or compressed_states[-1] != event.state.value:
                    compressed_states.append(event.state.value)
            self.assertEqual(
                compressed_states,
                [
                    "IDLE",
                    "PREPARING_SANDBOX",
                    "STARTING_ENDPOINT",
                    "WAITING_FOR_ENDPOINT",
                    "STARTING_CAPTURE",
                    "IKE_NEGOTIATING",
                    "AUTHENTICATING",
                    "CHILD_SA_ESTABLISHED",
                    "TUNNEL_ACTIVE",
                ],
            )
            types = [event.type for event in events]
            for event_type in (
                "ike.sa_init.request",
                "ike.sa_init.response",
                "ike.proposal.selected",
                "ike.auth.request",
                "ike.auth.response",
                "ike.sa.established",
                "child_sa.observed",
                "child_sa.verified",
                "xfrm.verified",
                "tunnel.active",
            ):
                self.assertIn(event_type, types)
            self.assertLess(types.index("child_sa.verified"), types.index("tunnel.active"))
            self.assertLess(types.index("xfrm.verified"), types.index("tunnel.active"))

    def test_connect_failure_preserves_primary_error_and_cleans_up(self) -> None:
        with TemporaryDirectory() as directory:
            orchestrator, sessions = self.make_orchestrator(
                directory, fail_at="initiate"
            )
            created = orchestrator.create_session("secure-baseline")
            future = orchestrator.submit(created.session_id, LiveAction.CONNECT, {})
            with self.assertRaisesRegex(RuntimeError, "no-pfs"):
                future.result()
            failed = orchestrator.get_session(created.session_id)
            self.assertEqual(failed.state, SessionState.FAILED)
            self.assertEqual(failed.cleanup_status, CleanupStatus.SUCCEEDED)
            self.assertEqual(failed.tunnel_status, TunnelStatus.FAILED)
            self.assertEqual(failed.failure["operation"], "CONNECT")  # type: ignore[index]
            self.assertNotIn("no-pfs", json.dumps(failed.to_dict()))
            self.assertEqual(sessions[0].calls.count("cleanup"), 1)

    def test_connect_rejects_empty_sa_and_xfrm_evidence_before_active(self) -> None:
        with TemporaryDirectory() as directory:
            orchestrator, _ = self.make_orchestrator(directory, empty_evidence=True)
            created = orchestrator.create_session("secure-baseline")

            with self.assertRaisesRegex(RuntimeError, "tunnel evidence"):
                orchestrator.submit(created.session_id, LiveAction.CONNECT, {}).result()

            failed = orchestrator.get_session(created.session_id)
            self.assertEqual(failed.state, SessionState.FAILED)
            self.assertNotEqual(failed.tunnel_status, TunnelStatus.ACTIVE)

    def test_mystery_identity_stays_server_side_before_reveal(self) -> None:
        with TemporaryDirectory() as directory:
            orchestrator, sessions = self.make_orchestrator(
                directory, mystery_scenario="no-pfs"
            )
            created = orchestrator.create_session("mystery")
            self.assertEqual(created.display_name, "Mystery VPN #01")
            orchestrator.submit(created.session_id, LiveAction.CONNECT, {}).result()

            self.assertIn(("load_scenario", "no-pfs"), sessions[0].calls)
            public_text = json.dumps(
                {
                    "snapshot": orchestrator.get_session(created.session_id).to_dict(),
                    "events": [
                        event.to_dict()
                        for event in orchestrator.events(created.session_id, 0)
                    ],
                }
            )
            self.assertNotIn("no-pfs", public_text)
            self.assertNotIn("scenario_id", public_text)

    def test_close_releases_owned_session_logs_and_is_idempotent(self) -> None:
        with TemporaryDirectory() as directory:
            orchestrator, sessions = self.make_orchestrator(directory)
            orchestrator.create_session("secure-baseline")
            self.assertFalse(sessions[0].log.closed)  # type: ignore[union-attr]
            orchestrator.close()
            orchestrator.close()
            self.assertTrue(sessions[0].log.closed)  # type: ignore[union-attr]


if __name__ == "__main__":
    unittest.main()
