from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import Executor, Future, ThreadPoolExecutor
from dataclasses import dataclass, replace
from pathlib import Path
from secrets import choice, token_hex
from threading import Event, Thread
from typing import TextIO

from ipsec_sentinel.live.events import EventStore, LiveEvent
from ipsec_sentinel.live.models import (
    CaptureStatus,
    CleanupStatus,
    LiveAction,
    LiveProblem,
    LiveSessionSnapshot,
    SessionState,
    TunnelStatus,
    transition,
    validate_action,
)
from ipsec_sentinel.live.observations import (
    LiveObservation,
    StrongSwanObservationParser,
)
from ipsec_sentinel.live.provider import (
    LabProvider,
    LocalLabProvider,
    SCENARIO_NAMES,
    VALIDATED_SCENARIOS,
)
from ipsec_sentinel.session import SecureSession


SessionFactory = Callable[..., SecureSession]
ProviderFactory = Callable[[SecureSession], LabProvider]


@dataclass
class _SessionRecord:
    scenario_id: str
    mystery: bool
    session: SecureSession
    provider: LabProvider
    store: EventStore
    log: TextIO


def _default_session_factory(
    run_dir: Path,
    log: TextIO,
    **kwargs: object,
) -> SecureSession:
    return SecureSession(run_dir, log, **kwargs)


def _default_id() -> str:
    return f"SNT-{token_hex(4).upper()}"


class LiveLabOrchestrator:
    def __init__(
        self,
        root_dir: Path,
        *,
        session_factory: SessionFactory = _default_session_factory,
        provider_factory: ProviderFactory = LocalLabProvider,
        executor: Executor | None = None,
        id_factory: Callable[[], str] = _default_id,
        mystery_selector: Callable[[Sequence[str]], str] = choice,
    ) -> None:
        self.root_dir = Path(root_dir)
        self.root_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
        self._session_factory = session_factory
        self._provider_factory = provider_factory
        self._owns_executor = executor is None
        self._executor = executor or ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="ipsec-sentinel-live"
        )
        self._id_factory = id_factory
        self._mystery_selector = mystery_selector
        self._records: dict[str, _SessionRecord] = {}
        self._active_id: str | None = None
        self._mystery_index = 0
        self._closed = False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        errors: list[str] = []
        if self._owns_executor:
            try:
                assert isinstance(self._executor, ThreadPoolExecutor)
                self._executor.shutdown(wait=True, cancel_futures=False)
            except BaseException as error:
                errors.append(f"executor: {error}")
        for record in self._records.values():
            try:
                if bool(record.provider.health().get("ready")):
                    record.provider.stop_scenario()
            except BaseException as error:
                errors.append(f"{record.store.snapshot.session_id} cleanup: {error}")
            finally:
                record.log.close()
        if errors:
            raise RuntimeError("Live Lab shutdown errors: " + "; ".join(errors))

    def create_session(self, scenario_id: str) -> LiveSessionSnapshot:
        active = self._active_record()
        if active is not None:
            snapshot = active.store.snapshot
            if not (
                snapshot.state is SessionState.COMPLETE
                or (
                    snapshot.state is SessionState.FAILED
                    and snapshot.cleanup_status is CleanupStatus.SUCCEEDED
                )
            ):
                raise LiveProblem(
                    "ACTIVE_SESSION_EXISTS",
                    "A Live Lab session already owns the local testbed.",
                    session_id=snapshot.session_id,
                )
        mystery = scenario_id == "mystery"
        if mystery:
            selected = self._mystery_selector(tuple(sorted(VALIDATED_SCENARIOS)))
            if selected not in VALIDATED_SCENARIOS:
                raise ValueError("mystery selector returned a non-allowlisted scenario")
            actual_scenario = selected
            self._mystery_index += 1
            display_name = f"Mystery VPN #{self._mystery_index:02d}"
        else:
            if scenario_id not in VALIDATED_SCENARIOS:
                raise LiveProblem(
                    "SCENARIO_NOT_ALLOWED",
                    "Select one of the validated Live Lab scenarios.",
                    http_status=400,
                )
            actual_scenario = scenario_id
            display_name = SCENARIO_NAMES[scenario_id]
        session_id = self._id_factory()
        if session_id in self._records:
            raise RuntimeError("session ID factory returned a duplicate ID")
        run_dir = self.root_dir / session_id
        run_dir.mkdir(parents=True, exist_ok=False, mode=0o750)
        log = (run_dir / "orchestration.log").open("a", encoding="utf-8")
        secure_session = self._session_factory(
            run_dir,
            log,
            primary_capture_name="full-evidence.pcap",
        )
        initial = LiveSessionSnapshot(
            session_id=session_id,
            display_name=display_name,
            state=SessionState.CREATING_SESSION,
            state_reason="allocating Live Lab session",
            tunnel_status=TunnelStatus.INACTIVE,
            capture_status=CaptureStatus.NOT_STARTED,
            cleanup_status=CleanupStatus.NOT_RUN,
            mystery=mystery,
        )
        store = EventStore(run_dir, initial)
        record = _SessionRecord(
            actual_scenario,
            mystery,
            secure_session,
            self._provider_factory(secure_session),
            store,
            log,
        )
        self._records[session_id] = record
        self._active_id = session_id
        idle = transition(initial, SessionState.IDLE, "session persisted and ready")
        store.append(
            "session.created",
            SessionState.IDLE,
            idle.state_reason,
            {"display_name": display_name, "mystery": mystery},
            (),
            snapshot=idle,
            durable=True,
        )
        return store.snapshot

    def get_session(self, session_id: str) -> LiveSessionSnapshot:
        return self._record(session_id).store.snapshot

    def events(self, session_id: str, after_id: int) -> tuple[LiveEvent, ...]:
        return self._record(session_id).store.replay(after_id)

    def submit(
        self,
        session_id: str,
        action: LiveAction | str,
        payload: Mapping[str, object],
    ) -> Future[object]:
        del payload
        record = self._record(session_id)
        try:
            normalized_action = (
                action if isinstance(action, LiveAction) else LiveAction(action)
            )
        except ValueError as error:
            raise LiveProblem(
                "ACTION_NOT_ALLOWED",
                "Unknown Live Lab action.",
                http_status=400,
                session_id=session_id,
            ) from error
        validate_action(record.store.snapshot, normalized_action)
        if normalized_action is not LiveAction.CONNECT:
            raise LiveProblem(
                "ACTION_NOT_IMPLEMENTED",
                "This Live Lab action is not available yet.",
                session_id=session_id,
            )
        accepted = replace(
            record.store.snapshot,
            active_action=normalized_action,
            state_reason="CONNECT action accepted",
        )
        record.store.append(
            "action.accepted",
            accepted.state,
            accepted.state_reason,
            {"action": normalized_action.value},
            (),
            snapshot=accepted,
            durable=True,
        )
        return self._executor.submit(
            lambda: self._run_action(record, normalized_action)
        )

    def _run_action(self, record: _SessionRecord, action: LiveAction) -> None:
        try:
            self._connect(record)
        except BaseException as error:
            self._fail_and_cleanup(record, action, error)
            raise
        completed = replace(
            record.store.snapshot,
            active_action=None,
            state_reason="CONNECT action completed",
        )
        record.store.append(
            "action.completed",
            completed.state,
            completed.state_reason,
            {"action": action.value},
            (),
            snapshot=completed,
            durable=True,
        )

    def _connect(self, record: _SessionRecord) -> None:
        self._change_state(
            record,
            SessionState.PREPARING_SANDBOX,
            "sandbox.preparing",
            "preflight and scoped reset started",
        )
        record.session.preflight()
        record.session.reset()
        self._append(
            record,
            "sandbox.prepared",
            "preflight and scoped reset completed",
        )

        self._change_state(
            record,
            SessionState.STARTING_ENDPOINT,
            "endpoint.starting",
            "local controlled endpoint startup began",
        )
        endpoint = record.provider.start_scenario(record.scenario_id)
        self._change_state(
            record,
            SessionState.WAITING_FOR_ENDPOINT,
            "endpoint.waiting",
            "waiting for the local controlled endpoint",
        )
        endpoint = record.provider.wait_until_ready()
        endpoint_data = endpoint.to_public_dict()
        if record.mystery:
            endpoint_data["display_name"] = record.store.snapshot.display_name
        self._append(
            record,
            "endpoint.ready",
            "local controlled endpoint reported ready",
            endpoint_data,
        )

        self._change_state(
            record,
            SessionState.STARTING_CAPTURE,
            "capture.starting",
            "full-session evidence capture startup began",
        )
        record.session.start_captures()
        capture_running = replace(
            record.store.snapshot,
            capture_status=CaptureStatus.RUNNING,
            state_reason="full-session evidence capture is running",
        )
        record.store.append(
            "capture.started",
            capture_running.state,
            capture_running.state_reason,
            {"artifact": "full-evidence.pcap"},
            (),
            snapshot=capture_running,
            durable=True,
        )
        record.session.load_configuration()
        self._append(
            record,
            "ipsec.configuration.loaded",
            "allowlisted strongSwan configuration loaded",
        )

        self._change_state(
            record,
            SessionState.IKE_NEGOTIATING,
            "ike.negotiating",
            "strongSwan initiation started",
        )
        self._initiate_with_log_observations(record)
        record.session.wait_for_sa()
        record.session.collect_xfrm()
        if record.store.snapshot.state is SessionState.IKE_NEGOTIATING:
            self._change_state(
                record,
                SessionState.AUTHENTICATING,
                "ike.sa.verified",
                "swanctl independently verified the established IKE_SA",
            )
        else:
            self._append(
                record,
                "ike.sa.verified",
                "swanctl independently verified the established IKE_SA",
            )
        child = transition(
            record.store.snapshot,
            SessionState.CHILD_SA_ESTABLISHED,
            "swanctl verified an installed CHILD_SA",
        )
        child = replace(child, child_sa_established=True)
        record.store.append(
            "child_sa.verified",
            child.state,
            child.state_reason,
            {"gateways": ["gateway-a", "gateway-b"]},
            ({"source": "swanctl", "record": "list-sas"},),
            snapshot=child,
            durable=True,
        )
        self._append(
            record,
            "xfrm.verified",
            "XFRM state and policy were collected from both gateways",
            {"gateways": ["gateway-a", "gateway-b"]},
            ({"source": "xfrm", "record": "state-and-policy"},),
        )
        active = transition(
            record.store.snapshot,
            SessionState.TUNNEL_ACTIVE,
            "IKE_SA, CHILD_SA, XFRM, and capture checks completed",
        )
        active = replace(active, tunnel_status=TunnelStatus.ACTIVE)
        record.store.append(
            "tunnel.active",
            active.state,
            active.state_reason,
            {"endpoint": endpoint_data},
            (
                {"source": "swanctl", "record": "list-sas"},
                {"source": "xfrm", "record": "state-and-policy"},
            ),
            snapshot=active,
            durable=True,
        )

    def _initiate_with_log_observations(self, record: _SessionRecord) -> None:
        path = record.session.pair.files["gateway-a"].log
        offset = [path.stat().st_size if path.exists() else 0]
        parser = StrongSwanObservationParser()
        stop = Event()

        def drain() -> None:
            if not path.is_file():
                return
            with path.open("r", encoding="utf-8", errors="replace") as stream:
                stream.seek(offset[0])
                for line in stream:
                    observation = parser.feed(line)
                    if observation is not None:
                        self._emit_observation(record, observation)
                offset[0] = stream.tell()

        def follow() -> None:
            while not stop.is_set():
                drain()
                stop.wait(0.01)
            drain()

        follower = Thread(
            target=follow,
            name=f"{record.store.snapshot.session_id}-strongswan-events",
            daemon=True,
        )
        follower.start()
        try:
            record.session.initiate()
        finally:
            stop.set()
            follower.join(timeout=2.0)
            drain()

    def _emit_observation(
        self,
        record: _SessionRecord,
        observation: LiveObservation,
    ) -> None:
        event_type = observation.type
        snapshot = record.store.snapshot
        if event_type.startswith("ike.auth") and snapshot.state is SessionState.IKE_NEGOTIATING:
            snapshot = transition(
                snapshot,
                SessionState.AUTHENTICATING,
                observation.reason,
            )
        if event_type == "child_sa.established":
            event_type = "child_sa.observed"
        record.store.append(
            event_type,
            snapshot.state,
            observation.reason,
            observation.data,
            ({"source": "strongswan-log", "record": event_type},),
            snapshot=snapshot,
        )

    def _fail_and_cleanup(
        self,
        record: _SessionRecord,
        action: LiveAction,
        error: BaseException,
    ) -> None:
        public_failure = {
            "code": f"{action.value}_FAILED",
            "message": "Live Lab action failed; inspect retained diagnostics.",
            "operation": action.value,
            "exception_type": type(error).__name__,
        }
        current = record.store.snapshot
        if current.state is not SessionState.FAILED:
            failed = transition(
                current,
                SessionState.FAILED,
                f"{action.value} action failed",
            )
        else:
            failed = current
        failed = replace(
            failed,
            tunnel_status=TunnelStatus.FAILED,
            capture_status=(
                CaptureStatus.FAILED
                if failed.capture_status is CaptureStatus.RUNNING
                else failed.capture_status
            ),
            failure=public_failure,
        )
        record.store.append(
            "action.failed",
            SessionState.FAILED,
            failed.state_reason,
            {"action": action.value, "error": public_failure},
            (),
            snapshot=failed,
            durable=True,
        )
        cleaning = transition(
            record.store.snapshot,
            SessionState.CLEANING_UP,
            "failure cleanup started",
        )
        cleaning = replace(cleaning, cleanup_status=CleanupStatus.RUNNING)
        record.store.append(
            "cleanup.started",
            cleaning.state,
            cleaning.state_reason,
            {},
            (),
            snapshot=cleaning,
            durable=True,
        )
        try:
            record.provider.stop_scenario()
        except BaseException as cleanup_error:
            finished = transition(
                record.store.snapshot,
                SessionState.FAILED,
                "failure cleanup did not complete",
            )
            finished = replace(
                finished,
                cleanup_status=CleanupStatus.FAILED,
                active_action=None,
            )
            record.store.append(
                "cleanup.failed",
                finished.state,
                finished.state_reason,
                {"exception_type": type(cleanup_error).__name__},
                (),
                snapshot=finished,
                durable=True,
            )
        else:
            finished = transition(
                record.store.snapshot,
                SessionState.FAILED,
                "failure cleanup completed",
            )
            finished = replace(
                finished,
                cleanup_status=CleanupStatus.SUCCEEDED,
                active_action=None,
            )
            record.store.append(
                "cleanup.completed",
                finished.state,
                finished.state_reason,
                {},
                (),
                snapshot=finished,
                durable=True,
            )

    def _append(
        self,
        record: _SessionRecord,
        event_type: str,
        reason: str,
        data: Mapping[str, object] | None = None,
        evidence: tuple[Mapping[str, object], ...] = (),
    ) -> LiveEvent:
        return record.store.append(
            event_type,
            record.store.snapshot.state,
            reason,
            {} if data is None else data,
            evidence,
        )

    def _change_state(
        self,
        record: _SessionRecord,
        target: SessionState,
        event_type: str,
        reason: str,
    ) -> LiveEvent:
        snapshot = transition(record.store.snapshot, target, reason)
        return record.store.append(
            event_type,
            target,
            reason,
            {},
            (),
            snapshot=snapshot,
            durable=True,
        )

    def _record(self, session_id: str) -> _SessionRecord:
        try:
            return self._records[session_id]
        except KeyError as error:
            raise LiveProblem(
                "SESSION_NOT_FOUND",
                "Live Lab session was not found.",
                http_status=404,
                session_id=session_id,
            ) from error

    def _active_record(self) -> _SessionRecord | None:
        if self._active_id is None:
            return None
        return self._records[self._active_id]
