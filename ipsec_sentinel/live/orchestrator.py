from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import Executor, Future, ThreadPoolExecutor
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from secrets import choice, randbits, token_hex
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
    WorkloadWindow,
    transition,
    validate_action,
)
from ipsec_sentinel.live.observations import (
    EspSummary,
    EspTotals,
    LiveObservation,
    StrongSwanObservationParser,
    summarize_esp,
)
from ipsec_sentinel.live.provider import (
    LabProvider,
    LocalLabProvider,
    SCENARIO_NAMES,
    VALIDATED_SCENARIOS,
)
from ipsec_sentinel.session import SecureSession
from ipsec_sentinel.artifacts import write_json_atomic
from ipsec_sentinel.traffic import register_builtin_generators
from ipsec_sentinel.traffic.base import (
    SUPERVISED_CLASS_ALLOWLIST,
    TrafficContext,
    TrafficGenerator,
    TrafficRunResult,
    TrafficValidation,
    create_generator,
)


SessionFactory = Callable[..., SecureSession]
ProviderFactory = Callable[[SecureSession], LabProvider]
GeneratorFactory = Callable[[str, int], TrafficGenerator]
EspSummarizer = Callable[[Path, EspTotals], EspSummary | None]


@dataclass
class _SessionRecord:
    scenario_id: str
    mystery: bool
    session: SecureSession
    provider: LabProvider
    store: EventStore
    log: TextIO
    next_workload_sequence: int = 1
    esp_totals: EspTotals = field(default_factory=EspTotals.empty)


class _RecoveredTrafficFailure(Exception):
    def __init__(self, cause: BaseException, workload_id: str) -> None:
        super().__init__(str(cause))
        self.cause = cause
        self.workload_id = workload_id


def _default_session_factory(
    run_dir: Path,
    log: TextIO,
    **kwargs: object,
) -> SecureSession:
    return SecureSession(run_dir, log, **kwargs)


def _default_id() -> str:
    return f"SNT-{token_hex(4).upper()}"


def _default_generator_factory(name: str, seed: int) -> TrafficGenerator:
    register_builtin_generators()
    return create_generator(name, seed)


def _iso_from_ns(value: int) -> str:
    return (
        datetime.fromtimestamp(value / 1_000_000_000, timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


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
        generator_factory: GeneratorFactory = _default_generator_factory,
        seed_factory: Callable[[], int] = lambda: randbits(63),
        time_ns: Callable[[], int] = __import__("time").time_ns,
        esp_summarizer: EspSummarizer = summarize_esp,
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
        self._generator_factory = generator_factory
        self._seed_factory = seed_factory
        self._time_ns = time_ns
        self._esp_summarizer = esp_summarizer
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

    def run_traffic(self, session_id: str, workload_id: str) -> Future[object]:
        if workload_id not in SUPERVISED_CLASS_ALLOWLIST:
            raise LiveProblem(
                "WORKLOAD_NOT_ALLOWED",
                "Select one of the controlled supervised workloads.",
                http_status=400,
                session_id=session_id,
            )
        return self.submit(
            session_id,
            LiveAction.TRAFFIC,
            {"workload_id": workload_id},
        )

    def submit(
        self,
        session_id: str,
        action: LiveAction | str,
        payload: Mapping[str, object],
    ) -> Future[object]:
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
        if normalized_action not in (LiveAction.CONNECT, LiveAction.TRAFFIC):
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
            lambda: self._run_action(record, normalized_action, dict(payload))
        )

    def _run_action(
        self,
        record: _SessionRecord,
        action: LiveAction,
        payload: Mapping[str, object],
    ) -> None:
        try:
            if action is LiveAction.CONNECT:
                self._connect(record)
            elif action is LiveAction.TRAFFIC:
                workload_id = str(payload.get("workload_id", ""))
                self._run_traffic(record, workload_id)
            else:
                raise AssertionError(f"unhandled action: {action.value}")
        except _RecoveredTrafficFailure as recovered:
            cleared = replace(
                record.store.snapshot,
                active_action=None,
                state_reason=f"{recovered.workload_id} workload failed; tunnel reverified",
            )
            record.store.append(
                "action.failed",
                cleared.state,
                cleared.state_reason,
                {"action": action.value, "workload": recovered.workload_id},
                (),
                snapshot=cleared,
                durable=True,
            )
            raise recovered.cause
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

    def _run_traffic(self, record: _SessionRecord, workload_id: str) -> None:
        if workload_id not in SUPERVISED_CLASS_ALLOWLIST:
            raise LiveProblem(
                "WORKLOAD_NOT_ALLOWED",
                "Select one of the controlled supervised workloads.",
                http_status=400,
                session_id=record.store.snapshot.session_id,
            )
        sequence = record.next_workload_sequence
        record.next_workload_sequence += 1
        seed = self._seed_factory()
        generator = self._generator_factory(workload_id, seed)
        traffic_dir = record.session.run_dir / "traffic" / f"{sequence:04d}"
        traffic_dir.mkdir(parents=True, exist_ok=False, mode=0o750)
        context = TrafficContext(
            traffic_dir,
            record.log,
            seed,
            record.scenario_id,
            "clean",
        )
        self._change_state(
            record,
            SessionState.TRAFFIC_RUNNING,
            "traffic.preparing",
            f"{workload_id} generator preparation started",
        )
        started_ns = 0
        ended_ns = 0
        result: TrafficRunResult | None = None
        validation: TrafficValidation | None = None
        primary_error: BaseException | None = None
        cleanup_error: BaseException | None = None
        try:
            generator.prepare(context)
            started_ns = self._time_ns()
            self._append(
                record,
                "traffic.started",
                f"{workload_id} protected workload started",
                {"workload": workload_id, "sequence": sequence, "seed": seed},
            )
            result = generator.run(context)
            validation = generator.validate(context, result)
            ended_ns = self._time_ns()
            if not validation.passed:
                raise RuntimeError(
                    "traffic validation failed: " + "; ".join(validation.errors)
                )
        except BaseException as error:
            primary_error = error
            if started_ns and not ended_ns:
                ended_ns = self._time_ns()
        finally:
            try:
                generator.cleanup(context)
            except BaseException as error:
                cleanup_error = error
        if primary_error is None and cleanup_error is not None:
            primary_error = cleanup_error

        metadata = generator.metadata()
        traffic_payload: dict[str, object] = {
            "schema": "ipsec-sentinel.live-traffic/v1",
            "session_id": record.store.snapshot.session_id,
            "sequence": sequence,
            "workload": workload_id,
            "generator": metadata.get("generator", generator.name),
            "generator_version": metadata.get("version", generator.version),
            "seed": seed,
            "parameters": dict(metadata.get("parameters", {})),
            "started_at": None if not started_ns else _iso_from_ns(started_ns),
            "ended_at": None if not ended_ns else _iso_from_ns(ended_ns),
            "started_unix_ns": started_ns,
            "ended_unix_ns": ended_ns,
            "result": None if result is None else dict(result.metrics),
            "validation": None if validation is None else asdict(validation),
            "cleanup": {
                "status": "FAILED" if cleanup_error is not None else "SUCCEEDED",
                "exception_type": (
                    None if cleanup_error is None else type(cleanup_error).__name__
                ),
            },
            "status": "FAILED" if primary_error is not None else "PASS",
        }
        write_json_atomic(traffic_dir / "traffic.json", traffic_payload)

        if primary_error is not None:
            if self._traffic_tunnel_healthy(record):
                recovered = transition(
                    record.store.snapshot,
                    SessionState.TUNNEL_ACTIVE,
                    f"{workload_id} failed; tunnel health was independently reverified",
                )
                record.store.append(
                    "traffic.failed",
                    recovered.state,
                    recovered.state_reason,
                    {
                        "workload": workload_id,
                        "sequence": sequence,
                        "exception_type": type(primary_error).__name__,
                    },
                    (),
                    snapshot=recovered,
                    durable=True,
                )
                raise _RecoveredTrafficFailure(primary_error, workload_id)
            raise primary_error

        assert validation is not None and result is not None
        snapshot_path = traffic_dir / "capture-snapshot.pcap"
        record.session.capture_snapshot(snapshot_path)
        summary = self._esp_summarizer(snapshot_path, record.esp_totals)
        if summary is not None:
            record.esp_totals = summary.totals
            self._append(
                record,
                "esp.observed",
                "new protected ESP packets were parsed from the live capture",
                summary.to_dict(),
                ({"source": "capture", "record": "ESP delta"},),
            )
        workload = WorkloadWindow(
            sequence=sequence,
            workload_id=workload_id,
            seed=seed,
            started_at=_iso_from_ns(started_ns),
            ended_at=_iso_from_ns(ended_ns),
            started_unix_ns=started_ns,
            ended_unix_ns=ended_ns,
            validated=True,
            metadata={
                "generator": traffic_payload["generator"],
                "generator_version": traffic_payload["generator_version"],
                "parameters": traffic_payload["parameters"],
                "result": traffic_payload["result"],
                "validation": traffic_payload["validation"],
            },
        )
        completed = transition(
            record.store.snapshot,
            SessionState.TUNNEL_ACTIVE,
            f"{workload_id} workload completed and validated",
        )
        completed = replace(
            completed,
            completed_workloads=(*completed.completed_workloads, workload),
            latest_completed_workload_sequence=sequence,
        )
        record.store.append(
            "traffic.completed",
            completed.state,
            completed.state_reason,
            {
                "workload": workload_id,
                "sequence": sequence,
                "seed": seed,
                "validation": asdict(validation),
            },
            (),
            snapshot=completed,
            durable=True,
        )

    def _traffic_tunnel_healthy(self, record: _SessionRecord) -> bool:
        try:
            if not bool(record.provider.health().get("ready")):
                return False
            sas = record.session.refresh_sas()
            xfrm = record.session.collect_xfrm()
            primary = getattr(record.session, "captures", {}).get("primary")
            if primary is not None and not bool(primary.running):
                return False
            return bool(sas) and bool(xfrm)
        except BaseException:
            return False

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
