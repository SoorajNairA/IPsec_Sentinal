from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import Executor, Future, ThreadPoolExecutor
from copy import deepcopy
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from secrets import choice, randbits, token_hex
from threading import Event, Lock, Thread
from typing import TextIO
import os

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
from ipsec_sentinel.live.runtime import (
    LiveLabLock,
    OwnedProcess,
    RuntimeOwnership,
    process_start_identity,
    record_resource,
    recover_stale_runtime,
)
from ipsec_sentinel.session import SecureSession
from ipsec_sentinel.artifacts import write_json_atomic, write_text_atomic
from ipsec_sentinel.dataset.models import WorkloadWindow as DatasetWorkloadWindow
from ipsec_sentinel.evidence import evaluate_ipsec, evaluate_tunnel, parse_sa
from ipsec_sentinel.pcap import PcapSummary, derive_workload_esp, inspect_ml_pcap
from ipsec_sentinel.scenario import negotiated_policy
from ipsec_sentinel.traffic import register_builtin_generators
from ipsec_sentinel.traffic.base import (
    SUPERVISED_CLASS_ALLOWLIST,
    TrafficContext,
    TrafficGenerator,
    TrafficRunResult,
    TrafficValidation,
    create_generator,
)
from ipsec_sentinel.topology import NAMESPACES


SessionFactory = Callable[..., SecureSession]
ProviderFactory = Callable[[SecureSession], LabProvider]
GeneratorFactory = Callable[[str, int], TrafficGenerator]
EspSummarizer = Callable[[Path, EspTotals], EspSummary | None]
CaptureDeriver = Callable[[Path, Path, DatasetWorkloadWindow, tuple[str, str]], PcapSummary]
CaptureInspector = Callable[[Path, DatasetWorkloadWindow, tuple[str, str]], PcapSummary]
AnalysisRunner = Callable[..., dict[str, object]]


@dataclass
class _SessionRecord:
    scenario_id: str
    mystery: bool
    session: SecureSession
    provider: LabProvider
    store: EventStore
    log: TextIO
    ownership_path: Path
    next_workload_sequence: int = 1
    esp_totals: EspTotals = field(default_factory=EspTotals.empty)
    analysis: Mapping[str, object] | None = None


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


def _default_analysis_runner(*args: object, **kwargs: object) -> dict[str, object]:
    from ipsec_sentinel.frontend.bridge import analyze_for_frontend

    return analyze_for_frontend(*args, **kwargs)  # type: ignore[arg-type]


def _iso_from_ns(value: int) -> str:
    return (
        datetime.fromtimestamp(value / 1_000_000_000, timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _spis(sas: Mapping[str, str]) -> dict[str, list[str]]:
    return {
        gateway: list(parse_sa(sas.get(gateway, "")).spis)
        for gateway in ("gateway-a", "gateway-b")
    }


def _normalized_encryption(value: str) -> str:
    upper = value.upper()
    if "AES_GCM_16_256" in upper:
        return "AES-256-GCM"
    if "AES_GCM_16_128" in upper:
        return "AES-128-GCM"
    if "AES_CBC_256" in upper:
        return "AES-256-CBC"
    return "UNKNOWN"


def _public_mystery_envelope(envelope: Mapping[str, object]) -> dict[str, object]:
    public = deepcopy(envelope)
    analysis = public.get("analysis")
    if not isinstance(analysis, dict):
        return public
    controlled = analysis.get("controlled_evidence")
    capture_provenance = (
        controlled.get("capture_provenance")
        if isinstance(controlled, Mapping)
        else None
    )
    analysis["controlled_evidence"] = {
        "available": True,
        "source": "controlled-lab-artifacts",
        "withheld_until_reveal": True,
        "capture_provenance": capture_provenance,
    }
    evidence = analysis.get("evidence")
    if isinstance(evidence, list):
        retained: list[object] = []
        for item in evidence:
            if not isinstance(item, dict):
                retained.append(item)
                continue
            if item.get("id") == "ev-lab-config-001":
                continue
            if item.get("id") == "ev-lab-pfs-001":
                raw = item.get("raw_value")
                if isinstance(raw, list):
                    item["raw_value"] = [
                        value
                        for value in raw
                        if not (
                            isinstance(value, str)
                            and value.startswith(
                                (
                                    "pfs_configured=",
                                    "expected_rekey_proposal_selected=",
                                )
                            )
                        )
                    ]
            retained.append(item)
        analysis["evidence"] = retained
    findings = analysis.get("findings")
    if isinstance(findings, list):
        analysis["findings"] = [
            finding
            for finding in findings
            if not (
                isinstance(finding, Mapping)
                and (
                    finding.get("rule_id") == "IPSEC-EVIDENCE-001"
                    or "ev-lab-config-001" in finding.get("evidence_ids", [])
                )
            )
        ]
    return public


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
        capture_deriver: CaptureDeriver = derive_workload_esp,
        capture_inspector: CaptureInspector = inspect_ml_pcap,
        analysis_runner: AnalysisRunner = _default_analysis_runner,
        model_dir: Path = Path("model"),
        lock_path: Path | None = None,
        startup_recovery: Callable[[Path], None] | None = None,
        workload_allowlist: frozenset[str] = SUPERVISED_CLASS_ALLOWLIST,
    ) -> None:
        self.root_dir = Path(root_dir)
        self.root_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
        if lock_path is None:
            lock_path = (
                Path("/run/ipsec-sentinel/.live-lab.lock")
                if getattr(os, "geteuid", lambda: 1)() == 0
                else self.root_dir / ".live-lab.lock"
            )
        self._runtime_lock = LiveLabLock.acquire(lock_path)
        try:
            if startup_recovery is not None:
                startup_recovery(self.root_dir)
            for ownership_path in sorted(
                self.root_dir.glob("SNT-*/runtime-ownership.json")
            ):
                ownership = RuntimeOwnership.read(ownership_path)
                report = recover_stale_runtime(
                    ownership_path,
                    runtime_roots=(
                        Path("/run/ipsec-sentinel") / ownership.session_id,
                    ),
                )
                if report.status == "PARTIAL":
                    raise RuntimeError(
                        f"stale Live Lab recovery incomplete for {ownership.session_id}"
                    )
        except BaseException:
            self._runtime_lock.release()
            raise
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
        self._capture_deriver = capture_deriver
        self._capture_inspector = capture_inspector
        self._analysis_runner = analysis_runner
        self._model_dir = Path(model_dir)
        self.workload_allowlist = workload_allowlist
        self._records: dict[str, _SessionRecord] = {}
        self._active_id: str | None = None
        self._mystery_index = 0
        self._closed = False
        self._accept_lock = Lock()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        errors: list[str] = []
        try:
            if self._owns_executor:
                try:
                    assert isinstance(self._executor, ThreadPoolExecutor)
                    self._executor.shutdown(wait=True, cancel_futures=False)
                except BaseException as error:
                    errors.append(f"executor: {error}")
            for record in self._records.values():
                cleanup_succeeded = (
                    record.store.snapshot.cleanup_status
                    is not CleanupStatus.FAILED
                )
                try:
                    if record.store.snapshot.state is not SessionState.IDLE:
                        self._record_live_resources(record)
                    if cleanup_succeeded and bool(
                        record.provider.health().get("ready")
                    ):
                        record.provider.stop_scenario()
                except BaseException as error:
                    cleanup_succeeded = False
                    errors.append(f"{record.store.snapshot.session_id} cleanup: {error}")
                finally:
                    if cleanup_succeeded:
                        record.ownership_path.unlink(missing_ok=True)
                    record.log.close()
        finally:
            self._runtime_lock.release()
        if errors:
            raise RuntimeError("Live Lab shutdown errors: " + "; ".join(errors))

    def create_session(self, scenario_id: str) -> LiveSessionSnapshot:
        with self._accept_lock:
            return self._create_session(scenario_id)

    def _create_session(self, scenario_id: str) -> LiveSessionSnapshot:
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
        ownership_path = run_dir / "runtime-ownership.json"
        ownership = RuntimeOwnership.create(session_id)
        ownership.write(ownership_path)
        record_resource(ownership_path, evidence_path=run_dir)

        def observe_process(role: str, pid: int) -> None:
            identity = process_start_identity(pid)
            if identity is None:
                raise RuntimeError(f"cannot identify newly started {role} process")
            record_resource(
                ownership_path,
                process=OwnedProcess(pid, identity, role),
            )

        secure_session = self._session_factory(
            run_dir,
            log,
            primary_capture_name="full-evidence.pcap",
            process_observer=observe_process,
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
            ownership_path,
        )
        self._records[session_id] = record
        self._active_id = session_id
        self._record_live_resources(record)
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

    def wait_events(
        self,
        session_id: str,
        after_id: int,
        timeout: float,
    ) -> tuple[LiveEvent, ...]:
        return self._record(session_id).store.wait(after_id, timeout)

    def run_traffic(self, session_id: str, workload_id: str) -> Future[object]:
        record = self._record(session_id)
        if record.session.cloud_mode and workload_id not in {"icmp", "video"}:
            raise LiveProblem(
                "WORKLOAD_NOT_AVAILABLE_IN_CLOUD",
                "Cloud prototype mode currently supports ICMP and Video.",
                http_status=400,
                session_id=session_id,
            )
        if workload_id not in self.workload_allowlist:
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

    def trigger_rekey(self, session_id: str) -> Future[object]:
        return self.submit(session_id, LiveAction.REKEY, {})

    def refresh(self, session_id: str) -> Future[object]:
        return self.submit(session_id, LiveAction.REFRESH, {})

    def analyze(self, session_id: str) -> Future[object]:
        return self.submit(session_id, LiveAction.ANALYZE, {})

    def reveal(self, session_id: str) -> Future[object]:
        return self.submit(session_id, LiveAction.REVEAL, {})

    def disconnect(self, session_id: str) -> Future[object]:
        return self.submit(session_id, LiveAction.DISCONNECT, {})

    def submit(
        self,
        session_id: str,
        action: LiveAction | str,
        payload: Mapping[str, object],
    ) -> Future[object]:
        with self._accept_lock:
            return self._submit(session_id, action, payload)

    def _submit(
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
        accepted = replace(
            record.store.snapshot,
            active_action=normalized_action,
            state_reason=f"{normalized_action.value} action accepted",
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
            elif action is LiveAction.REKEY:
                self._rekey(record)
            elif action is LiveAction.REFRESH:
                self._refresh(record)
            elif action is LiveAction.ANALYZE:
                self._analyze(record)
            elif action is LiveAction.REVEAL:
                self._reveal(record)
            elif action is LiveAction.DISCONNECT:
                self._disconnect(record)
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
        if (
            action is LiveAction.DISCONNECT
            and record.store.snapshot.cleanup_status is CleanupStatus.FAILED
        ):
            cleared = replace(
                record.store.snapshot,
                active_action=None,
                state_reason="DISCONNECT action failed during cleanup",
            )
            record.store.append(
                "action.failed",
                cleared.state,
                cleared.state_reason,
                {"action": action.value, "error": cleared.failure},
                (),
                snapshot=cleared,
                durable=True,
            )
            return
        completed = replace(
            record.store.snapshot,
            active_action=None,
            state_reason=f"{action.value} action completed",
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

    def _rekey(self, record: _SessionRecord) -> None:
        before_sas = record.session.refresh_sas()
        rekeying = transition(
            record.store.snapshot,
            SessionState.REKEYING,
            "verified CHILD_SA rekey started",
        )
        record.store.append(
            "rekey.started",
            rekeying.state,
            rekeying.state_reason,
            {"before_spis": _spis(before_sas)},
            ({"source": "swanctl", "record": "list-sas-before-rekey"},),
            snapshot=rekeying,
            durable=True,
        )
        pfs = record.session.rekey()
        rekey_evidence = getattr(record.session, "rekey_evidence", None)
        after_sas = (
            dict(rekey_evidence.after_sas)
            if rekey_evidence is not None
            else record.session.refresh_sas()
        )
        # SecureSession.rekey() deliberately retains its pre-rekey snapshot for
        # the automated Phase 1 verdict.  Interactive sessions continue after
        # rekey, so their current SA and XFRM snapshots must describe the same
        # replacement CHILD_SA.
        record.session.sas = after_sas
        record.session.collect_xfrm()
        scenario = record.session.scenario
        if scenario is None:
            raise RuntimeError("scenario is unavailable after rekey")
        verification_state = {
            "VERIFIED": "enabled",
            "VERIFIED_DISABLED": "disabled",
        }.get(pfs.status, "unknown")
        active = transition(
            record.store.snapshot,
            SessionState.TUNNEL_ACTIVE,
            "CHILD_SA replacement and PFS semantics evaluated",
        )
        rekey_data: dict[str, object] = {
            "before_spis": _spis(before_sas),
            "after_spis": _spis(after_sas),
            "observed": {
                "status": pfs.status,
                "rekey_observed": pfs.rekey_observed,
                "evidence": list(pfs.evidence),
            },
            "verification_state": verification_state,
        }
        if record.mystery:
            observed = rekey_data["observed"]
            assert isinstance(observed, dict)
            evidence = observed.get("evidence")
            if isinstance(evidence, list):
                observed["evidence"] = [
                    value
                    for value in evidence
                    if not (
                        isinstance(value, str)
                        and value.startswith(
                            (
                                "pfs_configured=",
                                "expected_rekey_proposal_selected=",
                            )
                        )
                    )
                ]
            rekey_data["configuration_withheld"] = True
        else:
            rekey_data["configured"] = {
                "pfs": scenario.ipsec.pfs,
                "esp_proposal": scenario.ipsec.esp_proposal,
            }
        record.store.append(
            "child_sa.rekeyed",
            active.state,
            active.state_reason,
            rekey_data,
            (
                {"source": "swanctl", "record": "list-sas-after-rekey"},
                {"source": "strongswan-log", "record": "child-rekey-proposal"},
                {"source": "xfrm", "record": "state-and-policy-after-rekey"},
            ),
            snapshot=active,
            durable=True,
        )

    def _refresh(self, record: _SessionRecord) -> None:
        sas = record.session.refresh_sas()
        xfrm = record.session.collect_xfrm()
        if not sas or not xfrm:
            raise RuntimeError("SA refresh returned incomplete evidence")
        self._append(
            record,
            "sa.refreshed",
            "swanctl and XFRM state were refreshed",
            {"spis": _spis(sas), "gateways": sorted(xfrm)},
            (
                {"source": "swanctl", "record": "list-sas"},
                {"source": "xfrm", "record": "state-and-policy"},
            ),
        )

    def _analyze(self, record: _SessionRecord) -> None:
        latest_sequence = record.store.snapshot.latest_completed_workload_sequence
        workload = next(
            (
                item
                for item in record.store.snapshot.completed_workloads
                if item.sequence == latest_sequence
            ),
            None,
        )
        if workload is None:
            raise RuntimeError("latest completed workload metadata is unavailable")
        self._change_state(
            record,
            SessionState.ANALYZING,
            "analysis.started",
            "full-session capture sealing and analysis started",
        )
        record.session.stop_captures()
        sealed = replace(
            record.store.snapshot,
            capture_status=CaptureStatus.SEALED,
            state_reason="full-session evidence capture sealed",
        )
        record.store.append(
            "capture.sealed",
            sealed.state,
            sealed.state_reason,
            {"artifact": "full-evidence.pcap"},
            ({"source": "capture", "record": "full-session-finalized"},),
            snapshot=sealed,
            durable=True,
        )
        capture_evidence = record.session.validate_captures()
        window = DatasetWorkloadWindow(
            workload.started_unix_ns,
            workload.ended_unix_ns,
        )
        full_path = record.session.run_dir / "full-evidence.pcap"
        workload_path = record.session.run_dir / "encrypted.pcap"
        peers = record.session.capture_peers
        normalization_receipt: Mapping[str, object] | None = None
        if record.session.cloud_mode:
            from ipsec_sentinel.cloud.natt import normalize_natt_workload

            receipt = normalize_natt_workload(
                full_path,
                workload_path,
                peers,
                workload.started_unix_ns,
                workload.ended_unix_ns,
                excluded_intervals=record.session.control_intervals,
            )
            normalization_receipt = receipt.to_dict()
            write_json_atomic(
                record.session.run_dir / "natt-normalization.json",
                normalization_receipt,
            )
        else:
            self._capture_deriver(full_path, workload_path, window, peers)
        ml_summary = self._capture_inspector(workload_path, window, peers)
        self._write_analysis_evidence(
            record,
            workload,
            capture_evidence,
            ml_summary,
            normalization_receipt=normalization_receipt,
        )
        envelope = self._analysis_runner(
            full_path,
            model_dir=self._model_dir,
            evidence_dir=record.session.run_dir,
            traffic_capture_path=workload_path,
        )
        analysis = envelope.get("analysis")
        if not isinstance(analysis, Mapping) or analysis.get("summary", {}).get("status") != "COMPLETE":  # type: ignore[union-attr]
            raise RuntimeError("session analyzer did not complete")
        write_json_atomic(record.session.run_dir / "analysis.json", dict(envelope))
        record.analysis = dict(envelope)
        ready = transition(
            record.store.snapshot,
            SessionState.READY,
            "session analysis completed from sealed evidence",
        )
        ready = replace(ready, analysis_available=True)
        public_envelope = (
            _public_mystery_envelope(envelope)
            if record.mystery
            else deepcopy(envelope)
        )
        record.store.append(
            "analysis.completed",
            ready.state,
            ready.state_reason,
            public_envelope,
            (
                {"source": "capture", "record": "full-evidence.pcap"},
                {"source": "capture", "record": "encrypted.pcap"},
                {"source": "analyzer", "record": "analysis.json"},
            ),
            snapshot=ready,
            durable=True,
        )

    def _write_analysis_evidence(
        self,
        record: _SessionRecord,
        workload: WorkloadWindow,
        capture_evidence: object,
        ml_summary: PcapSummary,
        normalization_receipt: Mapping[str, object] | None = None,
    ) -> None:
        scenario = record.session.scenario
        if scenario is None:
            raise RuntimeError("scenario is unavailable during analysis")
        verification = evaluate_ipsec(
            record.session.sas,
            record.session.xfrm,
            capture_evidence,
            run_id=record.store.snapshot.session_id,
            scenario=scenario,
            allow_natt=record.session.cloud_mode,
            allow_dynamic_outer=record.session.cloud_mode,
        )
        if verification.status != "PASS":
            failed = [check.name for check in verification.checks if not check.passed]
            raise RuntimeError("sealed IPsec evidence failed: " + ", ".join(failed))
        sa = parse_sa(record.session.sas["gateway-a"])
        configured = {
            "ike_version": scenario.ipsec.ike_version,
            "mode": scenario.ipsec.mode,
            "ike_proposal": scenario.ipsec.ike_proposal,
            "esp_proposal": scenario.ipsec.esp_proposal,
            "pfs": scenario.ipsec.pfs,
            "ip_version": scenario.ipsec.ip_version,
            "local_subnet": scenario.ipsec.local_subnet,
            "remote_subnet": scenario.ipsec.remote_subnet,
            "transit_subnet": scenario.ipsec.transit_subnet,
        }
        observed = {
            "ike_version": 2,
            "ike_proposal": sa.ike_proposal,
            "esp_proposal": f"{sa.esp_proposal}/NO_EXT_SEQ",
            "pfs": asdict(record.session.pfs),
        }
        write_json_atomic(
            record.session.run_dir / "ground_truth.json",
            {
                "schema_version": "ipsec-sentinel.live-ground-truth/v1",
                "run_id": record.store.snapshot.session_id,
                "status": "PASS",
                "capture": {
                    "full_evidence_file": "full-evidence.pcap",
                    "ml_input_file": "encrypted.pcap",
                    "workload_started_unix_ns": workload.started_unix_ns,
                    "workload_finished_unix_ns": workload.ended_unix_ns,
                    "ml_esp_packets": ml_summary.packet_count,
                    "ml_capture_bytes": ml_summary.capture_bytes,
                    "ml_duration_seconds": ml_summary.duration_seconds,
                    "ml_provenance": (
                        "NATIVE_ESP_WORKLOAD_WINDOW"
                        if normalization_receipt is None
                        else "NATT_NORMALIZED_WORKLOAD_WINDOW"
                    ),
                    "normalization": normalization_receipt,
                },
                "traffic": {
                    "class": workload.workload_id,
                    "sequence": workload.sequence,
                    "seed": workload.seed,
                    "validated": workload.validated,
                    "generator": workload.metadata.get("generator"),
                    "generator_version": workload.metadata.get("generator_version"),
                },
                "ipsec": {
                    "scenario_id": scenario.id,
                    "configured": configured,
                    "observed": observed,
                },
            },
        )
        write_json_atomic(
            record.session.run_dir / "verification.json",
            verification.to_dict(),
        )
        write_text_atomic(record.session.run_dir / "scenario.yaml", record.session.scenario_yaml)
        for gateway in ("gateway-a", "gateway-b"):
            write_text_atomic(
                record.session.run_dir / f"swanctl-{gateway}.txt",
                record.session.sas[gateway],
            )
            write_text_atomic(
                record.session.run_dir / f"xfrm-{gateway}.txt",
                record.session.xfrm[gateway],
            )

    def _reveal(self, record: _SessionRecord) -> None:
        if record.analysis is None:
            raise RuntimeError("analysis is unavailable for Mystery reveal")
        scenario = record.session.scenario
        if scenario is None:
            raise RuntimeError("scenario is unavailable for Mystery reveal")
        analysis = record.analysis["analysis"]
        assert isinstance(analysis, Mapping)
        ike = analysis.get("ike", {})
        pfs = analysis.get("pfs", {})
        assert isinstance(ike, Mapping) and isinstance(pfs, Mapping)
        encryption = ike.get("encryption", {})
        assert isinstance(encryption, Mapping)
        expected_encryption = _normalized_encryption(
            negotiated_policy(scenario).esp_encryption
        )
        expected_pfs = "enabled" if scenario.ipsec.pfs else "disabled"
        revealed = replace(
            record.store.snapshot,
            revealed=True,
            state_reason="Mystery VPN ground truth revealed after analysis",
        )
        record.store.append(
            "mystery.revealed",
            revealed.state,
            revealed.state_reason,
            {
                "ground_truth": {
                    "scenario_id": scenario.id,
                    "display_name": SCENARIO_NAMES[scenario.id],
                    "encryption": expected_encryption,
                    "pfs": expected_pfs,
                    "provenance": "GROUND_TRUTH",
                },
                "sentinel": {
                    "encryption": dict(encryption),
                    "pfs": dict(pfs),
                },
                "comparison": {
                    "encryption_match": encryption.get("normalized") == expected_encryption,
                    "pfs_match": pfs.get("state") == expected_pfs,
                },
            },
            ({"source": "scenario", "record": "controlled-ground-truth"},),
            snapshot=revealed,
            durable=True,
        )

    def _disconnect(self, record: _SessionRecord) -> None:
        current = record.store.snapshot
        if current.state is SessionState.COMPLETE:
            record.provider.stop_scenario()
            repeated = replace(
                current,
                cleanup_status=CleanupStatus.SUCCEEDED,
                tunnel_status=TunnelStatus.DISCONNECTED,
                state_reason="cleanup already completed",
            )
            record.store.append(
                "cleanup.completed",
                repeated.state,
                repeated.state_reason,
                {"idempotent": True},
                (),
                snapshot=repeated,
                durable=True,
            )
            return
        disconnecting = transition(current, SessionState.DISCONNECTING, "disconnect started")
        record.store.append(
            "disconnect.started",
            disconnecting.state,
            disconnecting.state_reason,
            {},
            (),
            snapshot=disconnecting,
            durable=True,
        )
        cleaning = transition(
            record.store.snapshot,
            SessionState.CLEANING_UP,
            "owned Live Lab resource cleanup started",
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
        self._record_live_resources(record)
        try:
            record.provider.stop_scenario()
        except BaseException as error:
            failed = transition(
                record.store.snapshot,
                SessionState.FAILED,
                "disconnect cleanup did not complete",
            )
            primary_failure = failed.failure or {
                "code": "DISCONNECT_FAILED",
                "message": "Live Lab disconnect cleanup failed; retry disconnect.",
                "operation": "DISCONNECT",
                "exception_type": type(error).__name__,
            }
            failed = replace(
                failed,
                cleanup_status=CleanupStatus.FAILED,
                tunnel_status=TunnelStatus.FAILED,
                capture_status=(
                    CaptureStatus.FAILED
                    if failed.capture_status is CaptureStatus.RUNNING
                    else failed.capture_status
                ),
                failure=primary_failure,
            )
            record.store.append(
                "cleanup.failed",
                failed.state,
                failed.state_reason,
                {"exception_type": type(error).__name__},
                (),
                snapshot=failed,
                durable=True,
            )
            return
        record.ownership_path.unlink(missing_ok=True)
        complete = transition(
            record.store.snapshot,
            SessionState.COMPLETE,
            "disconnect cleanup completed",
        )
        complete = replace(
            complete,
            cleanup_status=CleanupStatus.SUCCEEDED,
            tunnel_status=TunnelStatus.DISCONNECTED,
            capture_status=(
                CaptureStatus.SEALED
                if complete.capture_status is CaptureStatus.SEALED
                else CaptureStatus.STOPPED
            ),
        )
        record.store.append(
            "cleanup.completed",
            complete.state,
            complete.state_reason,
            {"idempotent": False},
            (),
            snapshot=complete,
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
            remote_video_controller=(
                getattr(record.session.pair, "endpoint_client", None)
                if record.session.cloud_mode
                else None
            ),
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
            ended_ns = self._time_ns()
            after_workload = getattr(generator, "after_workload", None)
            if callable(after_workload):
                after_workload(context)
            validation = generator.validate(context, result)
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
        if record.session.cloud_mode:
            from ipsec_sentinel.cloud.natt import normalize_natt_workload

            live_path = traffic_dir / "live-encrypted.pcap"
            receipt = normalize_natt_workload(
                snapshot_path,
                live_path,
                record.session.capture_peers,
                started_ns,
                ended_ns,
                excluded_intervals=record.session.control_intervals,
            )
            packet_count = record.esp_totals.packet_count + receipt.packet_count
            byte_count = record.esp_totals.bytes + receipt.capture_bytes
            summary = EspSummary(
                record.session.capture_peers,
                packet_count,
                byte_count,
                receipt.packet_count,
                receipt.capture_bytes,
                {"captured": receipt.packet_count},
                {"captured": receipt.capture_bytes},
                receipt.first_timestamp_ns,
                receipt.last_timestamp_ns,
            )
        else:
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
            self._validate_tunnel_evidence(record, sas, xfrm)
            return True
        except BaseException:
            return False

    def _validate_tunnel_evidence(
        self,
        record: _SessionRecord,
        sas: Mapping[str, str],
        xfrm: Mapping[str, str],
    ) -> None:
        scenario = record.session.scenario
        if scenario is None:
            raise RuntimeError("scenario is unavailable during tunnel validation")
        verification = evaluate_tunnel(
            dict(sas),
            dict(xfrm),
            run_id=record.store.snapshot.session_id,
            scenario=scenario,
            allow_dynamic_outer=record.session.cloud_mode,
        )
        if verification.status != "PASS":
            failed = [check.name for check in verification.checks if not check.passed]
            raise RuntimeError("tunnel evidence failed: " + ", ".join(failed))
        primary = getattr(record.session, "captures", {}).get("primary")
        if primary is None or not bool(getattr(primary, "running", False)):
            raise RuntimeError("full-session capture is not running")

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
        self._record_live_resources(record)
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
        self._record_live_resources(record)
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
        self._validate_tunnel_evidence(
            record,
            record.session.sas,
            record.session.xfrm,
        )
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
        self._record_live_resources(record)
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
            record.ownership_path.unlink(missing_ok=True)
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

    def _record_live_resources(self, record: _SessionRecord) -> None:
        if not record.ownership_path.is_file():
            return
        namespaces = (
            ("ips-client", "ips-gwa")
            if record.session.cloud_mode
            else NAMESPACES
        )
        for namespace in namespaces:
            record_resource(record.ownership_path, namespace=namespace)
        runtime_root = (
            Path("/run/ipsec-sentinel") / record.store.snapshot.session_id
        ).resolve()
        runtime_paths: set[Path] = {runtime_root}
        gateways = ("gateway-a",) if record.session.cloud_mode else ("gateway-a", "gateway-b")
        for gateway in gateways:
            gateway_root = runtime_root / gateway
            runtime_paths.add(gateway_root)
            runtime_paths.update(
                gateway_root / name
                for name in ("charon.vici", "charon.pid", "charon.log")
            )
        capture_root = runtime_root / "capture"
        runtime_paths.add(capture_root)
        runtime_paths.update(
            capture_root / name
            for name in (
                "full-evidence.pcap",
                "cleartext-audit-gateway-a.pcap",
                "cleartext-audit-gateway-b.pcap",
            )
        )
        pair_files = getattr(record.session.pair, "files", {})
        if isinstance(pair_files, Mapping):
            for files in pair_files.values():
                for attribute in ("socket", "pid", "log"):
                    candidate = getattr(files, attribute, None)
                    if candidate is None:
                        continue
                    path = Path(candidate).resolve()
                    if path == runtime_root or runtime_root in path.parents:
                        runtime_paths.update((path, path.parent))
        temporary_pcaps = getattr(record.session, "temporary_pcaps", {})
        if isinstance(temporary_pcaps, Mapping):
            for candidate in temporary_pcaps.values():
                path = Path(candidate).resolve()
                if path == runtime_root or runtime_root in path.parents:
                    runtime_paths.update((path, path.parent))
        for path in sorted(runtime_paths, key=lambda item: (len(item.parts), str(item))):
            record_resource(record.ownership_path, runtime_path=path)
        process_candidates: list[tuple[str, object]] = []
        pair_processes = getattr(record.session.pair, "_processes", {})
        if isinstance(pair_processes, Mapping):
            process_candidates.extend(
                (f"strongswan-{name}", process)
                for name, process in pair_processes.items()
            )
        captures = getattr(record.session, "captures", {})
        if isinstance(captures, Mapping):
            process_candidates.extend(
                (f"tcpdump-{name}", capture)
                for name, capture in captures.items()
            )
        for role, resource in process_candidates:
            pid = getattr(resource, "pid", None)
            if not isinstance(pid, int) or pid <= 0:
                continue
            identity = process_start_identity(pid)
            if identity is None:
                continue
            record_resource(
                record.ownership_path,
                process=OwnedProcess(pid, identity, role),
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
