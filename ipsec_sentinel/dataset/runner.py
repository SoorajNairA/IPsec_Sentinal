from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
import hashlib
from io import StringIO
import os
from pathlib import Path
import platform
import re
import shutil
import time as time_module

from ipsec_sentinel.artifacts import write_text_atomic
from ipsec_sentinel.command import CommandFailure, run_checked
from ipsec_sentinel.dataset.artifacts import (
    build_terminal_payloads,
    publish_terminal_json,
    stage_terminal_json,
    validate_terminal_payloads,
    write_raw_attempt_artifacts,
)
from ipsec_sentinel.dataset.config import DatasetConfig
from ipsec_sentinel.dataset.manifest import AttemptPlan, Manifest
from ipsec_sentinel.dataset.matrix import matrix_fingerprint
from ipsec_sentinel.dataset.models import (
    DATASET_SCHEMA_VERSION,
    MANIFEST_SCHEMA_VERSION,
    SCENARIO_SCHEMA_VERSION,
    SEED_DERIVATION_VERSION,
    AttemptOutcome,
    CleanupState,
    ReproducibilityMetadata,
    RunState,
    WorkloadWindow,
)
from ipsec_sentinel.dataset.network import CleanNetworkProfile
from ipsec_sentinel.dataset.summary import DatasetSummary, build_summary, write_summary
from ipsec_sentinel.evidence import evaluate_ipsec, evaluate_tunnel
from ipsec_sentinel.models import StageRecord, Verification
from ipsec_sentinel.pcap import PcapSummary, derive_workload_esp, inspect_ml_pcap
from ipsec_sentinel.scenario import Scenario
from ipsec_sentinel.session import SecureSession
from ipsec_sentinel.traffic.base import (
    TrafficContext,
    TrafficGenerator,
    TrafficRunResult,
    TrafficValidation,
    create_generator,
    generator_versions,
)
from ipsec_sentinel.traffic import register_builtin_generators


DATASET_STAGES = (
    "preflight",
    "reset",
    "scenario_load",
    "topology_setup_readback",
    "network_profile",
    "daemon_start",
    "traffic_prepare",
    "capture_start",
    "configuration_load",
    "initiate",
    "sa_wait",
    "xfrm_collection",
    "traffic_run",
    "traffic_validate",
    "pfs_rekey",
    "capture_stop",
    "full_pcap_validate",
    "pcap_derive",
    "ml_pcap_validate",
    "artifacts",
    "cleanup",
    "metadata",
    "terminal_publish",
)

FAILURE_BY_STAGE = {
    "preflight": "preflight_failed",
    "reset": "topology_failed",
    "scenario_load": "configuration_failed",
    "topology_setup_readback": "topology_failed",
    "network_profile": "topology_failed",
    "daemon_start": "tunnel_establishment_failed",
    "traffic_prepare": "traffic_prepare_failed",
    "capture_start": "capture_failed",
    "configuration_load": "tunnel_establishment_failed",
    "initiate": "tunnel_establishment_failed",
    "sa_wait": "tunnel_establishment_failed",
    "xfrm_collection": "ipsec_evidence_failed",
    "traffic_run": "traffic_generator_failed",
    "traffic_validate": "traffic_validation_failed",
    "pfs_rekey": "ipsec_evidence_failed",
    "capture_stop": "capture_failed",
    "full_pcap_validate": "capture_failed",
    "pcap_derive": "pcap_derivation_failed",
    "ml_pcap_validate": "zero_or_insufficient_esp",
    "artifacts": "artifact_publication_failed",
    "metadata": "metadata_collection_failed",
    "terminal_publish": "artifact_publication_failed",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def dataset_preflight() -> None:
    for program in ("git", "tc", "python3"):
        if shutil.which(program) is None:
            raise RuntimeError(f"required dataset program is missing: {program}")


def classify_failure(stage: str, error: BaseException) -> str:
    if isinstance(error, KeyboardInterrupt):
        return "interrupted"
    return FAILURE_BY_STAGE.get(stage, "unexpected_error")


def finalize_attempt_state(
    *,
    interrupted: bool,
    primary_error: BaseException | None,
    primary_failure_class: str | None = None,
    cleanup_state: CleanupState,
    validations: tuple[bool, bool, bool],
) -> tuple[RunState, bool, str | None]:
    if interrupted:
        return RunState.INCOMPLETE, False, "interrupted"
    if cleanup_state is CleanupState.FAILED:
        return RunState.FAILED, False, "cleanup_failed"
    if primary_error is not None:
        return RunState.FAILED, False, primary_failure_class or "unexpected_error"
    if not all(validations):
        return RunState.FAILED, False, "dataset_validation_failed"
    return RunState.PASS, True, None


def minimum_esp_packets(traffic_class: str, parameters: dict[str, object]) -> int:
    if traffic_class == "icmp":
        return 2 * int(parameters["count"])
    if traffic_class == "web":
        return max(10, 2 * len(parameters["requests"]))  # type: ignore[arg-type]
    if traffic_class == "video":
        return max(20, 3 * len(parameters["segments"]))  # type: ignore[arg-type]
    if traffic_class == "voip":
        return max(20, int(parameters["expected_packets_total"]) // 2)
    raise ValueError(f"unsupported traffic class: {traffic_class}")


def _git_environment() -> dict[str, str] | None:
    marker = Path(".git")
    if not marker.is_file():
        return None
    line = marker.read_text(encoding="utf-8").strip()
    if not line.startswith("gitdir: "):
        return None
    git_dir = line.removeprefix("gitdir: ")
    match = re.fullmatch(r"([A-Za-z]):/(.*)", git_dir)
    if match and platform.system() == "Linux":
        git_dir = f"/mnt/{match.group(1).lower()}/{match.group(2)}"
    environment = dict(os.environ)
    environment["GIT_DIR"] = git_dir
    environment["GIT_WORK_TREE"] = str(Path.cwd())
    return environment


def collect_reproducibility(
    *,
    context: TrafficContext,
    generator: TrafficGenerator,
    matrix_fingerprint: str,
    run_started_at: str,
    run_finished_at: str,
    window: WorkloadWindow | None,
) -> ReproducibilityMetadata:
    errors: list[str] = []
    git_env = _git_environment()

    def optional_command(
        argv: list[str], name: str, *, env: dict[str, str] | None = None
    ) -> str:
        try:
            return run_checked(argv, 10, context.log, env=env).stdout.strip()
        except BaseException as error:
            errors.append(f"{name}: {error}")
            return "UNAVAILABLE"

    commit = optional_command(["git", "rev-parse", "HEAD"], "git_commit_sha", env=git_env)
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        errors.append("git_commit_sha: invalid or unavailable")
    status = optional_command(
        ["git", "status", "--porcelain"], "git_status", env=git_env
    )
    dirty = bool(status.strip()) and status != "UNAVAILABLE"
    diff_hash = None
    if dirty:
        diff = optional_command(
            ["git", "diff", "--binary", "HEAD"], "git_diff", env=git_env
        )
        diff_hash = hashlib.sha256((status + "\n" + diff).encode("utf-8")).hexdigest()
    try:
        strongswan = run_checked(["swanctl", "--version"], 10, context.log).stdout.strip()
    except CommandFailure as error:
        version_output = f"{error.stdout}\n{error.stderr}"
        match = re.search(r"strongSwan\s+([0-9][^\s]*)\s+swanctl", version_output)
        if match is None:
            errors.append(f"strongswan_version: {error}")
            strongswan = "UNAVAILABLE"
        else:
            strongswan = f"strongSwan {match.group(1)}"
    return ReproducibilityMetadata(
        commit,
        dirty,
        diff_hash,
        DATASET_SCHEMA_VERSION,
        SCENARIO_SCHEMA_VERSION,
        MANIFEST_SCHEMA_VERSION,
        strongswan,
        platform.release(),
        platform.version(),
        platform.python_implementation(),
        platform.python_version(),
        platform.platform(),
        platform.machine(),
        generator.name,
        generator.version,
        SEED_DERIVATION_VERSION,
        context.seed,
        matrix_fingerprint,
        run_started_at,
        run_finished_at,
        0 if window is None else window.started_unix_ns,
        0 if window is None else window.finished_unix_ns,
        tuple(errors),
    )


def unavailable_reproducibility(
    *,
    context: TrafficContext,
    generator: TrafficGenerator,
    matrix_fingerprint: str,
    run_started_at: str,
    run_finished_at: str,
    window: WorkloadWindow | None,
    error: BaseException,
) -> ReproducibilityMetadata:
    return ReproducibilityMetadata(
        "UNAVAILABLE",
        False,
        None,
        DATASET_SCHEMA_VERSION,
        SCENARIO_SCHEMA_VERSION,
        MANIFEST_SCHEMA_VERSION,
        "UNAVAILABLE",
        platform.release(),
        platform.version(),
        platform.python_implementation(),
        platform.python_version(),
        platform.platform(),
        platform.machine(),
        generator.name,
        generator.version,
        SEED_DERIVATION_VERSION,
        context.seed,
        matrix_fingerprint,
        run_started_at,
        run_finished_at,
        0 if window is None else window.started_unix_ns,
        0 if window is None else window.finished_unix_ns,
        (f"metadata collector: {error}",),
    )


def _noop_stage(stage: str) -> None:
    del stage


def run_dataset_attempt(
    plan: AttemptPlan,
    dataset_root: Path,
    matrix_fingerprint: str,
    *,
    clock: object = time_module,
    stage_hook: Callable[[str], None] = _noop_stage,
    session_factory: Callable[..., SecureSession] = SecureSession,
    generator_factory: Callable[[str, int], TrafficGenerator] = create_generator,
    profile_factory: Callable[[], CleanNetworkProfile] = CleanNetworkProfile,
) -> AttemptOutcome:
    run_dir = dataset_root / plan.artifact_path
    run_dir.mkdir(parents=True, mode=0o750)
    log = StringIO()
    generator = generator_factory(plan.traffic_class, plan.seed)
    context = TrafficContext(
        run_dir, log, plan.seed, plan.scenario_id, plan.network_profile
    )
    session = session_factory(
        run_dir, log, primary_capture_name="full-evidence.pcap"
    )
    profile = profile_factory()
    stages: list[StageRecord] = []
    cleanup_actions: list[dict[str, object]] = []
    current_stage = "preflight"
    primary_error: BaseException | None = None
    failure_class: str | None = None
    interrupted = False
    traffic_verified = False
    ipsec_verified = False
    capture_verified = False
    workload_window: WorkloadWindow | None = None
    traffic_result: TrafficRunResult | None = None
    traffic_validation: TrafficValidation | None = None
    ipsec_verification: Verification | None = None
    ml_summary: PcapSummary | None = None
    scenario: Scenario | None = None
    network_metadata: dict[str, object] | None = None
    run_started_at = utc_now()

    def execute(name: str, action: Callable[[], object]) -> object:
        nonlocal current_stage
        current_stage = name
        stage_hook(name)
        value = action()
        stages.append(StageRecord(name, "PASS", "completed"))
        return value

    try:
        execute("preflight", lambda: (dataset_preflight(), session.preflight()))
        execute("reset", session.reset)
        scenario = execute(  # type: ignore[assignment]
            "scenario_load", lambda: session.load_scenario(plan.scenario_id)
        )
        execute("topology_setup_readback", session.setup_topology)
        network_metadata = execute(  # type: ignore[assignment]
            "network_profile", lambda: (profile.apply(log), profile.verify(log))[1]
        )
        execute("daemon_start", session.start_daemons)
        execute("traffic_prepare", lambda: generator.prepare(context))
        execute("capture_start", session.start_captures)
        execute("configuration_load", session.load_configuration)
        execute("initiate", session.initiate)
        sas = execute("sa_wait", session.wait_for_sa)
        xfrm = execute("xfrm_collection", session.collect_xfrm)
        tunnel = evaluate_tunnel(sas, xfrm, run_id=plan.attempt_id)  # type: ignore[arg-type]
        if tunnel.status != "PASS":
            raise RuntimeError("tunnel SA/XFRM evidence failed")

        current_stage = "traffic_run"
        stage_hook(current_stage)
        started_ns = clock.time_ns()  # type: ignore[attr-defined]
        try:
            traffic_result = generator.run(context)
        finally:
            finished_ns = clock.time_ns()  # type: ignore[attr-defined]
            workload_window = WorkloadWindow(started_ns, finished_ns)
            stages.append(
                StageRecord(
                    "traffic_run",
                    "PASS" if traffic_result else "FAIL",
                    "workload process returned" if traffic_result else "workload raised",
                )
            )

        traffic_validation = execute(  # type: ignore[assignment]
            "traffic_validate", lambda: generator.validate(context, traffic_result)
        )
        traffic_verified = traffic_validation.passed
        if not traffic_verified:
            raise RuntimeError(
                "traffic validation failed: " + "; ".join(traffic_validation.errors)
            )

        pfs = execute("pfs_rekey", session.rekey)
        execute("capture_stop", session.stop_captures)
        full_capture = execute("full_pcap_validate", session.validate_captures)
        ipsec_verification = evaluate_ipsec(
            session.sas,
            session.xfrm,
            full_capture,  # type: ignore[arg-type]
            run_id=plan.attempt_id,
            pfs=pfs,  # type: ignore[arg-type]
        )
        ipsec_verified = ipsec_verification.status == "PASS"
        if not ipsec_verified:
            raise RuntimeError("complete IPsec evidence failed")

        execute(
            "pcap_derive",
            lambda: derive_workload_esp(
                run_dir / "full-evidence.pcap",
                run_dir / "encrypted.pcap",
                workload_window,
                ("192.0.2.1", "192.0.2.2"),
            ),
        )
        ml_summary = execute(  # type: ignore[assignment]
            "ml_pcap_validate",
            lambda: inspect_ml_pcap(
                run_dir / "encrypted.pcap",
                workload_window,
                ("192.0.2.1", "192.0.2.2"),
            ),
        )
        parameters = generator.metadata()["parameters"]
        minimum = minimum_esp_packets(plan.traffic_class, parameters)  # type: ignore[arg-type]
        if ml_summary.packet_count < minimum:
            failure_class = "zero_or_insufficient_esp"
            raise RuntimeError(
                f"ML ESP packets {ml_summary.packet_count} below minimum {minimum}"
            )
        capture_verified = True
        execute(
            "artifacts",
            lambda: write_raw_attempt_artifacts(
                run_dir, session, generator.metadata(), log.getvalue()
            ),
        )
    except BaseException as error:
        interrupted = isinstance(error, KeyboardInterrupt)
        primary_error = error
        failure_class = failure_class or classify_failure(current_stage, error)
        if (
            not stages
            or stages[-1].name != current_stage
            or stages[-1].status == "PASS"
        ):
            stages.append(
                StageRecord(
                    current_stage,
                    "INTERRUPTED" if interrupted else "FAIL",
                    str(error) or type(error).__name__,
                )
            )

    cleanup_started_at = utc_now()
    for name, action in (
        ("traffic_cleanup", lambda: generator.cleanup(context)),
        ("profile_cleanup", lambda: profile.cleanup(log)),
        ("session_cleanup", session.cleanup),
    ):
        try:
            action()
        except BaseException as error:
            cleanup_actions.append(
                {"name": name, "status": "FAILED", "error": str(error)}
            )
        else:
            cleanup_actions.append({"name": name, "status": "PASS", "error": None})
    cleanup_finished_at = utc_now()
    cleanup_state = (
        CleanupState.PASS
        if all(item["status"] == "PASS" for item in cleanup_actions)
        else CleanupState.FAILED
    )
    stages.append(
        StageRecord("cleanup", cleanup_state.value, "all cleanup actions attempted")
    )

    if not any(stage.name == "artifacts" and stage.status == "PASS" for stage in stages):
        try:
            write_raw_attempt_artifacts(
                run_dir, session, generator.metadata(), log.getvalue()
            )
        except BaseException as error:
            stages.append(StageRecord("artifacts", "FAIL", str(error)))
            if primary_error is None:
                primary_error = error
                failure_class = "artifact_publication_failed"
        else:
            stages.append(
                StageRecord("artifacts", "PASS", "available failure evidence preserved")
            )

    run_finished_at = utc_now()
    try:
        stage_hook("metadata")
        reproducibility = collect_reproducibility(
            context=context,
            generator=generator,
            matrix_fingerprint=matrix_fingerprint,
            run_started_at=run_started_at,
            run_finished_at=run_finished_at,
            window=workload_window,
        )
    except BaseException as error:
        reproducibility = unavailable_reproducibility(
            context=context,
            generator=generator,
            matrix_fingerprint=matrix_fingerprint,
            run_started_at=run_started_at,
            run_finished_at=run_finished_at,
            window=workload_window,
            error=error,
        )
        stages.append(StageRecord("metadata", "FAIL", str(error)))
        if primary_error is None:
            primary_error = error
            failure_class = "metadata_collection_failed"
    else:
        if reproducibility.collection_errors:
            message = "; ".join(reproducibility.collection_errors)
            stages.append(StageRecord("metadata", "FAIL", message))
            if primary_error is None:
                primary_error = RuntimeError(message)
                failure_class = "metadata_collection_failed"
        else:
            stages.append(StageRecord("metadata", "PASS", "complete"))

    state, training_ready, failure_class = finalize_attempt_state(
        interrupted=interrupted,
        primary_error=primary_error,
        primary_failure_class=failure_class,
        cleanup_state=cleanup_state,
        validations=(traffic_verified, ipsec_verified, capture_verified),
    )
    payloads = build_terminal_payloads(
        plan=plan,
        state=state,
        training_ready=training_ready,
        cleanup_state=cleanup_state,
        stages=tuple(stages),
        cleanup_actions=tuple(cleanup_actions),
        generator=generator,
        scenario=scenario,
        session=session,
        traffic_result=traffic_result,
        traffic_validation=traffic_validation,
        ipsec_verification=ipsec_verification,
        workload_window=workload_window,
        ml_summary=ml_summary,
        reproducibility=reproducibility,
        network_metadata=network_metadata,
        traffic_verified=traffic_verified,
        ipsec_verified=ipsec_verified,
        capture_verified=capture_verified,
        failure_class=failure_class,
        primary_error=primary_error,
    )
    try:
        stage_hook("terminal_publish")
        write_text_atomic(run_dir / "run.log", log.getvalue())
        validate_terminal_payloads(
            run_dir, payloads, require_pass_bundle=training_ready
        )
        publish_terminal_json(stage_terminal_json(run_dir, payloads))
    except BaseException as error:
        stages.append(StageRecord("terminal_publish", "FAIL", str(error)))
        state = RunState.FAILED
        training_ready = False
        failure_class = "artifact_publication_failed"
        primary_error = error

    return AttemptOutcome(
        plan.attempt_id,
        plan.slot_id,
        plan.attempt_number,
        state,
        cleanup_state,
        training_ready,
        failure_class,
        None if primary_error is None else str(primary_error),
        plan.artifact_path,
        run_started_at,
        run_finished_at,
        cleanup_started_at,
        cleanup_finished_at,
        tuple(cleanup_actions),
        "; ".join(
            str(item["error"])
            for item in cleanup_actions
            if item["status"] == "FAILED"
        )
        or None,
        traffic_verified,
        ipsec_verified,
        capture_verified,
        0 if ml_summary is None else ml_summary.packet_count,
        0 if ml_summary is None else ml_summary.capture_bytes,
        0.0 if ml_summary is None else ml_summary.duration_seconds,
    )


AttemptRunner = Callable[[AttemptPlan, Path, str], AttemptOutcome]
RETRIABLE_FAILURES = frozenset(
    {
        "topology_failed",
        "tunnel_establishment_failed",
        "ipsec_evidence_failed",
        "traffic_prepare_failed",
        "traffic_generator_failed",
        "traffic_validation_failed",
        "capture_failed",
        "zero_or_insufficient_esp",
        "pcap_derivation_failed",
        "artifact_publication_failed",
        "cleanup_failed",
        "interrupted",
        "metadata_collection_failed",
        "unexpected_error",
    }
)


def is_retriable(failure_class: str | None) -> bool:
    return failure_class in RETRIABLE_FAILURES


def generate_dataset(
    config_path: Path,
    dataset_parent: Path = Path("dataset"),
    *,
    resume: bool = False,
    attempt_runner: AttemptRunner = run_dataset_attempt,
) -> DatasetSummary:
    register_builtin_generators()
    config = DatasetConfig.load(config_path)
    versions = generator_versions(config.traffic_classes)
    fingerprint = matrix_fingerprint(config, versions)
    dataset_root = dataset_parent / config.name
    manifest_path = dataset_root / "manifest.sqlite3"
    if manifest_path.is_file():
        manifest = Manifest(manifest_path)
        if not resume:
            manifest.close()
            raise FileExistsError(f"dataset already initialized: {dataset_root}")
        manifest.assert_compatible(fingerprint)
        manifest.recover_running(utc_now())
    else:
        if dataset_root.exists() and any(dataset_root.iterdir()):
            raise FileExistsError(
                f"uninitialized nonempty dataset directory: {dataset_root}"
            )
        dataset_root.mkdir(parents=True, exist_ok=True)
        manifest = Manifest(manifest_path)
        write_text_atomic(
            dataset_root / "matrix.yaml", config_path.read_text(encoding="utf-8")
        )
        manifest.initialize(config, fingerprint, str(config_path), versions)

    try:
        for slot in manifest.slots_in_order():
            while True:
                latest = manifest.latest_attempt(slot.slot_id)
                if (
                    latest is not None
                    and latest.state in (RunState.FAILED, RunState.INCOMPLETE)
                    and not is_retriable(latest.failure_class)
                ):
                    break
                plan = manifest.next_attempt(slot.slot_id, config.retry_failed)
                if plan is None:
                    break
                manifest.mark_running(plan.attempt_id, utc_now())
                outcome = attempt_runner(plan, dataset_root, fingerprint)
                manifest.finish_attempt_from_outcome(outcome, utc_now())
                write_summary(
                    dataset_root / "dataset_summary.json", build_summary(manifest)
                )
                if (
                    outcome.state is RunState.INCOMPLETE
                    and outcome.failure_class == "interrupted"
                ):
                    raise KeyboardInterrupt()
                if outcome.state is RunState.PASS or not is_retriable(
                    outcome.failure_class
                ):
                    break
        summary = build_summary(manifest)
        write_summary(dataset_root / "dataset_summary.json", summary)
        return summary
    finally:
        manifest.close()
