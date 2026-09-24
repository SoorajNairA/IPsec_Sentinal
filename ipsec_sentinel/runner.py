from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

from ipsec_sentinel.artifacts import (
    create_run_dir,
    publish_results,
    write_success_artifacts,
    write_text_atomic,
)
from ipsec_sentinel.command import run_checked
from ipsec_sentinel.evidence import evaluate_baseline, parse_ping, parse_sa
from ipsec_sentinel.models import (
    ConfiguredPolicy,
    GroundTruth,
    ObservedState,
    StageRecord,
    Verification,
)
from ipsec_sentinel.scenario import Scenario
from ipsec_sentinel.session import SecureSession, run_cleanup_steps


ORDERED_STAGES = (
    "preflight",
    "reset",
    "scenario_load",
    "topology_setup_readback",
    "daemon_start",
    "capture_start",
    "configuration_load",
    "initiate",
    "sa_wait",
    "xfrm_collection",
    "icmp",
    "pfs_rekey",
    "capture_stop",
    "pcap_validation",
    "verdict",
    "artifacts",
    "cleanup",
)


def execute_ordered_stages(
    actions: Mapping[str, Callable[[], None]],
) -> tuple[StageRecord, ...]:
    missing = set(ORDERED_STAGES) - set(actions)
    if missing:
        raise ValueError(f"missing stage actions: {sorted(missing)}")
    records: list[StageRecord] = []
    primary: BaseException | None = None
    for stage in ORDERED_STAGES[:-1]:
        try:
            actions[stage]()
        except BaseException as error:
            status = "INTERRUPTED" if isinstance(error, KeyboardInterrupt) else "FAIL"
            records.append(StageRecord(stage, status, str(error) or type(error).__name__))
            primary = error
            break
        records.append(StageRecord(stage, "PASS", "completed"))

    try:
        actions["cleanup"]()
    except BaseException as cleanup_error:
        records.append(StageRecord("cleanup", "FAIL", str(cleanup_error)))
        if primary is None:
            primary = cleanup_error
    else:
        records.append(StageRecord("cleanup", "PASS", "completed"))

    if primary is not None:
        primary.stage_records = tuple(records)  # type: ignore[attr-defined]
        raise primary
    return tuple(records)


def run_secure_baseline(
    scenario: str | Path,
    keep_lab: bool = False,
    *,
    runs_root: Path = Path("runs"),
) -> int:
    run_dir = create_run_dir(runs_root, datetime.now(timezone.utc))
    run_id = run_dir.name
    log = StringIO()
    session = SecureSession(
        run_dir, log, primary_capture_name="encrypted.pcap", keep_lab=keep_lab
    )
    context: dict[str, object] = {}

    def scenario_load() -> None:
        context["scenario"] = session.load_scenario(scenario)
        context["scenario_yaml"] = session.scenario_yaml

    def icmp() -> None:
        loaded = context["scenario"]
        assert isinstance(loaded, Scenario)
        result = run_checked(
            [
                "ip", "netns", "exec", "ips-client", "ping", "-I", "10.10.0.2",
                "-c", str(loaded.traffic.count), "-W", "2", "10.20.0.2",
            ],
            15,
            log,
        )
        context["ping"] = result.stdout

    def verdict() -> None:
        verification = evaluate_baseline(
            session.sas,
            session.xfrm,
            context["ping"],  # type: ignore[arg-type]
            session.capture_evidence,  # type: ignore[arg-type]
            run_id=run_id,
            pfs=session.pfs,
        )
        context["verification"] = verification
        if verification.status != "PASS":
            failed = [check.name for check in verification.checks if not check.passed]
            raise RuntimeError(f"evidence verdict failed: {', '.join(failed)}")
        loaded = session.scenario
        assert loaded is not None
        sa = parse_sa(session.sas["gateway-a"])
        context["ground_truth"] = GroundTruth(
            run_id=run_id,
            scenario_id=loaded.id,
            status="PASS",
            configured=ConfiguredPolicy(
                loaded.ipsec.ike_version,
                loaded.ipsec.mode,
                loaded.ipsec.ike_proposal,
                loaded.ipsec.esp_proposal,
                loaded.ipsec.pfs,
                loaded.ipsec.ip_version,
                loaded.ipsec.local_subnet,
                loaded.ipsec.remote_subnet,
                loaded.ipsec.transit_subnet,
            ),
            observed=ObservedState(
                2,
                sa.ike_proposal,
                f"{sa.esp_proposal}/NO_EXT_SEQ",
                session.pfs,
            ),
            traffic=parse_ping(context["ping"]),  # type: ignore[arg-type]
            capture=session.capture_evidence,  # type: ignore[arg-type]
        )

    def artifacts() -> None:
        write_success_artifacts(
            run_dir,
            scenario_yaml=session.scenario_yaml,
            run_log=log.getvalue(),
            sas=session.sas,
            xfrm=session.xfrm,
            verification=context["verification"],  # type: ignore[arg-type]
            ground_truth=context["ground_truth"],  # type: ignore[arg-type]
        )
        session.preserve_diagnostics()

    actions = {
        "preflight": session.preflight,
        "reset": session.reset,
        "scenario_load": scenario_load,
        "topology_setup_readback": session.setup_topology,
        "daemon_start": session.start_daemons,
        "capture_start": session.start_captures,
        "configuration_load": lambda: context.update(load=session.load_configuration()),
        "initiate": lambda: context.update(initiate=session.initiate()),
        "sa_wait": lambda: context.update(sas=session.wait_for_sa()),
        "xfrm_collection": lambda: context.update(xfrm=session.collect_xfrm()),
        "icmp": icmp,
        "pfs_rekey": lambda: context.update(pfs=session.rekey()),
        "capture_stop": session.stop_captures,
        "pcap_validation": lambda: context.update(capture=session.validate_captures()),
        "verdict": verdict,
        "artifacts": artifacts,
        "cleanup": session.cleanup,
    }

    try:
        records = execute_ordered_stages(actions)
    except BaseException as error:
        records = getattr(error, "stage_records", ())
        existing = context.get("verification")
        checks = existing.checks if isinstance(existing, Verification) else ()
        status = "INTERRUPTED" if isinstance(error, KeyboardInterrupt) else "FAIL"
        verification = Verification(run_id, status, tuple(records), tuple(checks))
        truth = context.get("ground_truth")
        if isinstance(truth, GroundTruth):
            truth = replace(truth, status=status)
        else:
            truth = None
        _publish_failure_artifacts(run_dir, log, session, verification, truth)
        failed_stage = next(
            (record.name for record in records if record.status != "PASS"), "unknown"
        )
        print(f"run directory: {run_dir}")
        print(f"first failed stage: {failed_stage}: {error}")
        return 130 if isinstance(error, KeyboardInterrupt) else 1

    existing = context["verification"]
    assert isinstance(existing, Verification)
    final_verification = replace(existing, stages=records)
    publish_results(
        run_dir, final_verification, context["ground_truth"]  # type: ignore[arg-type]
    )
    write_text_atomic(run_dir / "run.log", log.getvalue())
    print(f"run directory: {run_dir}")
    print("status: PASS")
    return 0


def _publish_failure_artifacts(
    run_dir: Path,
    log: StringIO,
    session: SecureSession,
    verification: Verification,
    truth: GroundTruth | None,
) -> None:
    if session.scenario_yaml:
        write_text_atomic(run_dir / "scenario.yaml", session.scenario_yaml)
    write_text_atomic(run_dir / "run.log", log.getvalue())
    for values, prefix in ((session.sas, "swanctl"), (session.xfrm, "xfrm")):
        for gateway, value in values.items():
            write_text_atomic(run_dir / f"{prefix}-{gateway}.txt", value)
    session.preserve_diagnostics()
    publish_results(run_dir, verification, truth)
