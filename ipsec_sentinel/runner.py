from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from time import monotonic, sleep, time
import os
import shutil

from ipsec_sentinel.artifacts import (
    create_run_dir,
    publish_results,
    write_success_artifacts,
    write_text_atomic,
)
from ipsec_sentinel.capture import CaptureSession, validate_pcap
from ipsec_sentinel.command import run_checked
from ipsec_sentinel.evidence import evaluate_baseline, evaluate_pfs, parse_ping, parse_sa
from ipsec_sentinel.models import (
    ConfiguredPolicy,
    GroundTruth,
    ObservedState,
    StageRecord,
    Verification,
)
from ipsec_sentinel.scenario import Scenario
from ipsec_sentinel.strongswan import RekeyEvidence, StrongSwanPair
from ipsec_sentinel.topology import Topology


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
    topology = Topology(log)
    pair = StrongSwanPair(log)
    temporary_pcap = Path("/tmp") / f"ipsec-sentinel-{run_id}.pcap"
    capture_log = run_dir / "tcpdump.log"
    capture = CaptureSession(temporary_pcap, capture_log)
    context: dict[str, object] = {}

    def preflight() -> None:
        if os.geteuid() != 0:
            raise PermissionError("IPsec Sentinel must run as Linux root")
        for program in ("ip", "swanctl", "charon-systemd", "tcpdump", "ping"):
            if shutil.which(program) is None:
                raise RuntimeError(f"required program is missing: {program}")
        run_checked(["ip", "xfrm", "state"], 5, log)
        run_checked(["ip", "xfrm", "policy"], 5, log)
        if not Path("/proc/net/xfrm_stat").is_file():
            raise RuntimeError("kernel XFRM statistics are unavailable")
        if "rfc4106(gcm(aes))" not in Path("/proc/crypto").read_text(encoding="utf-8"):
            raise RuntimeError("kernel RFC 4106 AES-GCM support is unavailable")

    def reset() -> None:
        topology.reset()

    def scenario_load() -> None:
        path = _scenario_path(scenario)
        context["scenario_path"] = path
        context["scenario_yaml"] = path.read_text(encoding="utf-8")
        context["scenario"] = Scenario.load(path)

    def topology_setup_readback() -> None:
        topology.setup()
        checks = topology.verify()
        failures = [check.name for check in checks if not check.passed]
        if failures:
            raise RuntimeError(f"topology readback failed: {', '.join(failures)}")
        context["topology_checks"] = checks

    def daemon_start() -> None:
        pair.start(run_dir)

    def capture_start() -> None:
        context["capture_started_at"] = time()
        capture.start()

    def configuration_load() -> None:
        context["load"] = pair.load()

    def initiate() -> None:
        context["initiate"] = pair.initiate()

    def sa_wait() -> None:
        deadline = monotonic() + 10
        last: dict[str, str] = {}
        while monotonic() < deadline:
            last = pair.list_sas()
            if all(
                parse_sa(last[gateway]).ike_state == "ESTABLISHED"
                and parse_sa(last[gateway]).child_state == "INSTALLED"
                for gateway in ("gateway-a", "gateway-b")
            ):
                context["sas"] = last
                return
            sleep(0.1)
        context["sas"] = last
        raise TimeoutError("IKE and CHILD SAs did not become established")

    def xfrm_collection() -> None:
        evidence: dict[str, str] = {}
        for gateway, namespace in (("gateway-a", "ips-gwa"), ("gateway-b", "ips-gwb")):
            state = run_checked(
                ["ip", "netns", "exec", namespace, "ip", "xfrm", "state"],
                5,
                log,
            ).stdout
            policy = run_checked(
                ["ip", "netns", "exec", namespace, "ip", "xfrm", "policy"],
                5,
                log,
            ).stdout
            evidence[gateway] = f"STATE\n{state}POLICY\n{policy}"
        context["xfrm"] = evidence

    def icmp() -> None:
        loaded = context["scenario"]
        assert isinstance(loaded, Scenario)
        result = run_checked(
            [
                "ip", "netns", "exec", "ips-client", "ping",
                "-I", "10.10.0.2", "-c", str(loaded.traffic.count),
                "-W", "2", "10.20.0.2",
            ],
            15,
            log,
        )
        context["ping"] = result.stdout

    def pfs_rekey() -> None:
        rekey = pair.rekey()
        context["rekey"] = rekey
        context["pfs"] = evaluate_pfs(
            rekey.before_sas,
            rekey.after_sas,
            rekey.log_segment,
            attempted=rekey.attempted,
        )

    def capture_stop() -> None:
        capture.stop()
        context["capture_ended_at"] = time()
        finalized = run_dir / "encrypted.pcap"
        shutil.move(str(temporary_pcap), finalized)
        context["pcap"] = finalized

    def pcap_validation() -> None:
        context["capture"] = validate_pcap(
            context["pcap"],  # type: ignore[arg-type]
            peers=("192.0.2.1", "192.0.2.2"),
            started_at=context["capture_started_at"],  # type: ignore[arg-type]
            ended_at=context["capture_ended_at"],  # type: ignore[arg-type]
        )

    def verdict() -> None:
        verification = evaluate_baseline(
            context["sas"],  # type: ignore[arg-type]
            context["xfrm"],  # type: ignore[arg-type]
            context["ping"],  # type: ignore[arg-type]
            context["capture"],  # type: ignore[arg-type]
            run_id=run_id,
            pfs=context["pfs"],  # type: ignore[arg-type]
        )
        context["verification"] = verification
        if verification.status != "PASS":
            failed = [check.name for check in verification.checks if not check.passed]
            raise RuntimeError(f"evidence verdict failed: {', '.join(failed)}")
        loaded = context["scenario"]
        assert isinstance(loaded, Scenario)
        sa = parse_sa(context["sas"]["gateway-a"])  # type: ignore[index]
        context["ground_truth"] = GroundTruth(
            run_id=run_id,
            scenario_id=loaded.id,
            status="PASS",
            configured=ConfiguredPolicy(
                ike_version=loaded.ipsec.ike_version,
                mode=loaded.ipsec.mode,
                ike_proposal=loaded.ipsec.ike_proposal,
                esp_proposal=loaded.ipsec.esp_proposal,
                pfs=loaded.ipsec.pfs,
                ip_version=loaded.ipsec.ip_version,
                local_subnet=loaded.ipsec.local_subnet,
                remote_subnet=loaded.ipsec.remote_subnet,
                transit_subnet=loaded.ipsec.transit_subnet,
            ),
            observed=ObservedState(
                ike_version=2,
                ike_proposal=sa.ike_proposal,
                esp_proposal=f"{sa.esp_proposal}/NO_EXT_SEQ",
                pfs=context["pfs"],  # type: ignore[arg-type]
            ),
            traffic=parse_ping(context["ping"]),  # type: ignore[arg-type]
            capture=context["capture"],  # type: ignore[arg-type]
        )

    def artifacts() -> None:
        write_success_artifacts(
            run_dir,
            scenario_yaml=context["scenario_yaml"],  # type: ignore[arg-type]
            run_log=log.getvalue(),
            sas=context["sas"],  # type: ignore[arg-type]
            xfrm=context["xfrm"],  # type: ignore[arg-type]
            verification=context["verification"],  # type: ignore[arg-type]
            ground_truth=context["ground_truth"],  # type: ignore[arg-type]
        )
        _write_rekey_artifacts(run_dir, context.get("rekey"))
        _copy_strongswan_logs(run_dir, pair)

    def cleanup() -> None:
        capture.stop()
        _copy_strongswan_logs(run_dir, pair)
        pair.stop()
        if not keep_lab:
            topology.reset()

    actions = {
        "preflight": preflight,
        "reset": reset,
        "scenario_load": scenario_load,
        "topology_setup_readback": topology_setup_readback,
        "daemon_start": daemon_start,
        "capture_start": capture_start,
        "configuration_load": configuration_load,
        "initiate": initiate,
        "sa_wait": sa_wait,
        "xfrm_collection": xfrm_collection,
        "icmp": icmp,
        "pfs_rekey": pfs_rekey,
        "capture_stop": capture_stop,
        "pcap_validation": pcap_validation,
        "verdict": verdict,
        "artifacts": artifacts,
        "cleanup": cleanup,
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
        _publish_failure_artifacts(run_dir, log, context, verification, truth, temporary_pcap)
        failed_stage = next(
            (record.name for record in records if record.status != "PASS"),
            "unknown",
        )
        print(f"run directory: {run_dir}")
        print(f"first failed stage: {failed_stage}: {error}")
        return 130 if isinstance(error, KeyboardInterrupt) else 1

    existing = context["verification"]
    assert isinstance(existing, Verification)
    final_verification = replace(existing, stages=records)
    publish_results(run_dir, final_verification, context["ground_truth"])  # type: ignore[arg-type]
    write_text_atomic(run_dir / "run.log", log.getvalue())
    print(f"run directory: {run_dir}")
    print("status: PASS")
    return 0


def _scenario_path(scenario: str | Path) -> Path:
    if isinstance(scenario, Path):
        return scenario
    if scenario != "secure-baseline":
        raise ValueError(f"unsupported scenario: {scenario}")
    return Path("scenarios/secure-baseline.yaml")


def _publish_failure_artifacts(
    run_dir: Path,
    log: StringIO,
    context: dict[str, object],
    verification: Verification,
    truth: GroundTruth | None,
    temporary_pcap: Path,
) -> None:
    if "scenario_yaml" in context:
        write_text_atomic(run_dir / "scenario.yaml", context["scenario_yaml"])  # type: ignore[arg-type]
    write_text_atomic(run_dir / "run.log", log.getvalue())
    for key, prefix in (("sas", "swanctl"), ("xfrm", "xfrm")):
        values = context.get(key)
        if isinstance(values, dict):
            for gateway, value in values.items():
                write_text_atomic(run_dir / f"{prefix}-{gateway}.txt", str(value))
    if temporary_pcap.is_file() and not (run_dir / "encrypted.pcap").exists():
        shutil.move(str(temporary_pcap), run_dir / "encrypted.pcap")
    _write_rekey_artifacts(run_dir, context.get("rekey"))
    publish_results(run_dir, verification, truth)


def _write_rekey_artifacts(run_dir: Path, value: object) -> None:
    if not isinstance(value, RekeyEvidence):
        return
    write_text_atomic(run_dir / "pfs-rekey.log", value.log_segment)
    for gateway in ("gateway-a", "gateway-b"):
        write_text_atomic(
            run_dir / f"swanctl-before-rekey-{gateway}.txt",
            value.before_sas[gateway],
        )
        write_text_atomic(
            run_dir / f"swanctl-after-rekey-{gateway}.txt",
            value.after_sas[gateway],
        )


def _copy_strongswan_logs(run_dir: Path, pair: StrongSwanPair) -> None:
    for gateway, files in pair.files.items():
        if files.log.is_file():
            write_text_atomic(
                run_dir / f"strongswan-{gateway}.log",
                files.log.read_text(encoding="utf-8", errors="replace"),
            )
