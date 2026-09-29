from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
from uuid import uuid4

from ipsec_sentinel.artifacts import write_json_atomic, write_text_atomic
from ipsec_sentinel.dataset.manifest import AttemptPlan
from ipsec_sentinel.dataset.models import (
    DATASET_SCHEMA_VERSION,
    PCAP_DERIVATION_VERSION,
    SCENARIO_SCHEMA_VERSION,
    TRAFFIC_SCHEMA_VERSION,
    VERIFICATION_SCHEMA_VERSION,
    CleanupState,
    DatasetCaptureEvidence,
    DatasetGroundTruth,
    DatasetTrafficEvidence,
    DatasetValidation,
    DatasetVerification,
    ReproducibilityMetadata,
    RunState,
    WorkloadWindow,
)
from ipsec_sentinel.evidence import parse_sa
from ipsec_sentinel.models import Check, ConfiguredPolicy, ObservedState, StageRecord, Verification
from ipsec_sentinel.pcap import PcapSummary
from ipsec_sentinel.scenario import Scenario
from ipsec_sentinel.session import SecureSession
from ipsec_sentinel.traffic.base import (
    TrafficGenerator,
    TrafficRunResult,
    TrafficValidation,
)


REQUIRED_PASS_FILES = frozenset(
    {
        "full-evidence.pcap",
        "encrypted.pcap",
        "cleartext-audit-gateway-a.pcap",
        "cleartext-audit-gateway-b.pcap",
        "ground_truth.json",
        "verification.json",
        "traffic.json",
        "environment.json",
        "scenario.yaml",
        "run.log",
        "swanctl-gateway-a.txt",
        "swanctl-gateway-b.txt",
        "xfrm-gateway-a.txt",
        "xfrm-gateway-b.txt",
        "pfs-rekey.log",
    }
)


def write_raw_attempt_artifacts(
    run_dir: Path,
    session: SecureSession,
    traffic_metadata: dict[str, object],
    run_log: str,
) -> None:
    session.preserve_diagnostics()
    if session.scenario_yaml:
        write_text_atomic(run_dir / "scenario.yaml", session.scenario_yaml)
    for gateway, value in session.sas.items():
        write_text_atomic(run_dir / f"swanctl-{gateway}.txt", value)
    for gateway, value in session.xfrm.items():
        write_text_atomic(run_dir / f"xfrm-{gateway}.txt", value)
    write_json_atomic(run_dir / "traffic-partial.json", traffic_metadata)
    write_text_atomic(run_dir / "run.log", run_log)


def assert_pass_bundle(run_dir: Path) -> None:
    present = {path.name for path in run_dir.iterdir()}
    missing = REQUIRED_PASS_FILES - present
    if missing:
        raise RuntimeError(f"dataset artifact publication incomplete: {sorted(missing)}")
    truth = json.loads((run_dir / "ground_truth.json").read_text(encoding="utf-8"))
    if truth["status"] != "PASS" or truth["training_ready"] is not True:
        raise RuntimeError("PASS bundle has non-training-ready ground truth")


@dataclass(frozen=True)
class StagedTerminalJson:
    run_dir: Path
    temporary_paths: dict[str, Path]


def stage_terminal_json(
    run_dir: Path, payloads: dict[str, dict[str, object]]
) -> StagedTerminalJson:
    common = {"verification.json", "traffic.json", "environment.json"}
    allowed = common | {"ground_truth.json"}
    if not common.issubset(payloads) or not set(payloads).issubset(allowed):
        raise ValueError(f"terminal JSON set mismatch: {sorted(set(payloads) ^ allowed)}")
    temporary_paths: dict[str, Path] = {}
    try:
        for name, payload in payloads.items():
            path = run_dir / f".{name}.{uuid4().hex}.staged"
            with path.open("w", encoding="utf-8") as output:
                json.dump(payload, output, indent=2, sort_keys=True)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            temporary_paths[name] = path
    except BaseException:
        for path in temporary_paths.values():
            path.unlink(missing_ok=True)
        raise
    return StagedTerminalJson(run_dir, temporary_paths)


def publish_terminal_json(staged: StagedTerminalJson) -> None:
    for name, temporary in staged.temporary_paths.items():
        temporary.replace(staged.run_dir / name)
    (staged.run_dir / "traffic-partial.json").unlink(missing_ok=True)


def validate_terminal_payloads(
    run_dir: Path,
    payloads: dict[str, dict[str, object]],
    *,
    require_pass_bundle: bool,
) -> None:
    common = {"verification.json", "traffic.json", "environment.json"}
    if not common.issubset(payloads):
        raise RuntimeError("required terminal payload is missing")
    if require_pass_bundle:
        if "ground_truth.json" not in payloads:
            raise RuntimeError("PASS payload lacks ground truth")
        truth = payloads["ground_truth.json"]
        if truth.get("status") != "PASS" or truth.get("training_ready") is not True:
            raise RuntimeError("PASS payload is not training-ready")
        raw_required = REQUIRED_PASS_FILES - common - {"ground_truth.json"}
        missing = raw_required - {path.name for path in run_dir.iterdir()}
        if missing:
            raise RuntimeError(f"dataset artifact publication incomplete: {sorted(missing)}")


def build_terminal_payloads(
    *,
    plan: AttemptPlan,
    state: RunState,
    training_ready: bool,
    cleanup_state: CleanupState,
    stages: tuple[StageRecord, ...],
    cleanup_actions: tuple[dict[str, object], ...],
    generator: TrafficGenerator,
    scenario: Scenario | None,
    session: SecureSession,
    traffic_result: TrafficRunResult | None,
    traffic_validation: TrafficValidation | None,
    ipsec_verification: Verification | None,
    workload_window: WorkloadWindow | None,
    ml_summary: PcapSummary | None,
    reproducibility: ReproducibilityMetadata,
    network_metadata: dict[str, object] | None,
    traffic_verified: bool,
    ipsec_verified: bool,
    capture_verified: bool,
    failure_class: str | None,
    primary_error: BaseException | None,
) -> dict[str, dict[str, object]]:
    del failure_class, primary_error
    checks = list(ipsec_verification.checks) if ipsec_verification else []
    traffic_errors = () if traffic_validation is None else traffic_validation.errors
    checks.extend(
        (
            Check(
                f"traffic.{plan.traffic_class}.verified",
                traffic_verified,
                traffic_errors or (f"verified={traffic_verified}",),
            ),
            Check(
                "capture.ml_workload_esp",
                capture_verified,
                (f"packets={0 if ml_summary is None else ml_summary.packet_count}",),
            ),
            Check(
                "cleanup.complete",
                cleanup_state is CleanupState.PASS,
                tuple(f"{item['name']}={item['status']}" for item in cleanup_actions),
            ),
            Check(
                "metadata.complete",
                not reproducibility.collection_errors,
                reproducibility.collection_errors
                or ("all required fields recorded",),
            ),
        )
    )
    verification = DatasetVerification(
        VERIFICATION_SCHEMA_VERSION,
        plan.attempt_id,
        state,
        stages,
        tuple(checks),
        cleanup_actions,
    )
    metadata = generator.metadata()
    traffic_payload = {
        "schema_version": TRAFFIC_SCHEMA_VERSION,
        **metadata,
        "class": plan.traffic_class,
        "known_training_class": plan.known_training_class,
        "class_role": plan.class_role,
        "generator_version": plan.generator_version,
        "seed": plan.seed,
        "validation": None if traffic_validation is None else asdict(traffic_validation),
    }
    payloads: dict[str, dict[str, object]] = {
        "verification.json": verification.to_dict(),
        "traffic.json": traffic_payload,
        "environment.json": asdict(reproducibility),
    }
    full = session.capture_evidence
    if (
        scenario is not None
        and workload_window is not None
        and ml_summary is not None
        and network_metadata is not None
        and full is not None
        and session.sas
    ):
        sa = parse_sa(session.sas["gateway-a"])
        truth = DatasetGroundTruth(
            schema_version=DATASET_SCHEMA_VERSION,
            run_id=plan.attempt_id,
            slot_id=plan.slot_id,
            attempt_number=plan.attempt_number,
            status=state,
            training_ready=training_ready,
            traffic=DatasetTrafficEvidence(
                plan.traffic_class,
                plan.known_training_class,
                plan.class_role,
                str(metadata["generator"]),
                plan.generator_version,
                plan.seed,
                dict(metadata["parameters"]),
                {} if traffic_result is None else dict(traffic_result.metrics),
            ),
            scenario_id=scenario.id,
            scenario_schema_version=SCENARIO_SCHEMA_VERSION,
            configured=ConfiguredPolicy(
                scenario.ipsec.ike_version,
                scenario.ipsec.mode,
                scenario.ipsec.ike_proposal,
                scenario.ipsec.esp_proposal,
                scenario.ipsec.pfs,
                scenario.ipsec.ip_version,
                scenario.ipsec.local_subnet,
                scenario.ipsec.remote_subnet,
                scenario.ipsec.transit_subnet,
            ),
            observed=ObservedState(
                2, sa.ike_proposal, f"{sa.esp_proposal}/NO_EXT_SEQ", session.pfs
            ),
            network=network_metadata,
            capture=DatasetCaptureEvidence(
                "full-evidence.pcap",
                "encrypted.pcap",
                workload_window.started_unix_ns,
                workload_window.finished_unix_ns,
                full.packet_count,
                full.ike_packets,
                full.esp_packets,
                ml_summary.packet_count,
                ml_summary.capture_bytes,
                ml_summary.duration_seconds,
                PCAP_DERIVATION_VERSION,
            ),
            validation=DatasetValidation(
                traffic_verified,
                ipsec_verified,
                capture_verified,
                cleanup_state is CleanupState.PASS,
            ),
            cleanup_status=cleanup_state,
            reproducibility=reproducibility,
        )
        payloads["ground_truth.json"] = truth.to_dict()
    return payloads
