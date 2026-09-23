from __future__ import annotations

from datetime import datetime
from pathlib import Path
from uuid import uuid4
import json
import os

from ipsec_sentinel.models import GroundTruth, Verification


REQUIRED_SUCCESS_FILES = frozenset(
    {
        "scenario.yaml",
        "run.log",
        "swanctl-gateway-a.txt",
        "swanctl-gateway-b.txt",
        "xfrm-gateway-a.txt",
        "xfrm-gateway-b.txt",
        "encrypted.pcap",
        "verification.json",
        "ground_truth.json",
    }
)


def create_run_dir(root: Path, now: datetime) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    stem = now.strftime("run_%Y%m%dT%H%M%SZ")
    for index in range(1000):
        suffix = "" if index == 0 else f"-{index:02d}"
        candidate = root / f"{stem}{suffix}"
        try:
            candidate.mkdir(mode=0o750)
        except FileExistsError:
            continue
        os.chmod(candidate, 0o750)
        return candidate
    raise RuntimeError(f"unable to allocate a unique run directory under {root}")


def write_text_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        temporary.write_text(content, encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def write_json_atomic(path: Path, payload: dict[str, object]) -> None:
    write_text_atomic(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def publish_results(
    run_dir: Path,
    verification: Verification,
    ground_truth: GroundTruth | None,
) -> None:
    if verification.status == "PASS" and not all(
        check.passed for check in verification.checks
    ):
        raise ValueError("cannot publish PASS with a failed check")
    if ground_truth is not None and ground_truth.status != verification.status:
        raise ValueError("verification and ground truth status disagree")
    write_json_atomic(run_dir / "verification.json", verification.to_dict())
    if ground_truth is not None:
        write_json_atomic(run_dir / "ground_truth.json", ground_truth.to_dict())


def write_success_artifacts(
    run_dir: Path,
    *,
    scenario_yaml: str,
    run_log: str,
    sas: dict[str, str],
    xfrm: dict[str, str],
    verification: Verification,
    ground_truth: GroundTruth,
) -> None:
    if not (run_dir / "encrypted.pcap").is_file():
        raise ValueError("encrypted.pcap must be finalized before artifact publication")
    write_text_atomic(run_dir / "scenario.yaml", scenario_yaml)
    write_text_atomic(run_dir / "run.log", run_log)
    for gateway in ("gateway-a", "gateway-b"):
        write_text_atomic(run_dir / f"swanctl-{gateway}.txt", sas[gateway])
        write_text_atomic(run_dir / f"xfrm-{gateway}.txt", xfrm[gateway])
    publish_results(run_dir, verification, ground_truth)
    missing = REQUIRED_SUCCESS_FILES - {path.name for path in run_dir.iterdir()}
    if missing:
        raise RuntimeError(f"artifact publication incomplete: {sorted(missing)}")
