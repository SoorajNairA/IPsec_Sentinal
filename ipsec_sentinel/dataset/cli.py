from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path
import secrets

from ipsec_sentinel.artifacts import write_text_atomic
from ipsec_sentinel.dataset.runner import generate_dataset
from ipsec_sentinel.dataset.summary import DatasetSummary, render_summary
from ipsec_sentinel.dataset.validation import (
    DatasetValidationReport,
    validate_dataset,
)
from ipsec_sentinel.traffic import register_builtin_generators
from ipsec_sentinel.traffic.base import traffic_classes


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python3 -m ipsec_sentinel.dataset")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("list-traffic")
    run = subparsers.add_parser("run")
    run.add_argument("--traffic", required=True, choices=("icmp", "web", "video"))
    run.add_argument(
        "--scenario", default="secure-baseline", choices=("secure-baseline",)
    )
    run.add_argument("--seed", type=int)
    run.add_argument("--output", type=Path, default=Path("dataset/ad-hoc"))
    generate = subparsers.add_parser("generate")
    generate.add_argument("config", type=Path)
    generate.add_argument("--resume", action="store_true")
    validate = subparsers.add_parser("validate")
    validate.add_argument("dataset_root", type=Path)
    return parser


def _render_validation(report: DatasetValidationReport) -> str:
    lines = [
        f"Validation: {'PASS' if report.passed else 'FAIL'}",
        f"Valid runs: {report.valid_runs}",
        f"Failed attempts: {report.failed_runs}",
        f"Incomplete attempts: {report.incomplete_runs}",
    ]
    lines.extend(f"ERROR: {error}" for error in report.errors)
    return "\n".join(lines)


def _run_one(traffic: str, scenario: str, seed: int, output: Path) -> DatasetSummary:
    if output.exists():
        raise FileExistsError(f"output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    matrix_path = output.parent / f".{output.name}-matrix.yaml"
    matrix = f"""dataset:
  name: {output.name}
  schema_version: ipsec-sentinel.dataset-ground-truth/v1
  seed: {seed}
traffic:
  classes: [{traffic}]
ipsec:
  scenarios: [{scenario}]
network_profiles: [clean]
runs_per_combination: 1
execution:
  workers: 1
  retry_failed: 0
"""
    write_text_atomic(matrix_path, matrix)
    try:
        return generate_dataset(matrix_path, output.parent)
    finally:
        matrix_path.unlink(missing_ok=True)


def main(
    argv: list[str] | None = None,
    *,
    generate: Callable[[Path, bool], DatasetSummary] | None = None,
    validate: Callable[[Path], DatasetValidationReport] = validate_dataset,
) -> int:
    args = build_parser().parse_args(argv)
    register_builtin_generators()
    try:
        if args.command == "list-traffic":
            print(*traffic_classes(), sep="\n")
            return 0
        if args.command == "run":
            seed = args.seed if args.seed is not None else secrets.randbits(63)
            summary = _run_one(args.traffic, args.scenario, seed, args.output)
            print(render_summary(summary))
            return 0 if summary.successful_runs == summary.planned_runs else 1
        if args.command == "generate":
            orchestrator = generate or (
                lambda path, resume: generate_dataset(path, resume=resume)
            )
            summary = orchestrator(args.config, args.resume)
            print(render_summary(summary))
            return 0 if summary.successful_runs == summary.planned_runs else 1
        report = validate(args.dataset_root)
        print(_render_validation(report))
        return 0 if report.passed else 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
