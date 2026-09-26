from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from ipsec_sentinel.external.acquire import (
    AcquisitionError,
    AcquisitionReceipt,
    acquire_artifact,
    verify_download,
)
from ipsec_sentinel.external.config import ExternalConfig
from ipsec_sentinel.external.inspect import ArchiveSafetyError, InspectionReport, inspect_artifact
from ipsec_sentinel.external.registry import ExternalDatasetRegistry, SourceRecord
from ipsec_sentinel.external.storage import ExternalPaths


EXIT_CONFIG = 2
EXIT_ACQUISITION = 3
EXIT_CHECKSUM = 4
EXIT_INSPECTION = 5
EXIT_INCOMPATIBLE = 6
PHASE_ACQUISITION_ALLOWLIST = frozenset(
    {"usbvpn2022", "vpn_protocol_performance_2026", "mit_ll_vnat"}
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python3 -m ipsec_sentinel.external")
    parser.add_argument(
        "--registry", type=Path, default=Path("metadata/external-datasets.yaml")
    )
    parser.add_argument("--config", type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    registry = commands.add_parser("registry")
    registry_commands = registry.add_subparsers(dest="registry_command", required=True)
    registry_commands.add_parser("validate")
    acquire = commands.add_parser("acquire")
    acquire.add_argument("source_id")
    acquire.add_argument("--resume", action="store_true")
    inspect = commands.add_parser("inspect")
    inspect.add_argument("source_id")
    normalize = commands.add_parser("normalize")
    normalize.add_argument("source_id")
    selection = normalize.add_mutually_exclusive_group()
    selection.add_argument("--sample-sessions", type=int, default=10)
    selection.add_argument("--all-sessions", action="store_true")
    commands.add_parser("report")
    return parser


def _selected_artifact(source: SourceRecord):
    selected = tuple(artifact for artifact in source.artifacts if artifact.selected)
    if len(selected) != 1:
        raise ValueError(f"source {source.source_id} must have one selected artifact")
    return selected[0]


def _preamble(paths: ExternalPaths, source: SourceRecord | None) -> None:
    declared = None
    if source is not None:
        declared = sum(
            artifact.published_size_bytes or 0
            for artifact in source.artifacts
            if artifact.selected
        )
    print(
        json.dumps(
            {"external_root": str(paths.root), "declared_bytes": declared},
            sort_keys=True,
        )
    )


def _inspect_source(source: SourceRecord, paths: ExternalPaths) -> InspectionReport:
    artifact = _selected_artifact(source)
    path = paths.downloads / artifact.artifact_id / artifact.filename
    verified = verify_download(path, artifact)
    return inspect_artifact(source, verified, paths)


def _compatible_inspection_exists(source: SourceRecord, paths: ExternalPaths) -> bool:
    root = paths.inventories / source.source_id
    if not root.exists():
        return False
    for report_path in sorted(root.glob("*/inspection.json"), reverse=True):
        try:
            if json.loads(report_path.read_text(encoding="utf-8")).get("compatible") is True:
                return True
        except (OSError, json.JSONDecodeError):
            continue
    return False


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        registry = ExternalDatasetRegistry.load(args.registry)
        if args.command == "registry":
            print(
                json.dumps(
                    {
                        "schema_version": registry.schema_version,
                        "sources": len(registry.sources),
                    },
                    sort_keys=True,
                )
            )
            return 0

        config = ExternalConfig.load(args.config, os.environ)
        paths = ExternalPaths.create(config.external_data_root)
        source = None
        if hasattr(args, "source_id"):
            source = registry.source(args.source_id)
        _preamble(paths, source)

        if args.command == "acquire":
            if source is None or source.source_id not in PHASE_ACQUISITION_ALLOWLIST:
                raise ValueError("source is not allowlisted for acquisition")
            artifact = _selected_artifact(source)
            receipt: AcquisitionReceipt = acquire_artifact(
                artifact, paths, resume=args.resume
            )
            print(json.dumps(receipt.to_dict(), sort_keys=True))
            return 0
        if args.command == "inspect":
            if source is None or source.source_id not in PHASE_ACQUISITION_ALLOWLIST:
                raise ValueError("source is not allowlisted for inspection")
            report = _inspect_source(source, paths)
            print(json.dumps(report.to_dict(), sort_keys=True))
            return 0 if report.compatible else EXIT_INCOMPATIBLE
        if args.command == "normalize":
            if source is None or not _compatible_inspection_exists(source, paths):
                raise RuntimeError("source lacks a compatible inspection")
            # Source adapters are registered only after real schema inspection.
            raise RuntimeError("source adapter is not registered")
        raise RuntimeError("report generation is not implemented")
    except AcquisitionError as exc:
        print(json.dumps({"error": str(exc), "category": exc.category}))
        return EXIT_CHECKSUM if exc.category == "checksum" else EXIT_ACQUISITION
    except ArchiveSafetyError as exc:
        print(json.dumps({"error": str(exc), "category": "inspection"}))
        return EXIT_INSPECTION
    except KeyError as exc:
        print(json.dumps({"error": str(exc), "category": "configuration"}))
        return EXIT_CONFIG
    except ValueError as exc:
        print(json.dumps({"error": str(exc), "category": "configuration"}))
        return EXIT_CONFIG
    except (FileNotFoundError, OSError) as exc:
        print(json.dumps({"error": str(exc), "category": "inspection"}))
        return EXIT_INSPECTION
    except RuntimeError as exc:
        print(json.dumps({"error": str(exc), "category": "incompatible"}))
        return EXIT_INCOMPATIBLE
