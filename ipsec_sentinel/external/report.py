from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from ipsec_sentinel.external.registry import ExternalDatasetRegistry
from ipsec_sentinel.external.storage import ExternalPaths


REPORT_SCHEMA_VERSION = "ipsec-sentinel.external-report/v1"


def _read_json(path: Path) -> dict[str, object] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _latest_inventory(paths: ExternalPaths, source_id: str) -> dict[str, object] | None:
    candidates = sorted((paths.inventories / source_id).glob("*/inspection.json"))
    raw = _read_json(candidates[-1]) if candidates else None
    if raw is None:
        return None
    allowed = (
        "schema_version", "source_id", "artifact_sha256", "format",
        "compatible", "compatibility_reasons", "member_count", "warnings",
    )
    return {key: raw[key] for key in allowed if key in raw}


def _disk_usage(root: Path) -> int:
    return sum(path.stat().st_size for path in root.rglob("*") if path.is_file())


@dataclass(frozen=True)
class ExternalDatasetReport:
    payload: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return self.payload

    def to_markdown(self) -> str:
        lines = ["# External Dataset Compatibility Report", ""]
        for source in self.payload["sources"]:  # type: ignore[union-attr]
            lines.extend(
                (
                    f"## {source['display_name']}",
                    "",
                    f"- Source ID: `{source['source_id']}`",
                    f"- Acquisition: `{source['acquisition_state']}`",
                    f"- Inspection: `{source['inspection_state']}`",
                    f"- Adapter: `{source['adapter_id'] or 'none'}`",
                    f"- Protocols: {', '.join(source['observed_protocols']) or 'unknown'}",
                    "",
                )
            )
        lines.extend((
            "## Data-selection boundary",
            "",
            "Public datasets are external-evaluation evidence only and are not mixed into native supervised training.",
            "",
        ))
        return "\n".join(lines)


def build_external_report(
    registry: ExternalDatasetRegistry, paths: ExternalPaths
) -> ExternalDatasetReport:
    sources: list[dict[str, object]] = []
    for source in registry.sources:
        artifacts = []
        for artifact in source.artifacts:
            receipt = _read_json(
                paths.downloads / artifact.artifact_id / f"{artifact.filename}.receipt.json"
            )
            artifacts.append(
                {
                    "artifact_id": artifact.artifact_id,
                    "filename": artifact.filename,
                    "selected": artifact.selected,
                    "published_size_bytes": artifact.published_size_bytes,
                    "local_sha256": artifact.local_verification.sha256,
                    "receipt": receipt,
                }
            )
        sources.append(
            {
                "source_id": source.source_id,
                "display_name": source.display_name,
                "doi": source.doi,
                "landing_url": source.landing_url,
                "acquisition_state": source.acquisition_state.value,
                "inspection_state": source.inspection.state.value,
                "declared_formats": list(source.declared_formats),
                "observed_formats": list(source.inspection.observed_formats),
                "declared_protocols": list(source.declared_protocols),
                "observed_protocols": list(source.inspection.observed_protocols),
                "declared_labels": list(source.declared_labels),
                "observed_labels": list(source.inspection.observed_labels),
                "label_mappings": dict(source.label_mappings),
                "adapter_id": source.inspection.adapter_id,
                "inspection_notes": list(source.inspection.notes),
                "intended_use": source.intended_use,
                "license": {
                    "name": source.license.name,
                    "evidence_url": source.license.evidence_url,
                    "redistribution_status": source.license.redistribution_status.value,
                },
                "artifacts": artifacts,
                "inventory": _latest_inventory(paths, source.source_id),
            }
        )
    return ExternalDatasetReport(
        {
            "schema_version": REPORT_SCHEMA_VERSION,
            "disk_usage_bytes": _disk_usage(paths.root),
            "sources": sources,
            "intentionally_omitted": [
                {
                    "source_id": "mit_ll_vnat",
                    "artifact": "VNAT raw PCAP archive",
                    "reason": "36.1 GB raw archive is outside the allowlisted phase scope",
                },
                {
                    "source_id": "iscxvpn2016",
                    "artifact": "ISCXVPN2016 full collection",
                    "reason": "approximately 28 GB and access/redistribution terms remain gated",
                },
            ],
            "training_policy": "external evaluation only; never mixed into native supervised training",
        }
    )


def write_external_report(
    report: ExternalDatasetReport, paths: ExternalPaths
) -> dict[str, Path]:
    json_path = paths.reports / "external-datasets.json"
    markdown_path = paths.reports / "external-datasets.md"
    json_path.write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    markdown_path.write_text(report.to_markdown(), encoding="utf-8")
    return {"json": json_path, "markdown": markdown_path}
