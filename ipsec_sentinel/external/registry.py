from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
import re
from typing import Any

import yaml


REGISTRY_SCHEMA_VERSION = "ipsec-sentinel.external-registry/v1"
SUPERVISED_LABELS = frozenset(
    {"icmp", "web", "video", "voip", "email", "messaging", "file_transfer"}
)


class AcquisitionState(StrEnum):
    NOT_DOWNLOADED = "not_downloaded"
    VERIFIED = "verified"
    METADATA_ONLY = "metadata_only"


class InspectionState(StrEnum):
    UNINSPECTED = "uninspected"
    INSPECTED = "inspected"
    COMPATIBLE = "compatible"
    INCOMPATIBLE = "incompatible"
    CATALOG_ONLY = "catalog_only"


class RedistributionStatus(StrEnum):
    ALLOWED = "allowed"
    RESTRICTED = "restricted"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ChecksumRecord:
    algorithm: str
    value: str


@dataclass(frozen=True)
class LocalVerification:
    actual_size_bytes: int | None
    sha256: str | None
    verified_at: str | None
    result: str


@dataclass(frozen=True)
class ArtifactRecord:
    artifact_id: str
    filename: str
    download_url: str
    selected: bool
    published_size_bytes: int | None
    publisher_checksum: ChecksumRecord | None
    local_verification: LocalVerification


@dataclass(frozen=True)
class LicenseRecord:
    name: str
    evidence_url: str
    retrieved_at: str
    redistribution_status: RedistributionStatus


@dataclass(frozen=True)
class InspectionRecord:
    state: InspectionState
    inspected_at: str | None
    artifact_sha256: str | None
    observed_formats: tuple[str, ...]
    observed_protocols: tuple[str, ...]
    observed_labels: tuple[str, ...]
    adapter_id: str | None
    notes: tuple[str, ...]


@dataclass(frozen=True)
class SourceRecord:
    source_id: str
    display_name: str
    version: str
    doi: str | None
    landing_url: str
    citation: str
    publisher: str
    published_at: str
    license: LicenseRecord
    declared_protocols: tuple[str, ...]
    declared_formats: tuple[str, ...]
    declared_labels: tuple[str, ...]
    intended_use: str
    acquisition_state: AcquisitionState
    inspection: InspectionRecord
    artifacts: tuple[ArtifactRecord, ...]
    label_mappings: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class ExternalDatasetRegistry:
    schema_version: str
    sources: tuple[SourceRecord, ...]

    @classmethod
    def load(cls, path: Path) -> "ExternalDatasetRegistry":
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        root = _mapping(raw, {"schema_version", "sources"}, "registry")
        if root["schema_version"] != REGISTRY_SCHEMA_VERSION:
            raise ValueError("unsupported external registry schema")
        sources = tuple(_source(value) for value in _list(root["sources"], "sources"))
        _unique((source.source_id for source in sources), "source id")
        artifact_ids = [
            artifact.artifact_id for source in sources for artifact in source.artifacts
        ]
        _unique(artifact_ids, "artifact id")
        return cls(REGISTRY_SCHEMA_VERSION, sources)

    def source(self, source_id: str) -> SourceRecord:
        for source in self.sources:
            if source.source_id == source_id:
                return source
        raise KeyError(f"unknown external dataset source: {source_id}")


def _mapping(value: Any, keys: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{context} must be a mapping")
    actual = set(value)
    if actual != keys:
        raise ValueError(
            f"{context} fields mismatch: missing={sorted(keys - actual)}, "
            f"unknown={sorted(actual - keys)}"
        )
    return value


def _list(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{context} must be a list")
    return value


def _text(value: Any, context: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise ValueError(f"{context} must be a non-empty string")
    return value


def _optional_text(value: Any, context: str) -> str | None:
    return None if value is None else _text(value, context)


def _strings(value: Any, context: str) -> tuple[str, ...]:
    result = tuple(_text(item, context) for item in _list(value, context))
    _unique(result, context)
    return result


def _unique(values: Any, context: str) -> None:
    seen: set[str] = set()
    for value in values:
        if value in seen:
            raise ValueError(f"duplicate {context}: {value}")
        seen.add(value)


def _url(value: Any, context: str) -> str:
    result = _text(value, context)
    if not result.startswith("https://"):
        raise ValueError(f"{context} must be an HTTPS URL")
    return result


def _checksum(value: Any, context: str) -> ChecksumRecord | None:
    if value is None:
        return None
    raw = _mapping(value, {"algorithm", "value"}, context)
    algorithm = _text(raw["algorithm"], f"{context}.algorithm").lower()
    lengths = {"md5": 32, "sha256": 64}
    digest = _text(raw["value"], f"{context}.value").lower()
    if algorithm not in lengths or not re.fullmatch(
        rf"[0-9a-f]{{{lengths.get(algorithm, 0)}}}", digest
    ):
        raise ValueError(f"invalid {context}")
    return ChecksumRecord(algorithm, digest)


def _artifact(value: Any, context: str) -> ArtifactRecord:
    raw = _mapping(
        value,
        {
            "artifact_id",
            "filename",
            "download_url",
            "selected",
            "published_size_bytes",
            "publisher_checksum",
            "local_verification",
        },
        context,
    )
    size = raw["published_size_bytes"]
    if size is not None and (not isinstance(size, int) or isinstance(size, bool) or size <= 0):
        raise ValueError(f"{context}.published_size_bytes must be positive")
    if not isinstance(raw["selected"], bool):
        raise ValueError(f"{context}.selected must be boolean")
    local = _mapping(
        raw["local_verification"],
        {"actual_size_bytes", "sha256", "verified_at", "result"},
        f"{context}.local_verification",
    )
    actual_size = local["actual_size_bytes"]
    if actual_size is not None and (
        not isinstance(actual_size, int) or isinstance(actual_size, bool) or actual_size <= 0
    ):
        raise ValueError(f"{context}.local_verification.actual_size_bytes is invalid")
    sha256 = _optional_text(local["sha256"], f"{context}.local_verification.sha256")
    if sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", sha256):
        raise ValueError(f"{context}.local_verification.sha256 is invalid")
    return ArtifactRecord(
        _text(raw["artifact_id"], f"{context}.artifact_id"),
        _text(raw["filename"], f"{context}.filename"),
        _url(raw["download_url"], f"{context}.download_url"),
        raw["selected"],
        size,
        _checksum(raw["publisher_checksum"], f"{context}.publisher_checksum"),
        LocalVerification(
            actual_size,
            sha256,
            _optional_text(local["verified_at"], f"{context}.verified_at"),
            _text(local["result"], f"{context}.result"),
        ),
    )


def _source(value: Any) -> SourceRecord:
    keys = {
        "source_id",
        "display_name",
        "version",
        "doi",
        "landing_url",
        "citation",
        "publisher",
        "published_at",
        "license",
        "declared_protocols",
        "declared_formats",
        "declared_labels",
        "intended_use",
        "acquisition_state",
        "inspection",
        "artifacts",
        "label_mappings",
    }
    raw = _mapping(value, keys, "source")
    source_id = _text(raw["source_id"], "source.source_id")
    license_raw = _mapping(
        raw["license"],
        {"name", "evidence_url", "retrieved_at", "redistribution_status"},
        f"source {source_id}.license",
    )
    inspection_raw = _mapping(
        raw["inspection"],
        {
            "state",
            "inspected_at",
            "artifact_sha256",
            "observed_formats",
            "observed_protocols",
            "observed_labels",
            "adapter_id",
            "notes",
        },
        f"source {source_id}.inspection",
    )
    mapping_raw = raw["label_mappings"]
    if not isinstance(mapping_raw, dict):
        raise ValueError(f"source {source_id}.label_mappings must be a mapping")
    mappings = tuple(
        (_text(original, "original label"), _text(canonical, "canonical label"))
        for original, canonical in mapping_raw.items()
    )
    if any(canonical not in SUPERVISED_LABELS for _, canonical in mappings):
        raise ValueError(f"source {source_id} has unsupported canonical label")
    return SourceRecord(
        source_id,
        _text(raw["display_name"], f"source {source_id}.display_name"),
        _text(raw["version"], f"source {source_id}.version"),
        _optional_text(raw["doi"], f"source {source_id}.doi"),
        _url(raw["landing_url"], f"source {source_id}.landing_url"),
        _text(raw["citation"], f"source {source_id}.citation"),
        _text(raw["publisher"], f"source {source_id}.publisher"),
        _text(raw["published_at"], f"source {source_id}.published_at"),
        LicenseRecord(
            _text(license_raw["name"], f"source {source_id}.license.name"),
            _url(license_raw["evidence_url"], f"source {source_id}.license.evidence_url"),
            _text(license_raw["retrieved_at"], f"source {source_id}.license.retrieved_at"),
            RedistributionStatus(license_raw["redistribution_status"]),
        ),
        _strings(raw["declared_protocols"], f"source {source_id}.declared_protocols"),
        _strings(raw["declared_formats"], f"source {source_id}.declared_formats"),
        _strings(raw["declared_labels"], f"source {source_id}.declared_labels"),
        _text(raw["intended_use"], f"source {source_id}.intended_use"),
        AcquisitionState(raw["acquisition_state"]),
        InspectionRecord(
            InspectionState(inspection_raw["state"]),
            _optional_text(inspection_raw["inspected_at"], "inspection.inspected_at"),
            _optional_text(inspection_raw["artifact_sha256"], "inspection.artifact_sha256"),
            _strings(inspection_raw["observed_formats"], "inspection.observed_formats"),
            _strings(inspection_raw["observed_protocols"], "inspection.observed_protocols"),
            _strings(inspection_raw["observed_labels"], "inspection.observed_labels"),
            _optional_text(inspection_raw["adapter_id"], "inspection.adapter_id"),
            _strings(inspection_raw["notes"], "inspection.notes"),
        ),
        tuple(
            _artifact(item, f"source {source_id}.artifacts[{index}]")
            for index, item in enumerate(_list(raw["artifacts"], "artifacts"))
        ),
        mappings,
    )

