from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import stat
from typing import Any
from uuid import uuid4
from zipfile import ZipFile, ZipInfo

import h5py
import numpy as np

from ipsec_sentinel.artifacts import write_json_atomic
from ipsec_sentinel.external.acquire import VerifiedArtifact
from ipsec_sentinel.external.registry import SourceRecord
from ipsec_sentinel.external.storage import ExternalPaths


INSPECTION_SCHEMA_VERSION = "ipsec-sentinel.external-inspection/v1"
DEFAULT_MAX_EXPANDED_BYTES = 50 * 1024 * 1024 * 1024
DEFAULT_MAX_MEMBERS = 250_000


class ArchiveSafetyError(ValueError):
    pass


@dataclass(frozen=True)
class ExtractionReceipt:
    destination: Path
    member_count: int
    expanded_bytes: int
    artifact_sha256: str


@dataclass(frozen=True)
class InspectionReport:
    schema_version: str
    source_id: str
    artifact_sha256: str
    format: str
    structure: tuple[dict[str, object], ...]
    semantic_findings: dict[str, str]
    compatibility_reasons: tuple[str, ...]
    compatible: bool
    warnings: tuple[str, ...]
    inventory_path: Path

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["inventory_path"] = str(self.inventory_path)
        result["member_count"] = len(self.structure)
        return result


def _safe_member_name(info: ZipInfo) -> str:
    raw = info.filename.replace("\\", "/")
    if raw.startswith("/") or re.match(r"^[A-Za-z]:", raw):
        raise ArchiveSafetyError(f"absolute archive member: {raw}")
    parts = PurePosixPath(raw).parts
    if ".." in parts:
        raise ArchiveSafetyError(f"parent traversal archive member: {raw}")
    normalized = posixpath.normpath(raw)
    if normalized in ("", "."):
        raise ArchiveSafetyError("empty archive member")
    mode = info.external_attr >> 16
    if stat.S_ISLNK(mode):
        raise ArchiveSafetyError(f"archive symlink is not allowed: {raw}")
    return normalized.rstrip("/")


def _zip_members(
    archive: Path, *, max_expanded_bytes: int, max_members: int
) -> list[tuple[ZipInfo, str]]:
    with ZipFile(archive) as source:
        infos = source.infolist()
        if len(infos) > max_members:
            raise ArchiveSafetyError("archive member limit exceeded")
        if sum(info.file_size for info in infos) > max_expanded_bytes:
            raise ArchiveSafetyError("archive expansion limit exceeded")
        members: list[tuple[ZipInfo, str]] = []
        seen: set[str] = set()
        for info in infos:
            normalized = _safe_member_name(info)
            if normalized in seen:
                raise ArchiveSafetyError(f"duplicate normalized member: {normalized}")
            seen.add(normalized)
            members.append((info, normalized))
        return members


def safe_extract_zip(
    artifact: VerifiedArtifact,
    destination: Path,
    *,
    max_expanded_bytes: int,
    max_members: int,
) -> ExtractionReceipt:
    members = _zip_members(
        artifact.path,
        max_expanded_bytes=max_expanded_bytes,
        max_members=max_members,
    )
    expanded = sum(info.file_size for info, _ in members)
    if destination.exists():
        return ExtractionReceipt(destination, len(members), expanded, artifact.local_sha256)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.parent / f".{destination.name}.{uuid4().hex}.tmp"
    try:
        temporary.mkdir()
        with ZipFile(artifact.path) as source:
            for info, normalized in members:
                target = temporary / normalized
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.open(info) as input_file, target.open("wb") as output:
                    shutil.copyfileobj(input_file, output, length=1024 * 1024)
                    output.flush()
                    os.fsync(output.fileno())
        temporary.replace(destination)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return ExtractionReceipt(destination, len(members), expanded, artifact.local_sha256)


def _json_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, np.void) and value.dtype.names:
        return {name: _json_value(value[name]) for name in value.dtype.names}
    if isinstance(value, np.generic):
        return _json_value(value.item())
    if isinstance(value, np.ndarray):
        return [_json_value(item) for item in value.tolist()]
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    return value


def _inspect_hdf5(path: Path) -> tuple[list[dict[str, object]], dict[str, str], list[str]]:
    structure: list[dict[str, object]] = []
    fields: set[str] = set()
    with h5py.File(path, "r") as source:
        def visit(name: str, item: h5py.Group | h5py.Dataset) -> None:
            record: dict[str, object] = {
                "path": f"/{name}" if name else "/",
                "kind": "dataset" if isinstance(item, h5py.Dataset) else "group",
                "attributes": {str(key): _json_value(value) for key, value in item.attrs.items()},
            }
            if isinstance(item, h5py.Dataset):
                names = list(item.dtype.names or ())
                fields.update(names)
                record.update(
                    dtype=str(item.dtype),
                    shape=list(item.shape),
                    fields=names,
                    sample=[_json_value(value) for value in item[: min(5, item.shape[0])]]
                    if item.shape else [_json_value(item[()])],
                )
            structure.append(record)
        source.visititems(visit)

    patterns = {
        "timestamp": ("timestamp", "time"),
        "size": ("packet_size", "packet_length", "size", "length"),
        "direction": ("direction", "dir"),
        "session": ("session_id", "flow_id", "connection_id", "session", "flow"),
        "label": ("label", "class", "category"),
    }
    findings: dict[str, str] = {}
    reasons: list[str] = []
    lowered = {field.casefold(): field for field in fields}
    for semantic, candidates in patterns.items():
        matches = {
            original
            for lower, original in lowered.items()
            if lower in candidates or any(token in lower for token in candidates)
        }
        findings[semantic] = "observed" if len(matches) == 1 else "unknown"
        if len(matches) != 1:
            reasons.append(
                f"ambiguous_{semantic}" if len(matches) > 1 else f"missing_{semantic}"
            )
    return structure, findings, reasons


def inspect_artifact(
    source: SourceRecord,
    artifact: VerifiedArtifact,
    paths: ExternalPaths,
) -> InspectionReport:
    suffix = artifact.path.suffix.casefold()
    warnings: list[str] = []
    if suffix == ".zip":
        format_name = "zip"
        destination = paths.extracted / source.source_id / artifact.local_sha256
        safe_extract_zip(
            artifact,
            destination,
            max_expanded_bytes=DEFAULT_MAX_EXPANDED_BYTES,
            max_members=DEFAULT_MAX_MEMBERS,
        )
        members = _zip_members(
            artifact.path,
            max_expanded_bytes=DEFAULT_MAX_EXPANDED_BYTES,
            max_members=DEFAULT_MAX_MEMBERS,
        )
        structure = [
            {
                "path": normalized,
                "size_bytes": info.file_size,
                "compressed_bytes": info.compress_size,
                "kind": "directory" if info.is_dir() else "file",
            }
            for info, normalized in members
        ]
        findings = {name: "unknown" for name in ("timestamp", "size", "direction", "session", "label")}
        reasons = [f"missing_{name}" for name in findings]
    elif suffix in (".h5", ".hdf5"):
        format_name = "hdf5"
        structure, findings, reasons = _inspect_hdf5(artifact.path)
    else:
        format_name = "unknown"
        structure = []
        findings = {name: "unknown" for name in ("timestamp", "size", "direction", "session", "label")}
        reasons = ["unsupported_format"]
    inventory_dir = paths.inventories / source.source_id / artifact.local_sha256
    inventory_dir.mkdir(parents=True, exist_ok=True)
    inventory_path = inventory_dir / "inspection.json"
    report = InspectionReport(
        INSPECTION_SCHEMA_VERSION,
        source.source_id,
        artifact.local_sha256,
        format_name,
        tuple(structure),
        findings,
        tuple(reasons),
        not reasons,
        tuple(warnings),
        inventory_path,
    )
    write_json_atomic(inventory_path, report.to_dict())
    return report
