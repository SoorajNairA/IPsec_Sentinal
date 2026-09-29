from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
from typing import Callable, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ipsec_sentinel.artifacts import write_json_atomic
from ipsec_sentinel.external.registry import ArtifactRecord
from ipsec_sentinel.external.storage import ExternalPaths


ACQUISITION_TOOL_VERSION = "ipsec-sentinel.external-acquire/v1"
SPACE_SAFETY_BYTES = 64 * 1024 * 1024
MAX_ATTEMPTS = 3


class AcquisitionError(RuntimeError):
    def __init__(self, category: str, message: str):
        self.category = category
        super().__init__(f"{category}: {message}")


class Response(Protocol):
    headers: object
    status: int

    def read(self, size: int = -1) -> bytes: ...
    def __enter__(self) -> "Response": ...
    def __exit__(self, *args: object) -> None: ...


UrlOpener = Callable[[Request], Response]


@dataclass(frozen=True)
class VerifiedArtifact:
    path: Path
    observed_size_bytes: int
    local_sha256: str
    publisher_checksum_result: str


@dataclass(frozen=True)
class AcquisitionReceipt:
    artifact_id: str
    url: str
    etag: str | None
    last_modified: str | None
    declared_size_bytes: int | None
    observed_size_bytes: int
    publisher_checksum_result: str
    local_sha256: str
    started_at: str
    finished_at: str
    tool_version: str
    final_path: Path
    receipt_path: Path
    outcome: str

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["final_path"] = str(self.final_path)
        payload["receipt_path"] = str(self.receipt_path)
        return payload


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _available_bytes(path: Path) -> int:
    return shutil.disk_usage(path).free


def _default_open(request: Request) -> Response:
    return urlopen(request, timeout=60)  # type: ignore[return-value]


def _digest(path: Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def verify_download(path: Path, artifact: ArtifactRecord) -> VerifiedArtifact:
    observed = path.stat().st_size
    if artifact.published_size_bytes is not None and observed != artifact.published_size_bytes:
        raise AcquisitionError(
            "size",
            f"expected {artifact.published_size_bytes} bytes, observed {observed}",
        )
    local_sha256 = _digest(path, "sha256")
    checksum_result = "absent"
    if artifact.publisher_checksum is not None:
        actual = _digest(path, artifact.publisher_checksum.algorithm)
        if actual != artifact.publisher_checksum.value:
            raise AcquisitionError(
                "checksum",
                f"{artifact.publisher_checksum.algorithm} mismatch",
            )
        checksum_result = "matched"
    return VerifiedArtifact(path, observed, local_sha256, checksum_result)


def _load_partial(path: Path, artifact: ArtifactRecord, resume: bool) -> tuple[int, dict[str, object] | None]:
    metadata_path = path.with_name(f"{path.name}.json")
    if not resume or not path.exists() or not metadata_path.exists():
        return 0, None
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0, None
    if metadata.get("url") != artifact.download_url:
        return 0, None
    if metadata.get("total_size") not in (None, artifact.published_size_bytes):
        return 0, None
    return path.stat().st_size, metadata


def _content_range_start(value: str | None) -> int | None:
    if value is None or not value.startswith("bytes ") or "/" not in value:
        return None
    interval = value[6:].split("/", 1)[0]
    try:
        return int(interval.split("-", 1)[0])
    except (ValueError, IndexError):
        return None


def _download_once(
    artifact: ArtifactRecord,
    part: Path,
    *,
    resume: bool,
    opener: UrlOpener,
) -> tuple[str | None, str | None]:
    offset, metadata = _load_partial(part, artifact, resume)
    headers: dict[str, str] = {}
    if offset and metadata is not None:
        validator = metadata.get("etag") or metadata.get("last_modified")
        if isinstance(validator, str):
            headers = {"Range": f"bytes={offset}-", "If-Range": validator}
        else:
            offset = 0
    request = Request(artifact.download_url, headers=headers)
    with opener(request) as response:
        status = getattr(response, "status", response.getcode())
        etag = response.headers.get("ETag")
        last_modified = response.headers.get("Last-Modified")
        append = False
        if offset:
            old_validator = metadata.get("etag") or metadata.get("last_modified")
            new_validator = etag or last_modified
            append = (
                status == 206
                and _content_range_start(response.headers.get("Content-Range")) == offset
                and old_validator == new_validator
            )
        mode = "ab" if append else "wb"
        content_length = response.headers.get("Content-Length")
        total_size = artifact.published_size_bytes
        if total_size is None and content_length is not None:
            total_size = int(content_length) + (offset if append else 0)
        write_json_atomic(
            part.with_name(f"{part.name}.json"),
            {
                "url": artifact.download_url,
                "etag": etag,
                "last_modified": last_modified,
                "total_size": total_size,
            },
        )
        with part.open(mode) as output:
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        return etag, last_modified


def acquire_artifact(
    artifact: ArtifactRecord,
    paths: ExternalPaths,
    *,
    resume: bool = True,
    opener: UrlOpener | None = None,
) -> AcquisitionReceipt:
    started = _now()
    directory = paths.downloads / artifact.artifact_id
    directory.mkdir(parents=True, exist_ok=True)
    final = directory / artifact.filename
    receipt_path = directory / f"{artifact.filename}.receipt.json"
    if final.exists():
        verified = verify_download(final, artifact)
        receipt = AcquisitionReceipt(
            artifact.artifact_id,
            artifact.download_url,
            None,
            None,
            artifact.published_size_bytes,
            verified.observed_size_bytes,
            verified.publisher_checksum_result,
            verified.local_sha256,
            started,
            _now(),
            ACQUISITION_TOOL_VERSION,
            final,
            receipt_path,
            "reused",
        )
        write_json_atomic(receipt_path, receipt.to_dict())
        return receipt

    required = (artifact.published_size_bytes or 0) + SPACE_SAFETY_BYTES
    if _available_bytes(paths.root) < required:
        raise AcquisitionError("space", f"requires at least {required} free bytes")

    part = directory / f"{artifact.filename}.part"
    selected_opener = opener or _default_open
    etag: str | None = None
    last_modified: str | None = None
    error: BaseException | None = None
    for _attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            etag, last_modified = _download_once(
                artifact, part, resume=resume, opener=selected_opener
            )
            error = None
            break
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            error = exc
    if error is not None:
        write_json_atomic(
            directory / f"{artifact.filename}.failure.json",
            {"category": "transport", "message": str(error), "at": _now()},
        )
        raise AcquisitionError("transport", str(error)) from error

    try:
        verified = verify_download(part, artifact)
    except AcquisitionError as exc:
        write_json_atomic(
            directory / f"{artifact.filename}.failure.json",
            {"category": exc.category, "message": str(exc), "at": _now()},
        )
        raise
    part.replace(final)
    part.with_name(f"{part.name}.json").unlink(missing_ok=True)
    receipt = AcquisitionReceipt(
        artifact.artifact_id,
        artifact.download_url,
        etag,
        last_modified,
        artifact.published_size_bytes,
        verified.observed_size_bytes,
        verified.publisher_checksum_result,
        verified.local_sha256,
        started,
        _now(),
        ACQUISITION_TOOL_VERSION,
        final,
        receipt_path,
        "downloaded",
    )
    write_json_atomic(receipt_path, receipt.to_dict())
    return receipt
