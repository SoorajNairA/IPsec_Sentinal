from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re


def _beneath(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def resolve_external_root(
    raw_root: str,
    repo_root: Path,
    *,
    require_wsl_ext4: bool = True,
) -> Path:
    if not raw_root.strip():
        raise ValueError("external data root is required")
    candidate = Path(raw_root).expanduser()
    if not candidate.is_absolute():
        raise ValueError("external data root must be absolute")
    resolved = candidate.resolve(strict=False)
    repository = repo_root.resolve(strict=False)
    if _beneath(resolved, repository):
        raise ValueError("external data root cannot be inside the repository")
    if any("onedrive" in part.casefold() for part in resolved.parts):
        raise ValueError("external data root cannot be inside OneDrive")
    if require_wsl_ext4 and re.match(r"^/mnt/[^/]+(?:/|$)", resolved.as_posix()):
        raise ValueError("large external artifacts require a WSL ext4 path")
    return resolved


@dataclass(frozen=True)
class ExternalPaths:
    root: Path
    downloads: Path
    extracted: Path
    inventories: Path
    normalized: Path
    reports: Path
    logs: Path
    tmp: Path

    @classmethod
    def create(cls, root: Path) -> "ExternalPaths":
        resolved = root.resolve(strict=False)
        if not resolved.is_absolute():
            raise ValueError("external root must be absolute")
        resolved.mkdir(parents=True, exist_ok=True)
        values = {
            name: resolved / name
            for name in (
                "downloads",
                "extracted",
                "inventories",
                "normalized",
                "reports",
                "logs",
                "tmp",
            )
        }
        for path in values.values():
            path.mkdir(parents=True, exist_ok=True)
        return cls(resolved, **values)
