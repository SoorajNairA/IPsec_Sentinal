from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

import yaml

from ipsec_sentinel.external.storage import resolve_external_root


EXTERNAL_CONFIG_SCHEMA_VERSION = "ipsec-sentinel.external-config/v1"
EXTERNAL_ROOT_ENV = "IPSEC_SENTINEL_EXTERNAL_DATA_ROOT"


@dataclass(frozen=True)
class ExternalConfig:
    external_data_root: Path

    @classmethod
    def load(
        cls,
        path: Path | None,
        environ: Mapping[str, str],
    ) -> "ExternalConfig":
        selected = path
        if selected is None:
            local = Path("configs/external-datasets.local.yaml")
            selected = local if local.exists() else Path(
                "configs/external-datasets.example.yaml"
            )
        raw = yaml.safe_load(selected.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or set(raw) != {
            "schema_version",
            "external_data_root",
        }:
            raise ValueError("external config fields mismatch")
        if raw["schema_version"] != EXTERNAL_CONFIG_SCHEMA_VERSION:
            raise ValueError("unsupported external config schema")
        configured = environ.get(EXTERNAL_ROOT_ENV, raw["external_data_root"])
        return cls(resolve_external_root(str(configured), Path.cwd()))

