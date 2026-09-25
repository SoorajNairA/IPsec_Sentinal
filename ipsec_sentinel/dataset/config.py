from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any

import yaml

from ipsec_sentinel.dataset.models import DATASET_SCHEMA_VERSION
from ipsec_sentinel.traffic.base import (
    OOD_CLASS_ALLOWLIST,
    SUPERVISED_CLASS_ALLOWLIST,
)


class DatasetConfigError(ValueError):
    """Raised when a matrix file violates the Phase 2 contract."""


def _exact_mapping(value: Any, fields: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DatasetConfigError(f"{context} must be a mapping")
    actual = set(value)
    unknown = actual - fields
    missing = fields - actual
    if unknown:
        raise DatasetConfigError(f"unknown field in {context}: {sorted(unknown)[0]}")
    if missing:
        raise DatasetConfigError(f"missing field in {context}: {sorted(missing)[0]}")
    return value


def _string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise DatasetConfigError(f"{name} must be a nonempty string")
    return value


def _slug(value: Any) -> str:
    result = _string(value, "dataset.name")
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", result):
        raise DatasetConfigError("dataset.name must be a lowercase slug")
    return result


def _unique_strings(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise DatasetConfigError(f"{name} must be a nonempty list")
    items = tuple(_string(item, name) for item in value)
    if len(set(items)) != len(items):
        raise DatasetConfigError(f"{name} must not contain duplicates")
    return items


def _nonnegative_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise DatasetConfigError(f"{name} must be a nonnegative integer")
    return value


def _positive_int(value: Any, name: str) -> int:
    result = _nonnegative_int(value, name)
    if result == 0:
        raise DatasetConfigError(f"{name} must be positive")
    return result


@dataclass(frozen=True)
class DatasetConfig:
    name: str
    schema_version: str
    base_seed: int
    traffic_classes: tuple[str, ...]
    scenarios: tuple[str, ...]
    network_profiles: tuple[str, ...]
    runs_per_combination: int
    workers: int
    retry_failed: int
    evaluation_ood_classes: tuple[str, ...] = ()
    evaluation_runs_per_combination: int = 0

    @classmethod
    def load(cls, path: Path) -> "DatasetConfig":
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as error:
            raise DatasetConfigError(f"cannot load matrix: {error}") from error
        required_root = {
                "dataset",
                "traffic",
                "ipsec",
                "network_profiles",
                "runs_per_combination",
                "execution",
        }
        if not isinstance(raw, dict):
            raise DatasetConfigError("matrix must be a mapping")
        unknown_root = set(raw) - required_root - {"evaluation"}
        missing_root = required_root - set(raw)
        if unknown_root:
            raise DatasetConfigError(
                f"unknown field in matrix: {sorted(unknown_root)[0]}"
            )
        if missing_root:
            raise DatasetConfigError(
                f"missing field in matrix: {sorted(missing_root)[0]}"
            )
        root = raw
        dataset = _exact_mapping(
            root["dataset"], {"name", "schema_version", "seed"}, "dataset"
        )
        traffic = _exact_mapping(root["traffic"], {"classes"}, "traffic")
        ipsec = _exact_mapping(root["ipsec"], {"scenarios"}, "ipsec")
        execution = _exact_mapping(
            root["execution"], {"workers", "retry_failed"}, "execution"
        )
        evaluation = None
        if "evaluation" in root:
            evaluation = _exact_mapping(
                root["evaluation"],
                {"ood_classes", "runs_per_combination"},
                "evaluation",
            )
        traffic_classes = _unique_strings(traffic["classes"], "traffic.classes")
        for name in traffic_classes:
            if name in OOD_CLASS_ALLOWLIST:
                raise DatasetConfigError(
                    f"OOD class cannot appear in traffic.classes: {name}"
                )
            if name not in SUPERVISED_CLASS_ALLOWLIST:
                raise DatasetConfigError(f"unknown traffic class: {name}")
        evaluation_classes: tuple[str, ...] = ()
        evaluation_runs = 0
        if evaluation is not None:
            evaluation_classes = _unique_strings(
                evaluation["ood_classes"], "evaluation.ood_classes"
            )
            evaluation_runs = _positive_int(
                evaluation["runs_per_combination"],
                "evaluation.runs_per_combination",
            )
            for name in evaluation_classes:
                if name in SUPERVISED_CLASS_ALLOWLIST:
                    raise DatasetConfigError(
                        f"supervised class cannot appear in evaluation.ood_classes: {name}"
                    )
                if name not in OOD_CLASS_ALLOWLIST:
                    raise DatasetConfigError(f"unknown OOD traffic class: {name}")
        config = cls(
            name=_slug(dataset["name"]),
            schema_version=_string(dataset["schema_version"], "schema_version"),
            base_seed=_nonnegative_int(dataset["seed"], "seed"),
            traffic_classes=traffic_classes,
            scenarios=_unique_strings(ipsec["scenarios"], "ipsec.scenarios"),
            network_profiles=_unique_strings(
                root["network_profiles"], "network_profiles"
            ),
            runs_per_combination=_positive_int(
                root["runs_per_combination"], "runs_per_combination"
            ),
            workers=_positive_int(execution["workers"], "workers"),
            retry_failed=_nonnegative_int(
                execution["retry_failed"], "retry_failed"
            ),
            evaluation_ood_classes=evaluation_classes,
            evaluation_runs_per_combination=evaluation_runs,
        )
        if config.schema_version != DATASET_SCHEMA_VERSION:
            raise DatasetConfigError("unsupported dataset schema_version")
        if config.workers != 1:
            raise DatasetConfigError("workers must be 1 in Phase 2")
        if config.network_profiles != ("clean",):
            raise DatasetConfigError("unsupported network profile")
        if config.scenarios != ("secure-baseline",):
            raise DatasetConfigError("unsupported IPsec scenario")
        return config
