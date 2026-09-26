from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
import hashlib
import os
import platform
import re
import subprocess

import joblib
import numpy
import sklearn

from ipsec_sentinel.artifacts import write_json_atomic, write_text_atomic
from ipsec_sentinel.ml.schema import FEATURE_NAMES, FEATURE_SCHEMA_VERSION


MODEL_SCHEMA_VERSION = "ipsec-sentinel.classifier/v1"


def _git_commit_sha() -> str:
    environment = dict(os.environ)
    marker = Path(".git")
    if marker.is_file():
        line = marker.read_text(encoding="utf-8").strip()
        if line.startswith("gitdir: "):
            git_dir = line.removeprefix("gitdir: ")
            match = re.fullmatch(r"([A-Za-z]):/(.*)", git_dir)
            if match and platform.system() == "Linux":
                git_dir = f"/mnt/{match.group(1).lower()}/{match.group(2)}"
            environment["GIT_DIR"] = git_dir
            environment["GIT_WORK_TREE"] = str(Path.cwd())
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], check=True, capture_output=True,
        text=True, timeout=10, env=environment,
    ).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", result):
        raise RuntimeError("git returned an invalid commit SHA")
    return result


def export_model_bundle(
    output_dir: Path,
    *,
    estimator: object,
    selected_model: str,
    class_labels: tuple[str, ...],
    metrics: dict[str, object],
    split_manifest: Path,
    dataset_sha256: str,
    seed: int,
    hyperparameters: dict[str, object],
) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    bundle = {
        "model_schema_version": MODEL_SCHEMA_VERSION,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_names": FEATURE_NAMES,
        "class_labels": class_labels,
        "selected_model": selected_model,
        "estimator": estimator,
    }
    model_path = output_dir / "model.joblib"
    temporary = output_dir / f".{model_path.name}.{uuid4().hex}.tmp"
    try:
        joblib.dump(bundle, temporary)
        temporary.replace(model_path)
    finally:
        temporary.unlink(missing_ok=True)

    feature_schema_path = output_dir / "feature_schema.json"
    class_map_path = output_dir / "class_map.json"
    metrics_path = output_dir / "metrics.json"
    split_path = output_dir / "split_manifest.json"
    metadata_path = output_dir / "training_metadata.json"
    write_json_atomic(
        feature_schema_path,
        {
            "schema_version": FEATURE_SCHEMA_VERSION,
            "feature_names": list(FEATURE_NAMES),
            "sample_unit": "complete workload-window ESP session",
        },
    )
    write_json_atomic(
        class_map_path,
        {"classes": {str(index): label for index, label in enumerate(class_labels)}},
    )
    write_json_atomic(metrics_path, metrics)
    split_text = split_manifest.read_text(encoding="utf-8")
    write_text_atomic(split_path, split_text)
    write_json_atomic(
        metadata_path,
        {
            "model_schema_version": MODEL_SCHEMA_VERSION,
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "git_commit_sha": _git_commit_sha(),
            "dataset_sha256": dataset_sha256,
            "split_manifest_sha256": hashlib.sha256(
                split_text.encode("utf-8")
            ).hexdigest(),
            "selected_model": selected_model,
            "hyperparameters": hyperparameters,
            "random_seed": seed,
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "python_version": platform.python_version(),
            "numpy_version": numpy.__version__,
            "scikit_learn_version": sklearn.__version__,
            "confidence_kind": "raw_predict_proba",
            "calibration_status": "not_applied",
        },
    )
    return {
        "model": model_path,
        "feature_schema": feature_schema_path,
        "class_map": class_map_path,
        "metrics": metrics_path,
        "split": split_path,
        "training_metadata": metadata_path,
    }
