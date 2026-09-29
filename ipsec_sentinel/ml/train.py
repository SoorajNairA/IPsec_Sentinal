from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import csv
import hashlib
import json

import numpy as np
from sklearn.base import clone
from sklearn.ensemble import (
    ExtraTreesClassifier,
    HistGradientBoostingClassifier,
    RandomForestClassifier,
)
from sklearn.inspection import permutation_importance

from ipsec_sentinel.ml.evaluate import classification_metrics, confidence_summary
from ipsec_sentinel.ml.export import export_model_bundle
from ipsec_sentinel.ml.schema import FEATURE_NAMES


@dataclass(frozen=True)
class TrainingRun:
    output_dir: Path
    model_path: Path
    metrics_path: Path
    training_metadata_path: Path
    selected_model: str
    validation_macro_f1: float
    dataset_sha256: str


def _load_table(
    features_csv: Path, split_manifest: Path
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, str]:
    source = features_csv.read_bytes()
    digest = hashlib.sha256(source).hexdigest()
    split = json.loads(split_manifest.read_text(encoding="utf-8"))
    if split.get("source_sha256") != digest:
        raise ValueError("split manifest does not match feature table")
    assignments = {
        item["session_id"]: item["split"] for item in split["assignments"]
    }
    with features_csv.open(newline="", encoding="utf-8") as input_file:
        reader = csv.DictReader(input_file)
        expected = ("session_id", "label", "scenario_id", *FEATURE_NAMES)
        if tuple(reader.fieldnames or ()) != expected:
            raise ValueError("feature table columns do not match the schema")
        rows = list(reader)
    if set(assignments) != {row["session_id"] for row in rows}:
        raise ValueError("split assignments and feature sessions differ")
    features = np.asarray(
        [[float(row[name]) for name in FEATURE_NAMES] for row in rows], dtype=float
    )
    labels = np.asarray([row["label"] for row in rows], dtype=str)
    scenarios = np.asarray([row["scenario_id"] for row in rows], dtype=str)
    splits = np.asarray([assignments[row["session_id"]] for row in rows], dtype=str)
    if not np.isfinite(features).all():
        raise ValueError("feature table contains a non-finite value")
    return features, labels, scenarios, splits, digest


def _model_candidates(seed: int) -> dict[str, object]:
    return {
        "random_forest": RandomForestClassifier(
            n_estimators=128, class_weight="balanced", random_state=seed, n_jobs=1
        ),
        "extra_trees": ExtraTreesClassifier(
            n_estimators=128, class_weight="balanced", random_state=seed, n_jobs=1
        ),
        "hist_gradient_boosting": HistGradientBoostingClassifier(
            max_iter=100, class_weight="balanced", random_state=seed
        ),
    }


def train_and_export(
    features_csv: Path,
    split_manifest: Path,
    output_dir: Path,
    *,
    seed: int = 20260926,
) -> TrainingRun:
    features, labels, scenarios, splits, digest = _load_table(
        features_csv, split_manifest
    )
    class_labels = tuple(sorted(set(labels.tolist())))
    train_mask = splits == "train"
    validation_mask = splits == "validation"
    test_mask = splits == "test"
    if len(set(labels[train_mask].tolist())) < 2:
        raise ValueError("training split must contain at least two classes")
    if not validation_mask.any() or not test_mask.any():
        raise ValueError("validation and test splits must be nonempty")

    candidates: dict[str, dict[str, object]] = {}
    fitted: dict[str, object] = {}
    for name, estimator in _model_candidates(seed).items():
        estimator.fit(features[train_mask], labels[train_mask])
        prediction = estimator.predict(features[validation_mask])
        metrics = classification_metrics(
            labels[validation_mask].tolist(), prediction.tolist(), class_labels
        )
        candidates[name] = metrics
        fitted[name] = estimator
    selected_name = min(
        candidates,
        key=lambda name: (-float(candidates[name]["macro_f1"]), name),
    )
    selected = fitted[selected_name]
    test_prediction = selected.predict(features[test_mask])
    test_metrics = classification_metrics(
        labels[test_mask].tolist(), test_prediction.tolist(), class_labels
    )
    probabilities = selected.predict_proba(features[test_mask])

    per_scenario: dict[str, object] = {}
    for scenario in sorted(set(scenarios[test_mask].tolist())):
        mask = test_mask & (scenarios == scenario)
        per_scenario[scenario] = classification_metrics(
            labels[mask].tolist(), selected.predict(features[mask]).tolist(),
            class_labels,
        )

    leave_one_out: dict[str, object] = {}
    for scenario in sorted(set(scenarios.tolist())):
        held_out = scenarios == scenario
        remaining = ~held_out
        if len(set(labels[remaining].tolist())) < 2 or not held_out.any():
            leave_one_out[scenario] = {
                "available": False, "reason": "insufficient class/scenario support"
            }
            continue
        estimator = clone(selected)
        estimator.fit(features[remaining], labels[remaining])
        leave_one_out[scenario] = classification_metrics(
            labels[held_out].tolist(), estimator.predict(features[held_out]).tolist(),
            class_labels,
        )

    importance = permutation_importance(
        selected, features[test_mask], labels[test_mask],
        scoring="f1_macro", n_repeats=3, random_state=seed, n_jobs=1,
    )
    ranking = sorted(
        zip(FEATURE_NAMES, importance.importances_mean.tolist()),
        key=lambda item: (-item[1], item[0]),
    )[:20]
    metrics_payload: dict[str, object] = {
        "metrics_scope": "pilot-only until the full grouped matrix is collected",
        "selection_metric": "validation macro_f1",
        "selected_model": selected_name,
        "candidates": candidates,
        "test": test_metrics,
        "per_scenario": per_scenario,
        "leave_one_scenario_out": leave_one_out,
        "confidence": confidence_summary(probabilities),
        "calibration": {
            "status": "not_applied",
            "reason": (
                "prototype avoids calibration until each class/scenario has "
                "enough independent session groups for a separate calibration set"
            ),
        },
        "permutation_importance_top20": [
            {"feature": name, "mean_macro_f1_decrease": float(value)}
            for name, value in ranking
        ],
    }
    hyperparameters = {
        key: value
        for key, value in selected.get_params(deep=False).items()
        if isinstance(value, (str, int, float, bool)) or value is None
    }
    paths = export_model_bundle(
        output_dir,
        estimator=selected,
        selected_model=selected_name,
        class_labels=class_labels,
        metrics=metrics_payload,
        split_manifest=split_manifest,
        dataset_sha256=digest,
        seed=seed,
        hyperparameters=hyperparameters,
    )
    return TrainingRun(
        output_dir,
        paths["model"],
        paths["metrics"],
        paths["training_metadata"],
        selected_name,
        float(candidates[selected_name]["macro_f1"]),
        digest,
    )
