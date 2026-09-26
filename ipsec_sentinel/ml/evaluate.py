from __future__ import annotations

from collections.abc import Sequence

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
)


def classification_metrics(
    truth: Sequence[str],
    predicted: Sequence[str],
    labels: Sequence[str],
) -> dict[str, object]:
    if not truth:
        return {"available": False, "sample_count": 0}
    precision, recall, f1, support = precision_recall_fscore_support(
        truth, predicted, labels=labels, zero_division=0
    )
    macro = precision_recall_fscore_support(
        truth, predicted, average="macro", labels=labels, zero_division=0
    )
    weighted = precision_recall_fscore_support(
        truth, predicted, average="weighted", labels=labels, zero_division=0
    )
    return {
        "available": True,
        "sample_count": len(truth),
        "accuracy": float(accuracy_score(truth, predicted)),
        "macro_precision": float(macro[0]),
        "macro_recall": float(macro[1]),
        "macro_f1": float(macro[2]),
        "weighted_precision": float(weighted[0]),
        "weighted_recall": float(weighted[1]),
        "weighted_f1": float(weighted[2]),
        "labels": list(labels),
        "confusion_matrix": confusion_matrix(
            truth, predicted, labels=labels
        ).astype(int).tolist(),
        "per_class": {
            label: {
                "precision": float(precision[index]),
                "recall": float(recall[index]),
                "f1": float(f1[index]),
                "support": int(support[index]),
            }
            for index, label in enumerate(labels)
        },
    }


def confidence_summary(probabilities: np.ndarray) -> dict[str, object]:
    if probabilities.size == 0:
        return {"available": False, "sample_count": 0}
    confidence = np.max(probabilities, axis=1)
    return {
        "available": True,
        "sample_count": int(len(confidence)),
        "kind": "raw_predict_proba",
        "mean": float(np.mean(confidence)),
        "min": float(np.min(confidence)),
        "p10": float(np.percentile(confidence, 10)),
        "median": float(np.median(confidence)),
        "p90": float(np.percentile(confidence, 90)),
        "max": float(np.max(confidence)),
    }
