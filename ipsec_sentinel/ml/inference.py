from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np

from ipsec_sentinel.dataset.models import WorkloadWindow
from ipsec_sentinel.ml.export import MODEL_SCHEMA_VERSION
from ipsec_sentinel.ml.features import extract_session_features
from ipsec_sentinel.ml.schema import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from ipsec_sentinel.pcap import read_ml_esp_packets


def predict_observations(
    packets: object,
    model_dir: Path = Path("model"),
    *,
    low_confidence_threshold: float = 0.60,
) -> dict[str, object]:
    if not 0 <= low_confidence_threshold <= 1.1:
        raise ValueError("low-confidence threshold must be between 0 and 1.1")
    packet_sequence = tuple(packets)  # type: ignore[arg-type]
    bundle = joblib.load(model_dir / "model.joblib")
    if bundle.get("model_schema_version") != MODEL_SCHEMA_VERSION:
        raise ValueError("unsupported model schema")
    if bundle.get("feature_schema_version") != FEATURE_SCHEMA_VERSION:
        raise ValueError("model feature schema is incompatible")
    if tuple(bundle.get("feature_names", ())) != FEATURE_NAMES:
        raise ValueError("model feature order is incompatible")
    features = extract_session_features(packet_sequence)
    vector = np.asarray([[features[name] for name in FEATURE_NAMES]], dtype=float)
    estimator = bundle["estimator"]
    probabilities = estimator.predict_proba(vector)[0]
    index = int(np.argmax(probabilities))
    inferred = str(estimator.classes_[index])
    confidence = float(probabilities[index])
    return {
        "evidence_type": "AI-INFERRED",
        "inferred_class": inferred,
        "raw_confidence": confidence,
        "class_probabilities": {
            str(label): float(probability)
            for label, probability in zip(estimator.classes_, probabilities)
        },
        "confidence_kind": "raw_predict_proba",
        "low_confidence_threshold": low_confidence_threshold,
        "low_confidence": confidence < low_confidence_threshold,
        "model_schema_version": MODEL_SCHEMA_VERSION,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "selected_model": bundle["selected_model"],
        "packet_count": len(packet_sequence),
        "interpretation": (
            "AI-INFERRED from ESP packet timing, length, and direction; "
            "this does not decrypt or inspect payload content."
        ),
    }


def predict_pcap(
    pcap: Path,
    model_dir: Path = Path("model"),
    *,
    low_confidence_threshold: float = 0.60,
    peers: tuple[str, str] = ("192.0.2.1", "192.0.2.2"),
) -> dict[str, object]:
    packets = read_ml_esp_packets(
        pcap, WorkloadWindow(1, (1 << 63) - 1), peers
    )
    return predict_observations(
        packets, model_dir, low_confidence_threshold=low_confidence_threshold
    )
