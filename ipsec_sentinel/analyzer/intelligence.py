from __future__ import annotations

from pathlib import Path
from typing import Sequence

from ipsec_sentinel.ml.inference import predict_observations


def infer_traffic(
    observations: Sequence[object],
    model_dir: Path,
    *,
    minimum_packets: int = 10,
    low_confidence_threshold: float = 0.60,
    require_model_exists: bool = True,
) -> dict[str, object]:
    base = {
        "state": "UNKNOWN", "predicted_class": "UNKNOWN", "raw_confidence": None,
        "confidence_kind": "raw_uncalibrated", "probabilities": {},
        "provenance": "UNKNOWN", "model_version": "UNKNOWN",
        "feature_schema_version": "ipsec-sentinel.esp-session-features/v1",
        "payload_decrypted": False,
    }
    if len(observations) < minimum_packets:
        return {**base, "reason": f"insufficient ESP packets: {len(observations)} < {minimum_packets}"}
    if require_model_exists and not (model_dir / "model.joblib").is_file():
        return {**base, "reason": f"model artifact not found: {model_dir / 'model.joblib'}"}
    try:
        prediction = predict_observations(
            observations, model_dir,
            low_confidence_threshold=low_confidence_threshold,
        )
    except (OSError, ValueError, KeyError, TypeError) as error:
        return {**base, "reason": f"model unavailable or incompatible: {error}"}
    confidence = float(prediction["raw_confidence"])
    return {
        "state": "LOW_CONFIDENCE" if confidence < low_confidence_threshold else "PREDICTED",
        "predicted_class": prediction["inferred_class"],
        "raw_confidence": confidence,
        "confidence_kind": "raw_uncalibrated",
        "probabilities": prediction.get("class_probabilities", {}),
        "provenance": "AI_INFERRED",
        "model_version": prediction["model_schema_version"],
        "model_name": prediction["selected_model"],
        "feature_schema_version": prediction["feature_schema_version"],
        "payload_decrypted": False,
        "reason": "prototype classifier trained on controlled native-IPsec workloads",
    }
