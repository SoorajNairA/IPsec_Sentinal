from __future__ import annotations

from pathlib import Path
from typing import Any

from ipsec_sentinel.analyzer.capture import CaptureError, parse_capture
from ipsec_sentinel.analyzer.contract import ANALYSIS_SCHEMA_ID, validate_analysis
from ipsec_sentinel.analyzer.esp import analyze_esp
from ipsec_sentinel.analyzer.ike import analyze_ike
from ipsec_sentinel.analyzer.intelligence import infer_traffic
from ipsec_sentinel.analyzer.lab import load_controlled_evidence
from ipsec_sentinel.analyzer.models import Evidence
from ipsec_sentinel.analyzer.protocols import analyze_protocols
from ipsec_sentinel.analyzer.rules import assess_security
from ipsec_sentinel.analyzer.sa import reconstruct_security_associations


def _base(path: Path) -> dict[str, Any]:
    category_maximum = (
        ("Cryptography", 30), ("Key Exchange / PFS", 25),
        ("Security Association Hygiene", 15),
        ("Replay / Protocol Protections", 15),
        ("Metadata / Privacy Exposure", 15),
    )
    return {
        "analysis_version": "1.0", "schema_id": ANALYSIS_SCHEMA_ID,
        "capture": {"path": str(path), "format": "UNKNOWN", "packet_count": 0,
                    "capture_bytes": 0, "duration_seconds": 0.0, "warnings": []},
        "summary": {"status": "ERROR", "ipsec": "UNKNOWN", "message": ""},
        "peers": {"initiator": "UNKNOWN", "responder": "UNKNOWN", "peer_pairs": [],
                  "multiple_sessions": False},
        "protocols": {"ipsec_detected": False, "ike_detected": False,
                      "ike_version": "UNKNOWN", "esp_detected": False,
                      "ah_detected": False, "natt_detected": False,
                      "ike_packets": 0, "esp_packets": 0, "ah_packets": 0,
                      "natt_packets": 0, "peer_pairs": []},
        "ike": {"detected": False, "version": "UNKNOWN", "exchanges": [],
                "initiator_spi": "UNKNOWN", "responder_spi": "UNKNOWN",
                "encryption": {"raw": "UNKNOWN", "normalized": "UNKNOWN", "provenance": "UNKNOWN"},
                "integrity": {"raw": "UNKNOWN", "normalized": "UNKNOWN", "provenance": "UNKNOWN"},
                "prf": {"raw": "UNKNOWN", "normalized": "UNKNOWN", "provenance": "UNKNOWN"},
                "dh_group": {"raw": "UNKNOWN", "normalized": "UNKNOWN", "provenance": "UNKNOWN"},
                "selection_basis": "UNKNOWN", "traffic_selectors": {"value": "UNKNOWN", "provenance": "UNKNOWN"}},
        "controlled_evidence": {"available": False, "source": "none"},
        "security_associations": [],
        "pfs": {"state": "unknown", "provenance": "UNKNOWN", "evidence_ids": [],
                "explanation": "Insufficient CHILD-SA DH evidence."},
        "esp": {"packet_count": 0, "bytes": 0, "duration_seconds": 0.0,
                "direction_counts": {}, "direction_bytes": {}, "spi_distribution": {},
                "peer_pair": None, "features": None,
                "feature_schema_version": "ipsec-sentinel.esp-session-features/v1",
                "payload_decrypted": False},
        "traffic_intelligence": {"state": "UNKNOWN", "predicted_class": "UNKNOWN",
                                 "raw_confidence": None, "confidence_kind": "raw_uncalibrated",
                                 "probabilities": {}, "provenance": "UNKNOWN",
                                 "model_version": "UNKNOWN",
                                 "feature_schema_version": "ipsec-sentinel.esp-session-features/v1",
                                 "payload_decrypted": False, "reason": "analysis unavailable"},
        "evidence": [], "findings": [],
        "security_score": {"total": 0, "maximum": 100, "assessed_weight": 0,
                           "unassessed_weight": 100, "categories": [
                               {"name": name, "maximum_score": maximum,
                                "achieved_score": 0, "assessed_weight": 0,
                                "unassessed_weight": maximum, "deductions": []}
                               for name, maximum in category_maximum
                           ],
                           "method": "normalized over assessed evidence; UNKNOWN is not penalized"},
        "limitations": [],
    }


def _infer_peers(capture, peer_pairs: list[list[str]]) -> dict[str, Any]:
    initiator = responder = "UNKNOWN"
    for packet in capture.packets:
        if packet.kind != "IKE" or len(packet.transport_payload) < 28:
            continue
        if not packet.transport_payload[19] & 0x20:
            initiator, responder = packet.source or "UNKNOWN", packet.destination or "UNKNOWN"
            break
    return {
        "initiator": initiator, "responder": responder, "peer_pairs": peer_pairs,
        "multiple_sessions": len(peer_pairs) > 1,
    }


def _unknown_workload_traffic(reason: str, path: Path) -> dict[str, object]:
    return {
        "state": "UNKNOWN",
        "predicted_class": "UNKNOWN",
        "raw_confidence": None,
        "confidence_kind": "raw_uncalibrated",
        "probabilities": {},
        "provenance": "UNKNOWN",
        "model_version": "UNKNOWN",
        "feature_schema_version": "ipsec-sentinel.esp-session-features/v1",
        "payload_decrypted": False,
        "reason": reason,
        "capture_source": "WORKLOAD_WINDOW",
        "capture_path": str(path),
    }


def analyze_capture(
    path: Path,
    *,
    model_dir: Path = Path("model"),
    low_confidence_threshold: float = 0.60,
    evidence_dir: Path | None = None,
    traffic_capture_path: Path | None = None,
) -> dict[str, Any]:
    path = Path(path)
    result = _base(path)
    try:
        capture = parse_capture(path)
    except (CaptureError, OSError) as error:
        result["summary"] = {"status": "ERROR", "ipsec": "UNKNOWN", "message": str(error)}
        result["limitations"] = [{"code": "CAPTURE_ERROR", "description": str(error)}]
        validate_analysis(result)
        return result

    protocols, protocol_evidence = analyze_protocols(capture)
    ike, ike_evidence = analyze_ike(capture)
    associations, sa_evidence = reconstruct_security_associations(capture)
    esp, observations, esp_evidence = analyze_esp(capture)
    traffic_limitation: dict[str, str] | None = None
    if traffic_capture_path is None:
        traffic = infer_traffic(
            observations, model_dir,
            low_confidence_threshold=low_confidence_threshold,
        )
    else:
        workload_path = Path(traffic_capture_path)
        try:
            workload_capture = parse_capture(workload_path)
        except (CaptureError, OSError) as error:
            description = f"Workload capture unavailable: {error}"
            traffic = _unknown_workload_traffic(description, workload_path)
            traffic_limitation = {
                "code": "TRAFFIC_CAPTURE_ERROR",
                "description": description,
            }
        else:
            _, workload_observations, _ = analyze_esp(workload_capture)
            full_peer_pair = esp.get("peer_pair")
            has_non_esp = any(
                packet.kind != "ESP" or packet.natt
                for packet in workload_capture.packets
            )
            has_wrong_peer = bool(full_peer_pair) and any(
                {packet.source, packet.destination} != set(full_peer_pair)
                for packet in workload_capture.packets
            )
            if has_non_esp:
                description = "Workload capture must contain native ESP packets only."
                traffic = _unknown_workload_traffic(description, workload_path)
                traffic_limitation = {
                    "code": "TRAFFIC_CAPTURE_NO_ESP",
                    "description": description,
                }
            elif has_wrong_peer:
                description = "Workload capture ESP peers do not match the full session."
                traffic = _unknown_workload_traffic(description, workload_path)
                traffic_limitation = {
                    "code": "TRAFFIC_CAPTURE_WRONG_PEER",
                    "description": description,
                }
            elif not workload_observations:
                description = "Workload capture contains no ESP packets."
                traffic = _unknown_workload_traffic(description, workload_path)
                traffic_limitation = {
                    "code": "TRAFFIC_CAPTURE_NO_ESP",
                    "description": description,
                }
            else:
                traffic = infer_traffic(
                    workload_observations,
                    model_dir,
                    low_confidence_threshold=low_confidence_threshold,
                )
                traffic["capture_source"] = "WORKLOAD_WINDOW"
                traffic["capture_path"] = str(workload_path)
    sidecar_dir = path.parent if evidence_dir is None else Path(evidence_dir)
    controlled, controlled_pfs, controlled_items = load_controlled_evidence(sidecar_dir, path.name)
    if (
        traffic_capture_path is not None
        and controlled.get("capture_provenance") == "NATT_NORMALIZED_WORKLOAD_WINDOW"
    ):
        traffic["capture_source"] = "NATT_NORMALIZED_WORKLOAD_WINDOW"
    evidence: list[Evidence] = [*protocol_evidence, *ike_evidence, *sa_evidence, *esp_evidence, *controlled_items]
    evidence_ids = {item.id for item in evidence}
    for field, identifier in (
        ("encryption", "ev-ike-encryption-001"),
        ("integrity", "ev-ike-integrity-001"),
        ("prf", "ev-ike-prf-001"),
        ("dh_group", "ev-ike-dh_group-001"),
    ):
        if identifier in evidence_ids:
            ike[field]["evidence_id"] = identifier
    if traffic["state"] in ("PREDICTED", "LOW_CONFIDENCE"):
        inference_scope = (
            " in the workload-only ESP capture"
            if traffic_capture_path is not None
            else ""
        )
        evidence.append(Evidence(
            "ev-traffic-inference-001", "AI_INFERRED",
            f"Traffic classified as {traffic['predicted_class']} from encrypted ESP behavior{inference_scope}",
            protocol="ESP", raw_value=traffic["predicted_class"],
            normalized_value=traffic["predicted_class"], source_component="ml-classifier",
            confidence=float(traffic["raw_confidence"]),
        ))
    for item, ev in zip(
        [sa for sa in associations if sa.get("successor_spi")], sa_evidence
    ):
        item["rekey_evidence_id"] = ev.id

    result.update({
        "capture": {"path": str(path), "format": capture.capture_format,
                    "packet_count": capture.packet_count, "capture_bytes": capture.capture_bytes,
                    "first_timestamp_ns": capture.first_timestamp_ns,
                    "last_timestamp_ns": capture.last_timestamp_ns,
                    "duration_seconds": capture.duration_seconds,
                    "warnings": list(capture.warnings)},
        "summary": {"status": "COMPLETE", "ipsec": "DETECTED" if protocols["ipsec_detected"] else "NOT_DETECTED",
                    "message": "Analysis completed without payload decryption."},
        "peers": _infer_peers(capture, protocols["peer_pairs"]),
        "protocols": protocols, "ike": ike,
        "controlled_evidence": controlled,
        "security_associations": associations, "esp": esp,
        "traffic_intelligence": traffic,
    })
    if controlled_pfs is not None:
        result["pfs"] = controlled_pfs
    findings, score = assess_security(result)
    result["findings"] = findings
    result["security_score"] = score
    result["evidence"] = [item.to_dict() for item in evidence]
    limitations = [
        {"code": "NO_DECRYPTION", "description": "ESP payloads were not decrypted."},
        {"code": "PASSIVE_MODE", "description": "Tunnel/transport mode, SA lifetime, and replay enforcement may not be passively determinable."},
        {"code": "PFS_PASSIVE_LIMIT", "description": "ESP rekey alone does not establish CHILD-SA PFS."},
    ]
    if len(protocols["peer_pairs"]) > 1:
        limitations.append({"code": "MULTIPLE_SESSIONS", "description": "Multiple peer pairs were reported separately; ESP statistics use the dominant pair only."})
    if traffic["state"] == "UNKNOWN":
        limitations.append({"code": "TRAFFIC_UNKNOWN", "description": str(traffic["reason"])})
    else:
        limitations.append({"code": "MODEL_SCOPE", "description": "Traffic confidence is raw, uncalibrated, and based on a controlled synthetic testbed."})
    if traffic_limitation is not None:
        limitations.append(traffic_limitation)
    elif traffic_capture_path is not None:
        limitations.append({
            "code": "TRAFFIC_WINDOW_SCOPE",
            "description": (
                "Traffic intelligence and X-Ray use the workload-only ESP capture; "
                "protocol and security analysis use the full session capture."
            ),
        })
    result["limitations"] = limitations
    validate_analysis(result)
    return result
