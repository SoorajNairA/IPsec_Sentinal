from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ipsec_sentinel.analyzer.models import Evidence


def _normalize_proposal(value: str) -> dict[str, str]:
    upper = value.upper()
    encryption = "UNKNOWN"
    integrity = "UNKNOWN"
    dh_group = "UNKNOWN"
    if "AES_GCM_16_256" in upper or "AES256GCM16" in upper:
        encryption = "AES-256-GCM"
    elif "AES_GCM_16_128" in upper or "AES128GCM16" in upper:
        encryption = "AES-128-GCM"
    elif "AES_CBC_256" in upper or "AES256-SHA256" in upper:
        encryption = "AES-256-CBC"
    if "HMAC_SHA2_256" in upper or "SHA256" in upper:
        integrity = "HMAC-SHA-256"
    if "ECP_384" in upper or "ECP384" in upper:
        dh_group = "ECP-384"
    elif "ECP_256" in upper or "ECP256" in upper:
        dh_group = "ECP-256"
    return {"encryption": encryption, "integrity": integrity, "dh_group": dh_group}


def load_controlled_evidence(directory: Path, capture_name: str) -> tuple[dict[str, Any], dict[str, Any] | None, tuple[Evidence, ...]]:
    unavailable = {"available": False, "source": "none"}
    truth_path = directory / "ground_truth.json"
    verification_path = directory / "verification.json"
    if not truth_path.is_file() or not verification_path.is_file():
        return unavailable, None, ()
    try:
        truth = json.loads(truth_path.read_text(encoding="utf-8"))
        verification = json.loads(verification_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return unavailable, None, ()
    capture = truth.get("capture", {})
    accepted = {capture.get("full_evidence_file"), capture.get("ml_input_file")}
    if truth.get("status") != "PASS" or verification.get("status") != "PASS" or capture_name not in accepted:
        return unavailable, None, ()
    ipsec = truth.get("ipsec", {})
    configured = ipsec.get("configured", {})
    observed = ipsec.get("observed", {})
    configured_proposal = str(configured.get("esp_proposal", "UNKNOWN"))
    observed_proposal = str(observed.get("esp_proposal", "UNKNOWN"))
    pfs_observed = observed.get("pfs", {})
    pfs_state = "unknown"
    pfs_provenance = "UNKNOWN"
    evidence: list[Evidence] = [Evidence(
        "ev-lab-config-001", "OBSERVED",
        f"Controlled run configuration recorded scenario {ipsec.get('scenario_id', 'UNKNOWN')}",
        raw_value=configured, normalized_value=_normalize_proposal(configured_proposal),
        source_component="controlled-lab-artifacts",
    )]
    pfs_status = pfs_observed.get("status")
    verified_enabled = configured.get("pfs") is True and pfs_status == "VERIFIED"
    verified_disabled = configured.get("pfs") is False and pfs_status == "VERIFIED_DISABLED"
    if verified_enabled or verified_disabled:
        pfs_state = "enabled" if verified_enabled else "disabled"
        pfs_provenance = "DERIVED"
        evidence.append(Evidence(
            "ev-lab-pfs-001", "DERIVED",
            f"Controlled strongSwan/XFRM rekey evidence verified CHILD-SA PFS {pfs_state}",
            raw_value=pfs_observed.get("evidence", []), normalized_value=pfs_state,
            source_component="controlled-lab-artifacts",
        ))
    controlled = {
        "available": True, "source": "controlled-lab-artifacts",
        "run_id": truth.get("run_id", "UNKNOWN"),
        "scenario_id": ipsec.get("scenario_id", "UNKNOWN"),
        "configured": {**configured, "normalized_esp": _normalize_proposal(configured_proposal)},
        "observed": {**observed, "normalized_esp": _normalize_proposal(observed_proposal)},
        "verification_status": verification.get("status"),
        "capture_provenance": capture.get("ml_provenance", "NATIVE_ESP_WORKLOAD_WINDOW"),
        "normalization": capture.get("normalization"),
    }
    pfs = {
        "state": pfs_state, "provenance": pfs_provenance,
        "evidence_ids": ["ev-lab-pfs-001"] if pfs_state != "unknown" else [],
        "explanation": (
            "Controlled strongSwan/XFRM CHILD-SA rekey evidence was supplied."
            if pfs_state != "unknown" else "Controlled artifacts did not verify CHILD-SA DH behavior."
        ),
    }
    return controlled, pfs, tuple(evidence)
