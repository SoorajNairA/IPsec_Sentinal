from __future__ import annotations

from typing import Any


RULE_IDS = (
    "IPSEC-IKE-001", "IPSEC-IKE-002", "IPSEC-IKE-003", "IPSEC-CRYPTO-001",
    "IPSEC-CRYPTO-002", "IPSEC-CRYPTO-003", "IPSEC-INTEGRITY-001",
    "IPSEC-DH-001", "IPSEC-DH-002", "IPSEC-PFS-001", "IPSEC-PFS-002",
    "IPSEC-PFS-003", "IPSEC-REKEY-001", "IPSEC-REPLAY-001",
    "IPSEC-METADATA-001", "IPSEC-ML-001",
    "IPSEC-EVIDENCE-001",
)


def _finding(rule_id: str, title: str, severity: str, status: str, provenance: str,
             summary: str, explanation: str, impact: str, recommendation: str,
             evidence_ids: list[str]) -> dict[str, Any]:
    return {
        "rule_id": rule_id, "title": title, "severity": severity, "status": status,
        "provenance": provenance, "summary": summary,
        "technical_explanation": explanation, "impact": impact,
        "recommendation": recommendation, "evidence_ids": evidence_ids,
    }


def assess_security(context: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    ike = context.get("ike", {})
    findings: list[dict[str, Any]] = []
    deductions: dict[str, list[dict[str, Any]]] = {
        "Cryptography": [], "Key Exchange / PFS": [],
        "Security Association Hygiene": [], "Replay / Protocol Protections": [],
        "Metadata / Privacy Exposure": [],
    }
    assessed = {name: 0 for name in deductions}
    maximum = {
        "Cryptography": 30, "Key Exchange / PFS": 25,
        "Security Association Hygiene": 15, "Replay / Protocol Protections": 15,
        "Metadata / Privacy Exposure": 15,
    }

    version = ike.get("version", "UNKNOWN")
    if version == "IKEv2":
        findings.append(_finding("IPSEC-IKE-001", "Modern IKE version", "INFO", "PASS", "OBSERVED", "IKEv2 is present.", "The observed header identifies IKEv2.", "No legacy-version concern was observed.", "Continue using IKEv2.", ["ev-ike-version-001"]))
        assessed["Replay / Protocol Protections"] += 5
    elif version == "IKEv1":
        assessed["Replay / Protocol Protections"] += 5
        findings.append(_finding("IPSEC-IKE-002", "Legacy IKE version", "HIGH", "FAIL", "OBSERVED", "IKEv1 was observed.", "The packet header identifies legacy IKEv1 rather than IKEv2.", "Legacy negotiation has a larger compatibility and attack surface.", "Migrate the peers to IKEv2.", ["ev-ike-version-001"]))
        deductions["Replay / Protocol Protections"].append({"rule_id": "IPSEC-IKE-002", "points": 5, "evidence_ids": ["ev-ike-version-001"]})
    else:
        findings.append(_finding("IPSEC-IKE-003", "IKE version unassessed", "INFO", "UNKNOWN", "UNKNOWN", "IKE version could not be established.", "The capture lacks sufficient clear IKE header evidence.", "Protocol-version posture is unassessed.", "Provide IKE establishment packets.", []))

    encryption = ike.get("encryption", {})
    cipher = encryption.get("normalized", "UNKNOWN")
    cipher_ev = [encryption["evidence_id"]] if encryption.get("evidence_id") else []
    if cipher in ("AES-256-GCM", "AES-128-GCM"):
        assessed["Cryptography"] += 20
        findings.append(_finding("IPSEC-CRYPTO-001", "Modern AEAD encryption", "INFO", "PASS", encryption.get("provenance", "OBSERVED"), f"{cipher} was selected.", "GCM provides authenticated encryption.", "A modern cipher protects confidentiality and integrity.", "Retain an approved GCM configuration.", cipher_ev))
    elif cipher.endswith("-CBC"):
        assessed["Cryptography"] += 20
        findings.append(_finding("IPSEC-CRYPTO-002", "CBC encryption requires separate integrity", "LOW", "REVIEW", encryption.get("provenance", "OBSERVED"), f"{cipher} was selected.", "CBC is not AEAD and depends on a separate integrity transform.", "Misconfiguration can weaken protection.", "Prefer GCM where interoperability permits.", cipher_ev))
        deductions["Cryptography"].append({"rule_id": "IPSEC-CRYPTO-002", "points": 3, "evidence_ids": cipher_ev})
    elif cipher != "UNKNOWN":
        assessed["Cryptography"] += 20
        findings.append(_finding("IPSEC-CRYPTO-003", "Unrecognized or legacy encryption", "HIGH", "FAIL", encryption.get("provenance", "OBSERVED"), f"Observed encryption is {cipher}.", "The transform is outside the approved modern set.", "Confidentiality may be weak.", "Use AES-GCM or an approved equivalent.", cipher_ev))
        deductions["Cryptography"].append({"rule_id": "IPSEC-CRYPTO-003", "points": 15, "evidence_ids": cipher_ev})

    integrity = ike.get("integrity", {})
    if integrity.get("normalized") == "HMAC-SHA-256":
        assessed["Cryptography"] += 10
        ev = [integrity["evidence_id"]] if integrity.get("evidence_id") else []
        findings.append(_finding("IPSEC-INTEGRITY-001", "Strong separate integrity", "INFO", "PASS", integrity.get("provenance", "OBSERVED"), "HMAC-SHA-256 was selected.", "SHA-2 HMAC is a modern integrity transform.", "Packet integrity is strongly protected.", "Retain SHA-2 HMAC where CBC is used.", ev))
    elif cipher and cipher.endswith("-GCM"):
        assessed["Cryptography"] += 10

    dh = ike.get("dh_group", {})
    dh_value = dh.get("normalized", "UNKNOWN")
    dh_ev = [dh["evidence_id"]] if dh.get("evidence_id") else []
    if dh_value in ("ECP-384", "ECP-256"):
        assessed["Key Exchange / PFS"] += 10
        findings.append(_finding("IPSEC-DH-001", "Modern key-exchange group", "INFO", "PASS", dh.get("provenance", "OBSERVED"), f"{dh_value} was selected for the observable IKE exchange.", "The observed ECP group is modern.", "IKE key establishment uses a strong group.", "Retain an approved ECP group.", dh_ev))
    elif dh_value != "UNKNOWN":
        assessed["Key Exchange / PFS"] += 10
        findings.append(_finding("IPSEC-DH-002", "Legacy or unrecognized key-exchange group", "HIGH", "FAIL", dh.get("provenance", "OBSERVED"), f"Observed group is {dh_value}.", "The group is outside the preferred ECP set.", "Key-exchange strength may be reduced.", "Use ECP-256 or ECP-384.", dh_ev))
        deductions["Key Exchange / PFS"].append({"rule_id": "IPSEC-DH-002", "points": 7, "evidence_ids": dh_ev})

    pfs = context.get("pfs", {"state": "unknown", "provenance": "UNKNOWN", "evidence_ids": []})
    pfs_ids = list(pfs.get("evidence_ids", []))
    if pfs.get("state") == "enabled":
        assessed["Key Exchange / PFS"] += 15
        findings.append(_finding("IPSEC-PFS-001", "CHILD-SA PFS verified", "INFO", "PASS", pfs.get("provenance", "DERIVED"), "Fresh CHILD-SA DH behavior verifies PFS.", "The evidence establishes a new DH exchange for CHILD-SA keying.", "Past session keys do not expose rekeyed traffic.", "Retain CHILD-SA PFS.", pfs_ids))
    elif pfs.get("state") == "disabled":
        assessed["Key Exchange / PFS"] += 15
        findings.append(_finding("IPSEC-PFS-002", "CHILD-SA PFS disabled", "MEDIUM", "FAIL", pfs.get("provenance", "DERIVED"), "Controlled evidence verifies no CHILD-SA DH/PFS.", "Rekeying occurs without a fresh CHILD-SA DH exchange.", "Compromise of keying material has a broader retrospective impact.", "Enable a supported CHILD-SA DH group.", pfs_ids))
        deductions["Key Exchange / PFS"].append({"rule_id": "IPSEC-PFS-002", "points": 10, "evidence_ids": pfs_ids})
    else:
        findings.append(_finding("IPSEC-PFS-003", "CHILD-SA PFS unknown", "INFO", "UNKNOWN", "UNKNOWN", "Passive evidence does not establish CHILD-SA PFS.", "Rekey or IKE-SA DH alone is not proof of CHILD-SA PFS.", "PFS posture remains unassessed.", "Supply controlled rekey evidence if verification is required.", []))

    rekeys = [sa for sa in context.get("security_associations", []) if sa.get("successor_spi")]
    if rekeys:
        assessed["Security Association Hygiene"] += 10
        ev_ids = [item.get("rekey_evidence_id") for item in rekeys if item.get("rekey_evidence_id")]
        findings.append(_finding("IPSEC-REKEY-001", "ESP SPI replacement observed", "INFO", "PASS", "DERIVED", "An ESP SA replacement sequence was reconstructed.", "A later SPI superseded an earlier SPI in the same direction.", "SA renewal behavior is present, but does not itself prove PFS.", "Retain healthy rekey policy.", ev_ids))

    controlled = context.get("controlled_evidence", {})
    if controlled.get("available"):
        runtime_cipher = controlled.get("observed", {}).get("normalized_esp", {}).get("encryption", "UNKNOWN")
        packet_cipher = encryption.get("normalized", "UNKNOWN")
        if runtime_cipher != "UNKNOWN" and packet_cipher != "UNKNOWN":
            assessed["Security Association Hygiene"] += 5
            if runtime_cipher != packet_cipher:
                mismatch_ids = [identifier for identifier in (encryption.get("evidence_id"), "ev-lab-config-001") if identifier]
                findings.append(_finding("IPSEC-EVIDENCE-001", "Packet and controlled runtime evidence disagree", "MEDIUM", "FAIL", "DERIVED", f"Packet evidence reports {packet_cipher}; controlled runtime reports {runtime_cipher}.", "Two independently sourced observations identify different selected encryption transforms.", "The capture and supplied run artifacts may not represent the same session or a parser may be incomplete.", "Verify artifact pairing and negotiation evidence before relying on the assessment.", mismatch_ids))
                deductions["Security Association Hygiene"].append({"rule_id": "IPSEC-EVIDENCE-001", "points": 5, "evidence_ids": mismatch_ids})

    findings.append(_finding("IPSEC-REPLAY-001", "Replay protection unassessed", "INFO", "UNKNOWN", "UNKNOWN", "Replay-window enforcement is not visible in a passive capture.", "Packet sequence values do not prove receiver enforcement.", "Replay-protection posture remains unassessed.", "Use endpoint runtime evidence for verification.", []))
    assessed["Metadata / Privacy Exposure"] = 15
    findings.append(_finding("IPSEC-METADATA-001", "Encrypted metadata remains visible", "INFO", "INFORMATIONAL", "OBSERVED" if context.get("esp", {}).get("packet_count") else "UNKNOWN", "ESP conceals payload but exposes timing, sizes, direction, and duration.", "Traffic analysis can use these observable properties without decryption.", "An observer may infer application behavior.", "Use padding or traffic-flow confidentiality where the threat model requires it.", ["ev-esp-statistics-001"] if context.get("esp", {}).get("packet_count") else []))
    if context.get("traffic_intelligence", {}).get("state") in ("PREDICTED", "LOW_CONFIDENCE"):
        findings.append(_finding("IPSEC-ML-001", "Traffic type inferred from encrypted metadata", "INFO", "INFORMATIONAL", "AI_INFERRED", "The prototype model inferred an application class without decryption.", "Inference uses only ESP timing, length, and direction features.", "Payload confidentiality does not eliminate traffic-analysis exposure.", "Treat low confidence and controlled-testbed scope explicitly.", ["ev-traffic-inference-001"]))

    categories = []
    for name, max_score in maximum.items():
        points = sum(int(item["points"]) for item in deductions[name])
        assessed_score = assessed[name]
        categories.append({
            "name": name, "maximum_score": max_score,
            "achieved_score": max(0, assessed_score - points),
            "assessed_weight": assessed_score,
            "unassessed_weight": max_score - assessed_score,
            "deductions": deductions[name],
        })
    assessed_total = sum(item["assessed_weight"] for item in categories)
    achieved_total = sum(item["achieved_score"] for item in categories)
    score = {
        "total": 0 if assessed_total == 0 else round(100 * achieved_total / assessed_total),
        "maximum": 100, "assessed_weight": assessed_total,
        "unassessed_weight": 100 - assessed_total, "categories": categories,
        "method": "normalized over assessed evidence; UNKNOWN is not penalized",
    }
    return findings, score
