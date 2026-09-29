from __future__ import annotations

from typing import Any

from ipsec_sentinel.analyzer.models import PROVENANCE


ANALYSIS_SCHEMA_ID = "ipsec-sentinel.analysis/v1"
REQUIRED_FIELDS = (
    "analysis_version", "schema_id", "capture", "summary", "peers", "protocols",
    "ike", "controlled_evidence", "security_associations", "esp", "traffic_intelligence", "evidence",
    "findings", "security_score", "limitations",
)


def validate_analysis(result: dict[str, Any]) -> None:
    missing = [field for field in REQUIRED_FIELDS if field not in result]
    if missing:
        raise ValueError(f"analysis missing required fields: {', '.join(missing)}")
    if result["analysis_version"] != "1.0" or result["schema_id"] != ANALYSIS_SCHEMA_ID:
        raise ValueError("unsupported analysis schema version")
    if not isinstance(result["evidence"], list) or not isinstance(result["findings"], list):
        raise ValueError("evidence and findings must be arrays")
    identifiers: set[str] = set()
    for item in result["evidence"]:
        if item.get("provenance") not in PROVENANCE:
            raise ValueError("evidence contains invalid provenance")
        identifier = item.get("id")
        if not isinstance(identifier, str) or not identifier or identifier in identifiers:
            raise ValueError("evidence IDs must be unique nonempty strings")
        identifiers.add(identifier)
    for finding in result["findings"]:
        references = finding.get("evidence_ids")
        if not isinstance(references, list) or not set(references) <= identifiers:
            raise ValueError(f"finding {finding.get('rule_id')} has invalid evidence links")
    score = result["security_score"]
    if not 0 <= score.get("total", -1) <= score.get("maximum", 100) <= 100:
        raise ValueError("security score is outside bounds")
    if score.get("assessed_weight", 0) + score.get("unassessed_weight", 0) != 100:
        raise ValueError("security score weights must total 100")
