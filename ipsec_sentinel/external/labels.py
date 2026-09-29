from __future__ import annotations

from dataclasses import dataclass

from ipsec_sentinel.external.registry import ExternalDatasetRegistry


OOD_CANDIDATE_LABELS = frozenset(
    {"p2p", "ssh", "rdp", "c2", "unknown terminal traffic", "database", "gaming", "tor"}
)


@dataclass(frozen=True)
class LabelDecision:
    source_id: str
    original_label: str
    canonical_label: str | None
    status: str
    known_training_class: bool
    reason: str


def map_external_label(
    source_id: str,
    original_label: str,
    registry: ExternalDatasetRegistry,
) -> LabelDecision:
    source = registry.source(source_id)
    mappings = dict(source.label_mappings)
    if original_label in mappings:
        return LabelDecision(
            source_id,
            original_label,
            mappings[original_label],
            "mapped_supervised",
            True,
            "exact source-specific registry mapping",
        )
    status = (
        "ood_candidate"
        if original_label.casefold() in OOD_CANDIDATE_LABELS
        else "unmapped"
    )
    return LabelDecision(
        source_id,
        original_label,
        None,
        status,
        False,
        "no exact source-specific supervised mapping",
    )

