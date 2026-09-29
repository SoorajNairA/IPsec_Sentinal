from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
import csv
import hashlib

from ipsec_sentinel.artifacts import write_json_atomic


SPLIT_SCHEMA_VERSION = "ipsec-sentinel.session-split/v1"


@dataclass(frozen=True)
class SplitBuild:
    path: Path
    assignments: tuple[dict[str, str], ...]
    source_sha256: str


def _stable_order(session_id: str, seed: int) -> str:
    return hashlib.sha256(f"{seed}:{session_id}".encode("utf-8")).hexdigest()


def _counts(size: int) -> tuple[int, int, int]:
    if size <= 0:
        return 0, 0, 0
    if size == 1:
        return 1, 0, 0
    if size == 2:
        return 1, 0, 1
    if size < 6:
        return size - 2, 1, 1
    train = min(size - 2, max(1, round(size * 0.70)))
    remainder = size - train
    validation = max(1, remainder // 2)
    test = remainder - validation
    return train, validation, test


def build_grouped_split(
    features_csv: Path,
    destination: Path,
    *,
    seed: int,
) -> SplitBuild:
    source = features_csv.read_bytes()
    source_digest = hashlib.sha256(source).hexdigest()
    with features_csv.open(newline="", encoding="utf-8") as input_file:
        reader = csv.DictReader(input_file)
        required = {"session_id", "label", "scenario_id"}
        if reader.fieldnames is None or not required.issubset(reader.fieldnames):
            raise ValueError("feature table lacks split metadata columns")
        rows = list(reader)
    if not rows:
        raise ValueError("cannot split an empty feature table")
    session_ids = [row["session_id"] for row in rows]
    if len(session_ids) != len(set(session_ids)):
        raise ValueError("feature table contains duplicate session_id values")

    strata: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        strata[(row["label"], row["scenario_id"])].append(row)
    assignments: list[dict[str, str]] = []
    for stratum in sorted(strata):
        ordered = sorted(
            strata[stratum], key=lambda row: _stable_order(row["session_id"], seed)
        )
        train_count, validation_count, _ = _counts(len(ordered))
        for index, row in enumerate(ordered):
            if index < train_count:
                split = "train"
            elif index < train_count + validation_count:
                split = "validation"
            else:
                split = "test"
            assignments.append(
                {
                    "session_id": row["session_id"],
                    "label": row["label"],
                    "scenario_id": row["scenario_id"],
                    "split": split,
                }
            )
    assignments.sort(key=lambda item: item["session_id"])
    payload = {
        "schema_version": SPLIT_SCHEMA_VERSION,
        "source_sha256": source_digest,
        "seed": seed,
        "group_key": "session_id",
        "stratification": ["label", "scenario_id"],
        "assignments": assignments,
    }
    write_json_atomic(destination, payload)
    return SplitBuild(destination, tuple(assignments), source_digest)
