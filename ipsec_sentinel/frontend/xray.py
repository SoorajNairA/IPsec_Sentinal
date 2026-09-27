from __future__ import annotations

from pathlib import Path
from typing import Sequence

from ipsec_sentinel.analyzer.capture import parse_capture
from ipsec_sentinel.analyzer.esp import EspObservation, analyze_esp


XRAY_SCHEMA_ID = "ipsec-sentinel.xray/v1"
XRAY_VERSION = "1.0"


def _evenly_select(indices: Sequence[int], count: int) -> set[int]:
    if count <= 0 or not indices:
        return set()
    if count >= len(indices):
        return set(indices)
    if count == 1:
        return {indices[len(indices) // 2]}
    return {
        indices[round(position * (len(indices) - 1) / (count - 1))]
        for position in range(count)
    }


def _temporally_select(
    indices: Sequence[int],
    observations: Sequence[EspObservation],
    count: int,
) -> set[int]:
    if count <= 0 or not indices:
        return set()
    if count >= len(indices):
        return set(indices)
    first_time = observations[indices[0]].relative_time_seconds
    last_time = observations[indices[-1]].relative_time_seconds
    duration = last_time - first_time
    if duration <= 0:
        return _evenly_select(indices, count)

    buckets: list[list[int]] = [[] for _ in range(count)]
    for index in indices:
        offset = observations[index].relative_time_seconds - first_time
        bucket = min(count - 1, int(offset / duration * count))
        buckets[bucket].append(index)
    selected = {bucket[len(bucket) // 2] for bucket in buckets if bucket}
    remaining = count - len(selected)
    if remaining:
        candidates = [index for index in indices if index not in selected]
        selected.update(_evenly_select(candidates, remaining))
    return selected


def _sample_indices(observations: Sequence[EspObservation], max_points: int) -> list[int]:
    if max_points < 4:
        raise ValueError("max_points must be at least 4")
    count = len(observations)
    if count <= max_points:
        return list(range(count))

    minimum = min(range(count), key=lambda index: observations[index].length)
    maximum = max(range(count), key=lambda index: observations[index].length)
    selected = {0, count - 1, minimum, maximum}
    remaining = max_points - len(selected)
    if remaining <= 0:
        return sorted(selected)
    candidates = [index for index in range(count) if index not in selected]
    temporal_budget = max(1, remaining // 2)
    selected.update(_temporally_select(candidates, observations, temporal_budget))

    direction_edges = sorted({
        edge
        for index in range(1, count)
        if observations[index - 1].direction != observations[index].direction
        for edge in (index - 1, index)
    } - selected)
    remaining = max_points - len(selected)
    selected.update(_evenly_select(direction_edges, min(remaining, len(direction_edges))))

    remaining = max_points - len(selected)
    candidates = [index for index in range(count) if index not in selected]
    selected.update(_temporally_select(candidates, observations, remaining))
    return sorted(selected)


def build_xray_projection(
    path: Path,
    *,
    max_points: int = 1_500,
) -> dict[str, object]:
    """Project observable ESP timing, size, and direction for visualization."""

    esp, observations, _ = analyze_esp(parse_capture(Path(path)))
    indices = _sample_indices(observations, max_points) if observations else []
    packets = [
        {
            "relative_time_seconds": observations[index].relative_time_seconds,
            "length": observations[index].length,
            "direction": observations[index].direction,
        }
        for index in indices
    ]
    return {
        "schema_id": XRAY_SCHEMA_ID,
        "version": XRAY_VERSION,
        "total_packet_count": len(observations),
        "displayed_packet_count": len(packets),
        "sampled": len(packets) != len(observations),
        "duration_seconds": float(esp["duration_seconds"]),
        "peer_pair": esp["peer_pair"],
        "packets": packets,
    }
