from __future__ import annotations

from collections import Counter
import math
import statistics

from ipsec_sentinel.ml.schema import FEATURE_NAMES, IAT_STAT_NAMES, SIZE_STAT_NAMES
from ipsec_sentinel.pcap import EspPacket


def _percentile(values: list[float], percent: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    position = (len(ordered) - 1) * percent / 100
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    fraction = position - lower
    return float(ordered[lower] * (1 - fraction) + ordered[upper] * fraction)


def _stats(values: list[float], names: tuple[str, ...]) -> dict[str, float]:
    if not values:
        return {name: 0.0 for name in names}
    calculated = {
        "mean": statistics.fmean(values),
        "std": statistics.pstdev(values),
        "min": min(values),
        "max": max(values),
        "median": statistics.median(values),
        "p10": _percentile(values, 10),
        "p25": _percentile(values, 25),
        "p75": _percentile(values, 75),
        "p90": _percentile(values, 90),
        "p95": _percentile(values, 95),
    }
    return {name: float(calculated[name]) for name in names}


def _entropy(values: list[float]) -> float:
    if not values:
        return 0.0
    counts = Counter(values)
    total = len(values)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _autocorrelation(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = statistics.fmean(values)
    denominator = sum((value - mean) ** 2 for value in values)
    if denominator == 0:
        return 0.0
    numerator = sum(
        (left - mean) * (right - mean)
        for left, right in zip(values, values[1:])
    )
    return float(numerator / denominator)


def _coefficient_of_variation(values: list[float]) -> float:
    if not values:
        return 0.0
    mean = statistics.fmean(values)
    return 0.0 if mean == 0 else float(statistics.pstdev(values) / mean)


def _iats(packets: list[EspPacket]) -> list[float]:
    return [
        right.relative_time_seconds - left.relative_time_seconds
        for left, right in zip(packets, packets[1:])
    ]


def extract_session_features(packets: tuple[EspPacket, ...]) -> dict[str, float]:
    if not packets:
        raise ValueError("cannot extract features from an empty session")
    packet_list = list(packets)
    if any(packet.direction not in ("forward", "reverse") for packet in packet_list):
        raise ValueError("unsupported packet direction")
    if any(
        right.relative_time_seconds < left.relative_time_seconds
        for left, right in zip(packet_list, packet_list[1:])
    ):
        raise ValueError("packet times must be monotonic")

    result = {name: 0.0 for name in FEATURE_NAMES}
    sizes = [float(packet.length) for packet in packet_list]
    relative = [
        packet.relative_time_seconds - packet_list[0].relative_time_seconds
        for packet in packet_list
    ]
    duration = relative[-1]
    total_bytes = sum(sizes)
    result.update(
        packet_count=float(len(packet_list)),
        total_bytes=float(total_bytes),
        duration_seconds=float(duration),
        packet_rate=0.0 if duration == 0 else len(packet_list) / duration,
        byte_rate=0.0 if duration == 0 else total_bytes / duration,
    )

    directional: dict[str, list[EspPacket]] = {
        direction: [
            packet for packet in packet_list if packet.direction == direction
        ]
        for direction in ("forward", "reverse")
    }
    size_groups = {
        "size": sizes,
        "forward_size": [float(packet.length) for packet in directional["forward"]],
        "reverse_size": [float(packet.length) for packet in directional["reverse"]],
    }
    for prefix, values in size_groups.items():
        for name, value in _stats(values, SIZE_STAT_NAMES).items():
            result[f"{prefix}_{name}"] = value
        result[f"{prefix}_entropy"] = _entropy(values)
        result[f"{prefix}_unique_ratio"] = (
            0.0 if not values else len(set(values)) / len(values)
        )

    iat_groups = {
        "iat": [
            relative[index] - relative[index - 1]
            for index in range(1, len(relative))
        ],
        "forward_iat": _iats(directional["forward"]),
        "reverse_iat": _iats(directional["reverse"]),
    }
    for prefix, values in iat_groups.items():
        for name, value in _stats(values, IAT_STAT_NAMES).items():
            result[f"{prefix}_{name}"] = value

    bins = (
        (0, 127, "size_bin_0_127_ratio"),
        (128, 255, "size_bin_128_255_ratio"),
        (256, 511, "size_bin_256_511_ratio"),
        (512, 1023, "size_bin_512_1023_ratio"),
        (1024, 1279, "size_bin_1024_1279_ratio"),
        (1280, 1517, "size_bin_1280_1517_ratio"),
    )
    for lower, upper, name in bins:
        result[name] = sum(lower <= size <= upper for size in sizes) / len(sizes)
    result["size_bin_1518_plus_ratio"] = sum(size >= 1518 for size in sizes) / len(sizes)

    iats = iat_groups["iat"]
    for threshold, suffix in ((0.05, "50ms"), (0.2, "200ms"), (1.0, "1000ms")):
        count = sum(value > threshold for value in iats)
        result[f"idle_gap_{suffix}_count"] = float(count)
        result[f"idle_gap_{suffix}_ratio"] = 0.0 if not iats else count / len(iats)

    forward = directional["forward"]
    reverse = directional["reverse"]
    forward_bytes = sum(packet.length for packet in forward)
    reverse_bytes = sum(packet.length for packet in reverse)
    result.update(
        forward_packet_count=float(len(forward)),
        reverse_packet_count=float(len(reverse)),
        forward_byte_count=float(forward_bytes),
        reverse_byte_count=float(reverse_bytes),
        forward_packet_ratio=len(forward) / len(packet_list),
        reverse_packet_ratio=len(reverse) / len(packet_list),
        forward_byte_ratio=forward_bytes / total_bytes,
        reverse_byte_ratio=reverse_bytes / total_bytes,
    )
    switches = sum(
        left.direction != right.direction
        for left, right in zip(packet_list, packet_list[1:])
    )
    result["direction_switch_count"] = float(switches)
    result["direction_switch_ratio"] = (
        0.0 if len(packet_list) < 2 else switches / (len(packet_list) - 1)
    )

    runs: list[list[EspPacket]] = []
    bursts: list[list[EspPacket]] = []
    for packet in packet_list:
        if not runs or runs[-1][-1].direction != packet.direction:
            runs.append([packet])
        else:
            runs[-1].append(packet)
        if (
            not bursts
            or bursts[-1][-1].direction != packet.direction
            or packet.relative_time_seconds - bursts[-1][-1].relative_time_seconds > 0.1
        ):
            bursts.append([packet])
        else:
            bursts[-1].append(packet)
    result["longest_direction_run_packets"] = float(max(len(run) for run in runs))
    result["longest_direction_run_bytes"] = float(
        max(sum(packet.length for packet in run) for run in runs)
    )

    burst_packets = [float(len(burst)) for burst in bursts]
    burst_bytes = [float(sum(packet.length for packet in burst)) for burst in bursts]
    burst_durations = [
        burst[-1].relative_time_seconds - burst[0].relative_time_seconds
        for burst in bursts
    ]
    result.update(
        burst_count=float(len(bursts)),
        burst_packet_mean=statistics.fmean(burst_packets),
        burst_packet_std=statistics.pstdev(burst_packets),
        burst_packet_max=max(burst_packets),
        burst_byte_mean=statistics.fmean(burst_bytes),
        burst_byte_std=statistics.pstdev(burst_bytes),
        burst_byte_max=max(burst_bytes),
        burst_duration_mean=statistics.fmean(burst_durations),
        burst_duration_max=max(burst_durations),
    )
    size_counts = Counter(sizes)
    result.update(
        size_cv=_coefficient_of_variation(sizes),
        iat_cv=_coefficient_of_variation(iats),
        size_lag1_autocorrelation=_autocorrelation(sizes),
        iat_lag1_autocorrelation=_autocorrelation(iats),
        consecutive_same_size_ratio=(
            0.0 if len(sizes) < 2
            else sum(left == right for left, right in zip(sizes, sizes[1:]))
            / (len(sizes) - 1)
        ),
        dominant_size_ratio=max(size_counts.values()) / len(sizes),
    )
    return {name: float(result[name]) for name in FEATURE_NAMES}
