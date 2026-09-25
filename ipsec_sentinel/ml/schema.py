from __future__ import annotations


FEATURE_SCHEMA_VERSION = "ipsec-sentinel.esp-session-features/v1"

SIZE_STAT_NAMES = (
    "mean", "std", "min", "max", "median", "p10", "p25", "p75", "p90", "p95",
)
IAT_STAT_NAMES = SIZE_STAT_NAMES
SIZE_PREFIXES = ("size", "forward_size", "reverse_size")
IAT_PREFIXES = ("iat", "forward_iat", "reverse_iat")

FEATURE_NAMES = (
    "packet_count",
    "total_bytes",
    "duration_seconds",
    "packet_rate",
    "byte_rate",
    *(f"{prefix}_{stat}" for prefix in SIZE_PREFIXES for stat in SIZE_STAT_NAMES),
    *(f"{prefix}_{suffix}" for prefix in SIZE_PREFIXES for suffix in ("entropy", "unique_ratio")),
    *(f"{prefix}_{stat}" for prefix in IAT_PREFIXES for stat in IAT_STAT_NAMES),
    "size_bin_0_127_ratio",
    "size_bin_128_255_ratio",
    "size_bin_256_511_ratio",
    "size_bin_512_1023_ratio",
    "size_bin_1024_1279_ratio",
    "size_bin_1280_1517_ratio",
    "size_bin_1518_plus_ratio",
    "idle_gap_50ms_count",
    "idle_gap_50ms_ratio",
    "idle_gap_200ms_count",
    "idle_gap_200ms_ratio",
    "idle_gap_1000ms_count",
    "idle_gap_1000ms_ratio",
    "forward_packet_count",
    "reverse_packet_count",
    "forward_byte_count",
    "reverse_byte_count",
    "forward_packet_ratio",
    "reverse_packet_ratio",
    "forward_byte_ratio",
    "reverse_byte_ratio",
    "direction_switch_count",
    "direction_switch_ratio",
    "longest_direction_run_packets",
    "longest_direction_run_bytes",
    "burst_count",
    "burst_packet_mean",
    "burst_packet_std",
    "burst_packet_max",
    "burst_byte_mean",
    "burst_byte_std",
    "burst_byte_max",
    "burst_duration_mean",
    "burst_duration_max",
    "size_cv",
    "iat_cv",
    "size_lag1_autocorrelation",
    "iat_lag1_autocorrelation",
    "consecutive_same_size_ratio",
    "dominant_size_ratio",
)

if len(FEATURE_NAMES) != len(set(FEATURE_NAMES)):
    raise RuntimeError("feature schema contains duplicate names")
