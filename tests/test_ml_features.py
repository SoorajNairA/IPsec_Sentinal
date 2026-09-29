from pathlib import Path
from tempfile import TemporaryDirectory
import math
import unittest

from ipsec_sentinel.dataset.models import WorkloadWindow
from ipsec_sentinel.ml.features import extract_session_features
from ipsec_sentinel.ml.schema import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from ipsec_sentinel.pcap import PcapFormatError, read_ml_esp_packets
from tests.pcap_helpers import ethernet_ipv4, write_pcap


PEERS = ("192.0.2.1", "192.0.2.2")


class MlFeatureTest(unittest.TestCase):
    def build_capture(
        self, root: Path, records: list[tuple[int, str, str, int]]
    ) -> Path:
        path = root / "encrypted.pcap"
        write_pcap(
            path,
            [
                (timestamp, ethernet_ipv4(source, destination, 50, b"x" * (size - 34)))
                for timestamp, source, destination, size in records
            ],
        )
        return path

    def test_reads_direction_and_extracts_hand_checked_statistics(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.build_capture(
                root,
                [
                    (1_000_000_000, PEERS[0], PEERS[1], 100),
                    (1_010_000_000, PEERS[0], PEERS[1], 200),
                    (1_200_000_000, PEERS[1], PEERS[0], 300),
                    (1_210_000_000, PEERS[0], PEERS[1], 400),
                ],
            )
            packets = read_ml_esp_packets(
                path, WorkloadWindow(900_000_000, 1_300_000_000), PEERS
            )

        self.assertEqual(
            [packet.direction for packet in packets],
            ["forward", "forward", "reverse", "forward"],
        )
        self.assertEqual([packet.length for packet in packets], [100, 200, 300, 400])
        self.assertEqual(
            [packet.relative_time_seconds for packet in packets],
            [0.0, 0.01, 0.2, 0.21],
        )

        features = extract_session_features(packets)
        self.assertEqual(tuple(features), FEATURE_NAMES)
        self.assertEqual(features["packet_count"], 4.0)
        self.assertEqual(features["total_bytes"], 1000.0)
        self.assertAlmostEqual(features["duration_seconds"], 0.21)
        self.assertEqual(features["size_mean"], 250.0)
        self.assertAlmostEqual(features["size_std"], math.sqrt(12_500))
        self.assertEqual(features["size_median"], 250.0)
        self.assertEqual(features["size_p10"], 130.0)
        self.assertEqual(features["size_p95"], 385.0)
        self.assertEqual(features["forward_packet_count"], 3.0)
        self.assertEqual(features["reverse_packet_count"], 1.0)
        self.assertEqual(features["direction_switch_count"], 2.0)
        self.assertEqual(features["longest_direction_run_packets"], 2.0)
        self.assertAlmostEqual(features["iat_mean"], 0.07)
        self.assertEqual(features["idle_gap_50ms_count"], 1.0)
        self.assertEqual(features["burst_count"], 3.0)
        self.assertEqual(features["burst_packet_max"], 2.0)

    def test_short_session_is_retained_with_defined_zero_features(self) -> None:
        with TemporaryDirectory() as directory:
            path = self.build_capture(
                Path(directory), [(1_000_000_000, PEERS[0], PEERS[1], 128)]
            )
            packets = read_ml_esp_packets(
                path, WorkloadWindow(1_000_000_000, 1_000_000_000), PEERS
            )
        features = extract_session_features(packets)
        self.assertEqual(features["packet_count"], 1.0)
        self.assertEqual(features["duration_seconds"], 0.0)
        self.assertEqual(features["packet_rate"], 0.0)
        self.assertEqual(features["iat_mean"], 0.0)
        self.assertEqual(features["size_lag1_autocorrelation"], 0.0)

    def test_empty_or_non_esp_capture_fails_closed(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            empty = root / "empty.pcap"
            write_pcap(empty, [])
            non_esp = root / "non-esp.pcap"
            write_pcap(
                non_esp,
                [(1_000_000_000, ethernet_ipv4(PEERS[0], PEERS[1], 17, b"x"))],
            )
            window = WorkloadWindow(900_000_000, 1_100_000_000)
            for path in (empty, non_esp):
                with self.subTest(path=path.name), self.assertRaises(PcapFormatError):
                    read_ml_esp_packets(path, window, PEERS)

    def test_schema_is_versioned_ordered_and_contains_no_forbidden_metadata(self) -> None:
        self.assertEqual(FEATURE_SCHEMA_VERSION, "ipsec-sentinel.esp-session-features/v1")
        self.assertEqual(len(FEATURE_NAMES), len(set(FEATURE_NAMES)))
        forbidden = (
            "label", "class", "scenario", "generator", "seed", "path", "file",
            "port", "run_id", "slot", "traffic", "workload", "absolute",
        )
        for name in FEATURE_NAMES:
            with self.subTest(feature=name):
                self.assertFalse(any(token in name for token in forbidden))


if __name__ == "__main__":
    unittest.main()
