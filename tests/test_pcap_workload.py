from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from ipsec_sentinel.dataset.models import WorkloadWindow
from ipsec_sentinel.pcap import PcapFormatError, derive_workload_esp, inspect_ml_pcap
from tests.pcap_helpers import ethernet_ipv4, write_pcap


class WorkloadPcapTest(unittest.TestCase):
    def test_derives_only_peer_esp_inside_inclusive_window(self) -> None:
        with TemporaryDirectory() as directory:
            source = Path(directory) / "full-evidence.pcap"
            output = Path(directory) / "encrypted.pcap"
            write_pcap(
                source,
                [
                    (
                        999_999_999,
                        ethernet_ipv4("192.0.2.1", "192.0.2.2", 50, b"before"),
                    ),
                    (
                        1_000_000_000,
                        ethernet_ipv4("192.0.2.1", "192.0.2.2", 50, b"start"),
                    ),
                    (
                        1_100_000_000,
                        ethernet_ipv4("192.0.2.1", "192.0.2.2", 17, b"ike"),
                    ),
                    (
                        2_000_000_000,
                        ethernet_ipv4("192.0.2.2", "192.0.2.1", 50, b"end"),
                    ),
                    (
                        2_000_000_001,
                        ethernet_ipv4(
                            "192.0.2.1", "192.0.2.2", 50, b"rekey-period"
                        ),
                    ),
                ],
                nanoseconds=True,
            )
            window = WorkloadWindow(1_000_000_000, 2_000_000_000)
            summary = derive_workload_esp(
                source, output, window, peers=("192.0.2.1", "192.0.2.2")
            )
            self.assertEqual(summary.packet_count, 2)
            self.assertEqual(
                inspect_ml_pcap(
                    output, window, ("192.0.2.1", "192.0.2.2")
                ).packet_count,
                2,
            )

    def test_supports_big_endian_microseconds_and_vlan(self) -> None:
        with TemporaryDirectory() as directory:
            source = Path(directory) / "source.pcap"
            output = Path(directory) / "output.pcap"
            frame = ethernet_ipv4(
                "192.0.2.1", "192.0.2.2", 50, b"esp", vlan=True
            )
            write_pcap(
                source,
                [(1_500_000_000, frame)],
                nanoseconds=False,
                big_endian=True,
            )
            summary = derive_workload_esp(
                source,
                output,
                WorkloadWindow(1_000_000_000, 2_000_000_000),
                ("192.0.2.1", "192.0.2.2"),
            )
            self.assertEqual(summary.packet_count, 1)

    def test_rejects_unsupported_link_type_and_truncated_record(self) -> None:
        with TemporaryDirectory() as directory:
            bad = Path(directory) / "bad.pcap"
            write_pcap(bad, [], link_type=113)
            with self.assertRaisesRegex(PcapFormatError, "link type"):
                derive_workload_esp(
                    bad,
                    Path(directory) / "out.pcap",
                    WorkloadWindow(1, 2),
                    ("192.0.2.1", "192.0.2.2"),
                )
            truncated = Path(directory) / "truncated.pcap"
            write_pcap(truncated, [])
            truncated.write_bytes(truncated.read_bytes() + b"\x00\x01")
            with self.assertRaises(PcapFormatError):
                inspect_ml_pcap(
                    truncated,
                    WorkloadWindow(1, 2),
                    ("192.0.2.1", "192.0.2.2"),
                )

    def test_rejects_wrong_peer_and_out_of_window_packets_in_ml_capture(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "wrong-peer.pcap"
            write_pcap(
                path,
                [
                    (
                        1_500_000_000,
                        ethernet_ipv4("198.51.100.1", "198.51.100.2", 50, b"esp"),
                    )
                ],
            )
            with self.assertRaisesRegex(PcapFormatError, "peer"):
                inspect_ml_pcap(
                    path,
                    WorkloadWindow(1_000_000_000, 2_000_000_000),
                    ("192.0.2.1", "192.0.2.2"),
                )


if __name__ == "__main__":
    unittest.main()
