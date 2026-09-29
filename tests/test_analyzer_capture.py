from pathlib import Path
from tempfile import TemporaryDirectory
import struct
import unittest

from ipsec_sentinel.analyzer.capture import CaptureError, parse_capture
from tests.pcap_helpers import ethernet_ipv4, write_pcap


def udp(source: int, destination: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", source, destination, 8 + len(payload), 0) + payload


class AnalyzerCaptureTest(unittest.TestCase):
    def test_missing_empty_and_malformed_capture_are_structured_errors(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for path, message in (
                (root / "missing.pcap", "does not exist"),
                (root / "empty.pcap", "empty"),
                (root / "bad.pcap", "unsupported or truncated"),
            ):
                if path.name == "empty.pcap":
                    path.write_bytes(b"")
                elif path.name == "bad.pcap":
                    path.write_bytes(b"not a pcap")
                with self.subTest(path=path.name):
                    with self.assertRaisesRegex(CaptureError, message):
                        parse_capture(path)

    def test_non_ipsec_capture_is_read_once_and_timestamp_normalized(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "plain.pcap"
            write_pcap(path, [
                (2_000_000_000, ethernet_ipv4("10.0.0.1", "10.0.0.2", 17, udp(9, 9, b"b"))),
                (1_000_000_000, ethernet_ipv4("10.0.0.2", "10.0.0.1", 17, udp(9, 9, b"a"))),
            ])
            capture = parse_capture(path)
            self.assertEqual(capture.packet_count, 2)
            self.assertEqual([p.number for p in capture.packets], [2, 1])
            self.assertEqual(capture.first_timestamp_ns, 1_000_000_000)
            self.assertIn("timestamps normalized", capture.warnings)

    def test_empty_valid_pcap_is_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "empty-valid.pcap"
            write_pcap(path, [])
            with self.assertRaisesRegex(CaptureError, "zero packets"):
                parse_capture(path)

    def test_pcapng_is_detected_without_misparsing(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "capture.pcapng"
            path.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 24)
            with self.assertRaisesRegex(CaptureError, "PCAPNG"):
                parse_capture(path)


if __name__ == "__main__":
    unittest.main()
