from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import subprocess
import unittest

from ipsec_sentinel.capture import (
    CaptureValidationError,
    validate_pcap,
    validate_wire_cleartext,
)


FIXTURES = Path(__file__).parent / "fixtures"
PEERS = ("192.0.2.1", "192.0.2.2")
FULL_WINDOW = (0.0, 4_000_000_000.0)


class CaptureValidationTest(unittest.TestCase):
    def validate(self, fixture: str, peers: tuple[str, str] = PEERS):
        return validate_pcap(
            FIXTURES / fixture,
            peers=peers,
            started_at=FULL_WINDOW[0],
            ended_at=FULL_WINDOW[1],
        )

    def test_accepts_only_peer_matched_ike_and_native_esp(self) -> None:
        evidence = self.validate("ike-esp.pcap")

        self.assertEqual(evidence.pcap, "ike-esp.pcap")
        self.assertEqual(evidence.packet_count, 14)
        self.assertEqual(evidence.ike_packets, 4)
        self.assertEqual(evidence.esp_packets, 10)
        self.assertEqual(evidence.natt_packets, 0)
        self.assertEqual(evidence.cleartext_packets, 0)

    def test_rejects_empty_input(self) -> None:
        with TemporaryDirectory() as directory:
            empty = Path(directory) / "empty.pcap"
            empty.write_bytes(b"")

            with self.assertRaisesRegex(CaptureValidationError, "empty"):
                validate_pcap(empty, peers=PEERS, started_at=0, ended_at=1)

    def test_rejects_ike_without_esp(self) -> None:
        with self.assertRaisesRegex(CaptureValidationError, "ESP"):
            self.validate("ike-only.pcap")

    def test_rejects_esp_without_ike(self) -> None:
        with self.assertRaisesRegex(CaptureValidationError, "IKE"):
            self.validate("esp-only.pcap")

    def test_rejects_packets_from_different_peers(self) -> None:
        with self.assertRaisesRegex(CaptureValidationError, "peer"):
            self.validate("ike-esp.pcap", peers=("198.51.100.1", "198.51.100.2"))

    def test_rejects_udp_4500_nat_t(self) -> None:
        with self.assertRaisesRegex(CaptureValidationError, "NAT-T"):
            self.validate("natt.pcap")

    def test_rejects_protected_cleartext_icmp(self) -> None:
        with self.assertRaisesRegex(CaptureValidationError, "cleartext"):
            self.validate("cleartext-icmp.pcap")

    def test_rejects_packets_outside_the_run_window(self) -> None:
        with self.assertRaisesRegex(CaptureValidationError, "window"):
            validate_pcap(
                FIXTURES / "ike-esp.pcap",
                peers=PEERS,
                started_at=4_000_000_000,
                ended_at=4_000_000_100,
            )

    def test_cleartext_audit_requires_same_inner_packet_on_both_transit_endpoints(self) -> None:
        one_sided = validate_wire_cleartext(
            FIXTURES / "cleartext-icmp.pcap",
            FIXTURES / "ike-esp.pcap",
            started_at=FULL_WINDOW[0],
            ended_at=FULL_WINDOW[1],
        )
        self.assertEqual(one_sided, 0)

        with self.assertRaisesRegex(CaptureValidationError, "both transit endpoints"):
            validate_wire_cleartext(
                FIXTURES / "cleartext-icmp.pcap",
                FIXTURES / "cleartext-icmp.pcap",
                started_at=FULL_WINDOW[0],
                ended_at=FULL_WINDOW[1],
            )

    def test_pcap_reader_timeout_is_a_validation_failure(self) -> None:
        with patch(
            "ipsec_sentinel.capture.subprocess.run",
            side_effect=subprocess.TimeoutExpired(["tcpdump"], 5),
        ):
            with self.assertRaisesRegex(CaptureValidationError, "timed out"):
                self.validate("ike-esp.pcap")


if __name__ == "__main__":
    unittest.main()
