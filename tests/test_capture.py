from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch
import signal
import subprocess
import unittest

from ipsec_sentinel.capture import (
    CaptureSession,
    CaptureValidationError,
    validate_capture_log,
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

    def test_capture_command_uses_explicit_buffer_for_bulk_workloads(self) -> None:
        session = CaptureSession(Path("bulk.pcap"), Path("tcpdump.log"))
        command = session.command()
        buffer_index = command.index("-B")
        self.assertEqual(command[buffer_index + 1], "32768")

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
        outer = [
            "IP 192.0.2.1.500 > 192.0.2.2.500: isakmp: parent_sa ikev2_init[I]",
            "IP 192.0.2.1 > 192.0.2.2: ESP(spi=0x1,seq=0x1), length 120",
        ]
        request = "IP 10.10.0.2 > 10.20.0.2: ICMP echo request, id 1, seq 1, length 64"
        reply = "IP 10.20.0.2 > 10.10.0.2: ICMP echo reply, id 1, seq 1, length 64"
        with patch(
            "ipsec_sentinel.capture._read_packets",
            side_effect=(outer + [reply], outer + [request]),
        ):
            self.assertEqual(
                validate_wire_cleartext(
                    Path("a.pcap"), Path("b.pcap"),
                    started_at=FULL_WINDOW[0], ended_at=FULL_WINDOW[1],
                ),
                0,
            )

        with patch(
            "ipsec_sentinel.capture._read_packets",
            side_effect=(outer + [request], outer + [request]),
        ):
            with self.assertRaisesRegex(CaptureValidationError, "both transit endpoints"):
                validate_wire_cleartext(
                    Path("a.pcap"), Path("b.pcap"),
                    started_at=FULL_WINDOW[0], ended_at=FULL_WINDOW[1],
                )

    def test_cleartext_audit_fails_closed_without_outer_observations(self) -> None:
        with patch(
            "ipsec_sentinel.capture._read_packets",
            side_effect=([], []),
        ):
            with self.assertRaisesRegex(CaptureValidationError, "outer IKE/ESP"):
                validate_wire_cleartext(
                    Path("a.pcap"), Path("b.pcap"),
                    started_at=FULL_WINDOW[0], ended_at=FULL_WINDOW[1],
                )

    def test_capture_log_rejects_kernel_drops(self) -> None:
        with TemporaryDirectory() as directory:
            log = Path(directory) / "tcpdump.log"
            log.write_text(
                "20 packets captured\n20 packets received by filter\n1 packet dropped by kernel\n"
            )
            with self.assertRaisesRegex(CaptureValidationError, "dropped"):
                validate_capture_log(log)

    def test_pcap_reader_timeout_is_a_validation_failure(self) -> None:
        with patch(
            "ipsec_sentinel.capture.subprocess.run",
            side_effect=subprocess.TimeoutExpired(["tcpdump"], 5),
        ):
            with self.assertRaisesRegex(CaptureValidationError, "timed out"):
                self.validate("ike-esp.pcap")

    def test_running_and_flush_are_repeatable_without_stopping_tcpdump(self) -> None:
        process = Mock()
        process.pid = 4132
        process.poll.return_value = None
        session = CaptureSession(Path("live.pcap"), Path("tcpdump.log"))
        session._process = process

        self.assertTrue(session.running)
        session.flush()
        session.flush()

        self.assertEqual(
            process.send_signal.call_args_list,
            [unittest.mock.call(signal.SIGUSR2), unittest.mock.call(signal.SIGUSR2)],
        )
        process.wait.assert_not_called()
        process.kill.assert_not_called()

    def test_snapshot_copies_a_complete_prefix_while_capture_keeps_running(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "active.pcap"
            destination = root / "snapshots" / "current.pcap"
            source.write_bytes((FIXTURES / "ike-esp.pcap").read_bytes())
            process = Mock()
            process.pid = 4132
            process.poll.return_value = None
            session = CaptureSession(
                source,
                root / "tcpdump.log",
                timeout=0.2,
                drain_seconds=0,
            )
            session._process = process

            result = session.snapshot(destination)

            self.assertEqual(result, destination)
            self.assertEqual(destination.read_bytes(), source.read_bytes())
            self.assertTrue(session.running)
            process.send_signal.assert_called_with(signal.SIGUSR2)
            process.wait.assert_not_called()
            process.kill.assert_not_called()

    def test_flush_rejects_a_capture_that_has_not_started(self) -> None:
        session = CaptureSession(Path("live.pcap"), Path("tcpdump.log"))
        self.assertFalse(session.running)
        with self.assertRaisesRegex(RuntimeError, "not running"):
            session.flush()


if __name__ == "__main__":
    unittest.main()
