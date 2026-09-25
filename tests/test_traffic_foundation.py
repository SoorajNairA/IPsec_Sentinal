from io import StringIO
from pathlib import Path
import socket
from tempfile import TemporaryDirectory
import unittest

from ipsec_sentinel.traffic.base import TrafficContext
from ipsec_sentinel.traffic.framing import recv_frame, send_frame
from ipsec_sentinel.traffic.payload import deterministic_bytes
from ipsec_sentinel.traffic.ports import (
    choose_available_port,
    select_port_candidates,
)
from ipsec_sentinel.traffic.process import NamespaceServiceProcess


class FakeProcess:
    def __init__(self, returncode=None) -> None:
        self.returncode = returncode
        self.terminated = 0
        self.killed = 0

    def poll(self):
        return self.returncode

    def terminate(self) -> None:
        self.terminated += 1
        self.returncode = 0

    def kill(self) -> None:
        self.killed += 1
        self.returncode = -9

    def wait(self, timeout=None):
        del timeout
        return self.returncode


class TrafficFoundationTest(unittest.TestCase):
    def context(self, run_dir: Path) -> TrafficContext:
        return TrafficContext(run_dir, StringIO(), 7, "secure-baseline", "clean")

    def test_seeded_port_candidates_are_repeatable_varied_unique_and_bounded(self) -> None:
        candidates = select_port_candidates(7, "web", "tcp")
        self.assertEqual(candidates, select_port_candidates(7, "web", "tcp"))
        self.assertNotEqual(candidates[0], select_port_candidates(8, "web", "tcp")[0])
        self.assertEqual(len(candidates), 32)
        self.assertEqual(len(set(candidates)), 32)
        self.assertTrue(all(20_000 <= port <= 29_999 for port in candidates))

    def test_port_collision_uses_recorded_deterministic_fallback(self) -> None:
        candidates = select_port_candidates(7, "web", "tcp")
        probes: list[int] = []

        def probe(context, port: int, protocol: str) -> bool:
            del context, protocol
            probes.append(port)
            return port != candidates[0]

        with TemporaryDirectory() as directory:
            selection = choose_available_port(
                self.context(Path(directory)), 7, "web", "tcp", probe=probe
            )
        self.assertEqual(selection.port, candidates[1])
        self.assertEqual(selection.candidate_index, 1)
        self.assertEqual(selection.rejected_ports, (candidates[0],))
        self.assertEqual(probes, list(candidates[:2]))

    def test_framing_round_trip_and_truncation_fail_closed(self) -> None:
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        send_frame(left, b"hello")
        self.assertEqual(recv_frame(right), b"hello")
        left.sendall((5).to_bytes(4, "big") + b"xx")
        left.shutdown(socket.SHUT_WR)
        with self.assertRaisesRegex(EOFError, "truncated"):
            recv_frame(right)

    def test_deterministic_payload_has_exact_size_and_seeded_digest(self) -> None:
        payload = deterministic_bytes(7, "fixture", 97)
        self.assertEqual(len(payload), 97)
        self.assertEqual(payload, deterministic_bytes(7, "fixture", 97))
        self.assertNotEqual(payload, deterministic_bytes(8, "fixture", 97))
        self.assertNotEqual(payload, deterministic_bytes(7, "other", 97))

    def test_service_detects_early_exit_timeout_and_repeated_stop(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            context = self.context(root)
            early = FakeProcess(returncode=7)
            service = NamespaceServiceProcess(
                context,
                module="example.service",
                arguments=(),
                ready_path=root / "early.ready",
                log_name="early.log",
                popen_factory=lambda *args, **kwargs: early,
            )
            with self.assertRaisesRegex(RuntimeError, "exited with 7"):
                service.start()
            self.assertIsNone(service.process)

            hung = FakeProcess(returncode=None)
            service = NamespaceServiceProcess(
                context,
                module="example.service",
                arguments=(),
                ready_path=root / "hung.ready",
                log_name="hung.log",
                readiness_timeout=0.0,
                popen_factory=lambda *args, **kwargs: hung,
            )
            with self.assertRaisesRegex(TimeoutError, "readiness"):
                service.start()
            service.stop()
            self.assertEqual(hung.terminated, 1)
            self.assertIsNone(service.process)


if __name__ == "__main__":
    unittest.main()
