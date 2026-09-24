from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from ipsec_sentinel.session import SecureSession


class Action:
    def __init__(self, name: str, observed: list[str], *, fail: bool = False) -> None:
        self.name = name
        self.observed = observed
        self.fail = fail

    def stop(self) -> None:
        self.observed.append(self.name)
        if self.fail:
            raise RuntimeError(f"injected {self.name}")

    def reset(self) -> None:
        self.stop()


class SecureSessionTest(unittest.TestCase):
    def test_dataset_and_phase_one_primary_capture_names_do_not_overlap_semantics(self) -> None:
        with TemporaryDirectory() as directory:
            phase_one = SecureSession(
                Path(directory) / "phase1",
                StringIO(),
                primary_capture_name="encrypted.pcap",
            )
            dataset = SecureSession(
                Path(directory) / "dataset",
                StringIO(),
                primary_capture_name="full-evidence.pcap",
            )
            self.assertEqual(phase_one.primary_destination.name, "encrypted.pcap")
            self.assertEqual(dataset.primary_destination.name, "full-evidence.pcap")

    def test_cleanup_attempts_all_session_layers_after_capture_failure(self) -> None:
        with TemporaryDirectory() as directory:
            observed: list[str] = []
            session = SecureSession(
                Path(directory), StringIO(), primary_capture_name="full-evidence.pcap"
            )
            session.captures = {
                "primary": Action("primary", observed, fail=True),
                "gateway-a": Action("gateway-a", observed),
                "gateway-b": Action("gateway-b", observed),
            }
            session.preserve_diagnostics = lambda: observed.append("logs")
            session.pair = Action("daemons", observed)
            session.topology = Action("topology", observed)
            with self.assertRaisesRegex(RuntimeError, "primary"):
                session.cleanup()
            self.assertEqual(
                observed,
                ["primary", "gateway-a", "gateway-b", "logs", "daemons", "topology"],
            )

    def test_repeated_cleanup_remains_safe_and_complete(self) -> None:
        with TemporaryDirectory() as directory:
            observed: list[str] = []
            session = SecureSession(
                Path(directory), StringIO(), primary_capture_name="full-evidence.pcap"
            )
            session.captures = {"primary": Action("capture", observed)}
            session.preserve_diagnostics = lambda: observed.append("logs")
            session.pair = Action("daemons", observed)
            session.topology = Action("topology", observed)
            session.cleanup()
            session.cleanup()
            self.assertEqual(observed.count("capture"), 2)
            self.assertEqual(observed.count("topology"), 2)


if __name__ == "__main__":
    unittest.main()
