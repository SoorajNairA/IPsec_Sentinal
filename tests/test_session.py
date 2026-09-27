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


class SnapshotCapture(Action):
    def snapshot(self, destination: Path) -> Path:
        self.observed.append(f"snapshot:{destination.name}")
        destination.write_bytes(b"snapshot")
        return destination


class Pair(Action):
    def list_sas(self) -> dict[str, str]:
        self.observed.append("list_sas")
        return {"gateway-a": "a", "gateway-b": "b"}


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

    def test_capture_snapshot_delegates_to_running_primary_capture(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            observed: list[str] = []
            session = SecureSession(
                root / "run", StringIO(), primary_capture_name="full-evidence.pcap"
            )
            session.captures = {
                "primary": SnapshotCapture("primary", observed),
            }

            destination = root / "snapshot.pcap"
            result = session.capture_snapshot(destination)

            self.assertEqual(result, destination)
            self.assertEqual(destination.read_bytes(), b"snapshot")
            self.assertEqual(observed, ["snapshot:snapshot.pcap"])

    def test_refresh_sas_updates_session_without_waiting_or_restarting(self) -> None:
        with TemporaryDirectory() as directory:
            observed: list[str] = []
            session = SecureSession(
                Path(directory), StringIO(), primary_capture_name="full-evidence.pcap"
            )
            session.pair = Pair("pair_stop", observed)

            result = session.refresh_sas()

            self.assertEqual(result, {"gateway-a": "a", "gateway-b": "b"})
            self.assertEqual(session.sas, result)
            self.assertEqual(observed, ["list_sas"])

    def test_stop_captures_is_idempotent_and_does_not_stop_daemons(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "runtime"
            runtime.mkdir()
            (root / "run").mkdir()
            observed: list[str] = []
            session = SecureSession(
                root / "run", StringIO(), primary_capture_name="full-evidence.pcap"
            )
            session.runtime_dir = runtime
            session.temporary_pcaps = {
                name: runtime / f"{name}.pcap"
                for name in ("primary", "gateway-a", "gateway-b")
            }
            session.destinations = {
                name: root / "run" / f"{name}.pcap"
                for name in ("primary", "gateway-a", "gateway-b")
            }
            for path in session.temporary_pcaps.values():
                path.write_bytes(b"pcap")
            session.destinations["primary"] = session.primary_destination
            session.captures = {
                name: Action(f"stop:{name}", observed)
                for name in ("primary", "gateway-a", "gateway-b")
            }
            session.pair = Pair("daemon_stop", observed)

            session.stop_captures()
            first_ended_at = session.capture_ended_at
            session.stop_captures()

            self.assertGreater(first_ended_at, 0)
            self.assertEqual(session.capture_ended_at, first_ended_at)
            self.assertEqual(
                observed,
                ["stop:primary", "stop:gateway-a", "stop:gateway-b"],
            )
            self.assertNotIn("daemon_stop", observed)
            self.assertTrue(session.primary_destination.is_file())

    def test_capture_snapshot_does_not_change_evidence_completion_rules(self) -> None:
        with TemporaryDirectory() as directory:
            session = SecureSession(
                Path(directory), StringIO(), primary_capture_name="full-evidence.pcap"
            )
            session.captures = {
                "primary": SnapshotCapture("primary", []),
            }
            session.capture_snapshot(Path(directory) / "snapshot.pcap")
            with self.assertRaisesRegex(RuntimeError, "evidence is incomplete"):
                session.evidence()


if __name__ == "__main__":
    unittest.main()
