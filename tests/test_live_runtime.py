from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import json
import unittest

from ipsec_sentinel.live.runtime import (
    LiveLabLock,
    LiveOwnerActive,
    OwnedProcess,
    RuntimeOwnership,
    record_resource,
    recover_stale_runtime,
)
from ipsec_sentinel.live.orchestrator import LiveLabOrchestrator
from ipsec_sentinel.live.provider import LocalLabProvider
from tests.test_live_actions import ActionSession
from tests.test_live_orchestrator import InlineExecutor


class LiveRuntimeTest(unittest.TestCase):
    def test_lock_refuses_a_second_live_owner_and_can_be_reacquired(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "live.lock"
            first = LiveLabLock.acquire(path)
            self.addCleanup(first.release)
            with self.assertRaises(LiveOwnerActive):
                LiveLabLock.acquire(path)
            first.release()
            second = LiveLabLock.acquire(path)
            second.release()
            self.assertFalse(path.exists())

    def test_recovery_refuses_a_verified_live_owner(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            ownership_path = root / "runtime-ownership.json"
            RuntimeOwnership(
                session_id="SNT-LIVE0001",
                owner_pid=41,
                owner_start_identity="boot:100",
            ).write(ownership_path)

            with self.assertRaises(LiveOwnerActive):
                recover_stale_runtime(
                    ownership_path,
                    runtime_roots=(root / "runtime",),
                    read_process_identity=lambda pid: "boot:100" if pid == 41 else None,
                    terminate_process=lambda _pid: None,
                    reset_namespace=lambda _name: None,
                )

            self.assertTrue(ownership_path.exists())

    def test_stale_recovery_uses_exact_pid_namespace_and_runtime_path(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "runtime"
            runtime.mkdir()
            socket = runtime / "charon.vici"
            socket.write_text("socket", encoding="utf-8")
            evidence = root / "events.jsonl"
            evidence.write_text("evidence", encoding="utf-8")
            ownership_path = root / "runtime-ownership.json"
            ownership = RuntimeOwnership(
                session_id="SNT-STALE001",
                owner_pid=10,
                owner_start_identity="dead-owner",
                processes=(OwnedProcess(77, "proc:77", "tcpdump"),),
                namespaces=("ips-gwa",),
                runtime_paths=(str(socket), str(runtime)),
                evidence_paths=(str(evidence),),
            )
            ownership.write(ownership_path)
            terminated: list[int] = []
            namespaces: list[str] = []

            report = recover_stale_runtime(
                ownership_path,
                runtime_roots=(runtime,),
                read_process_identity=lambda pid: "proc:77" if pid == 77 else None,
                terminate_process=terminated.append,
                reset_namespace=namespaces.append,
            )

            self.assertEqual(report.status, "RECOVERED")
            self.assertEqual(terminated, [77])
            self.assertEqual(namespaces, ["ips-gwa"])
            self.assertFalse(socket.exists())
            self.assertFalse(runtime.exists())
            self.assertTrue(evidence.is_file())
            self.assertFalse(ownership_path.exists())
            second = recover_stale_runtime(
                ownership_path,
                runtime_roots=(runtime,),
                read_process_identity=lambda _pid: None,
                terminate_process=terminated.append,
                reset_namespace=namespaces.append,
            )
            self.assertEqual(second.status, "NO_RECORD")
            self.assertEqual(terminated, [77])
            self.assertEqual(namespaces, ["ips-gwa"])

    def test_reused_pid_identity_is_never_terminated(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            ownership_path = root / "runtime-ownership.json"
            RuntimeOwnership(
                session_id="SNT-STALE002",
                owner_pid=10,
                owner_start_identity="dead-owner",
                processes=(OwnedProcess(88, "old-start", "charon"),),
            ).write(ownership_path)
            terminated: list[int] = []

            report = recover_stale_runtime(
                ownership_path,
                runtime_roots=(root / "runtime",),
                read_process_identity=lambda pid: "new-start" if pid == 88 else None,
                terminate_process=terminated.append,
                reset_namespace=lambda _name: None,
            )

            self.assertEqual(terminated, [])
            action = next(item for item in report.actions if item["resource"] == "pid:88")
            self.assertEqual(action["status"], "SKIPPED_IDENTITY_MISMATCH")
            self.assertFalse(ownership_path.exists())

    def test_partial_recovery_records_diagnostics_and_preserves_ownership(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "runtime"
            runtime.mkdir()
            path = runtime / "owned.sock"
            path.write_text("owned", encoding="utf-8")
            ownership_path = root / "runtime-ownership.json"
            RuntimeOwnership(
                session_id="SNT-STALE003",
                owner_pid=10,
                owner_start_identity="dead-owner",
                namespaces=("ips-gwa", "ips-gwb"),
                runtime_paths=(str(path),),
            ).write(ownership_path)

            def reset(name: str) -> None:
                if name == "ips-gwa":
                    raise RuntimeError("injected namespace failure")

            report = recover_stale_runtime(
                ownership_path,
                runtime_roots=(runtime,),
                read_process_identity=lambda _pid: None,
                terminate_process=lambda _pid: None,
                reset_namespace=reset,
            )

            self.assertEqual(report.status, "PARTIAL")
            self.assertTrue(ownership_path.exists())
            persisted = json.loads(ownership_path.read_text(encoding="utf-8"))
            self.assertEqual(persisted["last_recovery"]["status"], "PARTIAL")
            self.assertIn("injected namespace failure", json.dumps(persisted))
            self.assertFalse(path.exists())

    def test_record_resource_is_idempotent_and_rejects_unowned_names(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime-ownership.json"
            RuntimeOwnership(
                session_id="SNT-RECORD01",
                owner_pid=1,
                owner_start_identity="owner",
            ).write(path)
            record_resource(path, namespace="ips-client")
            record_resource(path, namespace="ips-client")
            record_resource(
                path,
                process=OwnedProcess(99, "proc:99", "tcpdump-primary"),
            )
            saved = RuntimeOwnership.read(path)
            self.assertEqual(saved.namespaces, ("ips-client",))
            self.assertEqual(saved.processes[0].pid, 99)
            with self.assertRaises(ValueError):
                record_resource(path, namespace="unrelated-namespace")

    def test_orchestrator_records_and_clears_owned_runtime_resources(self) -> None:
        with TemporaryDirectory() as directory:
            sessions: list[ActionSession] = []

            def factory(run_dir: Path, log: object, **_kwargs: object) -> ActionSession:
                session = ActionSession(run_dir, log)
                sessions.append(session)
                return session

            orchestrator = LiveLabOrchestrator(
                Path(directory),
                session_factory=factory,
                provider_factory=LocalLabProvider,
                executor=InlineExecutor(),
                id_factory=lambda: "SNT-RUNTIME1",
            )
            self.addCleanup(orchestrator.close)
            created = orchestrator.create_session("secure-baseline")
            ownership_path = Path(directory) / created.session_id / "runtime-ownership.json"
            self.assertTrue(ownership_path.is_file())

            orchestrator.submit(created.session_id, "CONNECT", {}).result()

            ownership = RuntimeOwnership.read(ownership_path)
            self.assertEqual(set(ownership.namespaces), {
                "ips-client", "ips-gwa", "ips-gwb", "ips-server"
            })
            self.assertIn(
                str((Path("/run/ipsec-sentinel") / created.session_id).resolve()),
                ownership.runtime_paths,
            )
            self.assertTrue((Path(directory) / ".live-lab.lock").is_file())

            orchestrator.disconnect(created.session_id).result()
            self.assertFalse(ownership_path.exists())
            orchestrator.close()
            self.assertFalse((Path(directory) / ".live-lab.lock").exists())

    def test_failed_cleanup_keeps_ownership_for_next_startup_recovery(self) -> None:
        with TemporaryDirectory() as directory:
            def factory(run_dir: Path, log: object, **_kwargs: object) -> ActionSession:
                return ActionSession(run_dir, log, cleanup_error=True)

            orchestrator = LiveLabOrchestrator(
                Path(directory),
                session_factory=factory,
                provider_factory=LocalLabProvider,
                executor=InlineExecutor(),
                id_factory=lambda: "SNT-RUNTIME2",
            )
            created = orchestrator.create_session("secure-baseline")
            orchestrator.submit(created.session_id, "CONNECT", {}).result()
            orchestrator.disconnect(created.session_id).result()
            ownership_path = Path(directory) / created.session_id / "runtime-ownership.json"
            self.assertTrue(ownership_path.is_file())

            orchestrator.close()

            self.assertTrue(ownership_path.is_file())
            self.assertFalse((Path(directory) / ".live-lab.lock").exists())

    def test_orchestrator_startup_recovers_an_abandoned_record(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            prior = root / "SNT-ABANDON1"
            prior.mkdir()
            evidence = prior / "events.jsonl"
            evidence.write_text("retained evidence", encoding="utf-8")
            ownership_path = prior / "runtime-ownership.json"
            RuntimeOwnership(
                session_id="SNT-ABANDON1",
                owner_pid=2_000_000_000,
                owner_start_identity="definitely-dead",
                evidence_paths=(str(evidence),),
            ).write(ownership_path)

            orchestrator = LiveLabOrchestrator(root, executor=InlineExecutor())
            orchestrator.close()

            self.assertFalse(ownership_path.exists())
            self.assertTrue(evidence.is_file())
            report = json.loads((prior / "runtime-recovery.json").read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "RECOVERED")

    def test_orchestrator_refuses_start_after_partial_recovery(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            prior = root / "SNT-PARTIAL1"
            prior.mkdir()
            ownership_path = prior / "runtime-ownership.json"
            RuntimeOwnership(
                session_id="SNT-PARTIAL1",
                owner_pid=2_000_000_000,
                owner_start_identity="definitely-dead",
                runtime_paths=(str(root / "outside-approved-runtime"),),
            ).write(ownership_path)

            with self.assertRaisesRegex(RuntimeError, "stale Live Lab recovery incomplete"):
                LiveLabOrchestrator(root, executor=InlineExecutor())

            self.assertTrue(ownership_path.is_file())
            self.assertFalse((root / ".live-lab.lock").exists())


if __name__ == "__main__":
    unittest.main()
