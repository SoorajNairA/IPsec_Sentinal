from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from time import monotonic, sleep
from typing import TextIO
from uuid import uuid4
import fcntl
import json
import os
import signal
import subprocess

from ipsec_sentinel.artifacts import write_json_atomic
from ipsec_sentinel.topology import NAMESPACES


RUNTIME_SCHEMA = "ipsec-sentinel.live-runtime/v1"
RECOVERY_SCHEMA = "ipsec-sentinel.live-runtime-recovery/v1"


class LiveOwnerActive(RuntimeError):
    """Raised when another verified process still owns the Live Lab."""


@dataclass(frozen=True, order=True)
class OwnedProcess:
    pid: int
    start_identity: str
    role: str

    def __post_init__(self) -> None:
        if self.pid <= 0:
            raise ValueError("owned process PID must be positive")
        if not self.start_identity.strip() or not self.role.strip():
            raise ValueError("owned process identity and role must not be empty")


@dataclass(frozen=True)
class RuntimeOwnership:
    session_id: str
    owner_pid: int
    owner_start_identity: str
    processes: tuple[OwnedProcess, ...] = ()
    namespaces: tuple[str, ...] = ()
    runtime_paths: tuple[str, ...] = ()
    evidence_paths: tuple[str, ...] = ()
    last_recovery: Mapping[str, object] | None = None
    schema: str = field(default=RUNTIME_SCHEMA, init=False)

    def __post_init__(self) -> None:
        if not self.session_id.startswith("SNT-"):
            raise ValueError("runtime ownership requires a Live Lab session ID")
        if self.owner_pid <= 0 or not self.owner_start_identity.strip():
            raise ValueError("runtime ownership requires an exact process owner")
        unknown = set(self.namespaces) - set(NAMESPACES)
        if unknown:
            raise ValueError(f"runtime ownership contains unknown namespaces: {sorted(unknown)}")
        if len(set(self.namespaces)) != len(self.namespaces):
            raise ValueError("runtime ownership namespaces must be unique")
        if len({process.pid for process in self.processes}) != len(self.processes):
            raise ValueError("runtime ownership process PIDs must be unique")

    @classmethod
    def create(cls, session_id: str) -> "RuntimeOwnership":
        pid = os.getpid()
        identity = process_start_identity(pid)
        if identity is None:
            raise RuntimeError("cannot determine Live Lab owner process identity")
        return cls(session_id, pid, identity)

    @classmethod
    def read(cls, path: Path) -> "RuntimeOwnership":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if payload.get("schema") != RUNTIME_SCHEMA:
            raise ValueError("unsupported runtime ownership schema")
        return cls(
            session_id=str(payload["session_id"]),
            owner_pid=int(payload["owner_pid"]),
            owner_start_identity=str(payload["owner_start_identity"]),
            processes=tuple(
                OwnedProcess(
                    int(item["pid"]),
                    str(item["start_identity"]),
                    str(item["role"]),
                )
                for item in payload.get("processes", [])
            ),
            namespaces=tuple(str(item) for item in payload.get("namespaces", [])),
            runtime_paths=tuple(str(item) for item in payload.get("runtime_paths", [])),
            evidence_paths=tuple(str(item) for item in payload.get("evidence_paths", [])),
            last_recovery=payload.get("last_recovery"),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "session_id": self.session_id,
            "owner_pid": self.owner_pid,
            "owner_start_identity": self.owner_start_identity,
            "processes": [asdict(process) for process in self.processes],
            "namespaces": list(self.namespaces),
            "runtime_paths": list(self.runtime_paths),
            "evidence_paths": list(self.evidence_paths),
            "last_recovery": (
                None if self.last_recovery is None else dict(self.last_recovery)
            ),
        }

    def write(self, path: Path) -> None:
        write_json_atomic(Path(path), self.to_dict())


@dataclass(frozen=True)
class RecoveryReport:
    session_id: str | None
    status: str
    actions: tuple[dict[str, object], ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": RECOVERY_SCHEMA,
            "session_id": self.session_id,
            "status": self.status,
            "actions": [dict(action) for action in self.actions],
        }


class LiveLabLock:
    def __init__(self, path: Path, stream: TextIO, token: str) -> None:
        self.path = path
        self._stream = stream
        self._token = token
        self._released = False

    @classmethod
    def acquire(cls, path: Path) -> "LiveLabLock":
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        stream = path.open("a+", encoding="utf-8")
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            stream.close()
            raise LiveOwnerActive("another Sentinel Agent owns the Live Lab lock") from error
        token = uuid4().hex
        identity = process_start_identity(os.getpid())
        if identity is None:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            stream.close()
            raise RuntimeError("cannot determine lock owner process identity")
        stream.seek(0)
        stream.truncate()
        json.dump(
            {
                "pid": os.getpid(),
                "start_identity": identity,
                "token": token,
            },
            stream,
            sort_keys=True,
        )
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
        return cls(path, stream, token)

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        try:
            self._stream.seek(0)
            payload = json.load(self._stream)
            owns_path = payload.get("token") == self._token
        except (OSError, ValueError, json.JSONDecodeError):
            owns_path = False
        if owns_path:
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass
        try:
            fcntl.flock(self._stream.fileno(), fcntl.LOCK_UN)
        finally:
            self._stream.close()

    def __enter__(self) -> "LiveLabLock":
        return self

    def __exit__(self, *_args: object) -> None:
        self.release()


def process_start_identity(pid: int) -> str | None:
    proc = Path("/proc") / str(pid)
    try:
        stat = (proc / "stat").read_text(encoding="utf-8")
        closing = stat.rfind(")")
        if closing < 0:
            return None
        fields = stat[closing + 2 :].split()
        start_ticks = fields[19]
        executable = os.readlink(proc / "exe")
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(
            encoding="ascii"
        ).strip()
    except (FileNotFoundError, PermissionError, OSError, IndexError):
        return None
    return f"{boot_id}:{start_ticks}:{executable}"


def record_resource(
    ownership_path: Path,
    *,
    process: OwnedProcess | None = None,
    namespace: str | None = None,
    runtime_path: Path | str | None = None,
    evidence_path: Path | str | None = None,
) -> RuntimeOwnership:
    if all(item is None for item in (process, namespace, runtime_path, evidence_path)):
        raise ValueError("record_resource requires a resource")
    ownership = RuntimeOwnership.read(ownership_path)
    processes = list(ownership.processes)
    namespaces = list(ownership.namespaces)
    runtime_paths = list(ownership.runtime_paths)
    evidence_paths = list(ownership.evidence_paths)
    if process is not None and process not in processes:
        if any(existing.pid == process.pid for existing in processes):
            raise ValueError("a different process identity is already recorded for this PID")
        processes.append(process)
    if namespace is not None:
        if namespace not in NAMESPACES:
            raise ValueError(f"namespace is outside the Live Lab allowlist: {namespace}")
        if namespace not in namespaces:
            namespaces.append(namespace)
    if runtime_path is not None:
        normalized = str(Path(runtime_path).resolve())
        if normalized not in runtime_paths:
            runtime_paths.append(normalized)
    if evidence_path is not None:
        normalized = str(Path(evidence_path).resolve())
        if normalized not in evidence_paths:
            evidence_paths.append(normalized)
    updated = replace(
        ownership,
        processes=tuple(sorted(processes)),
        namespaces=tuple(sorted(namespaces)),
        runtime_paths=tuple(sorted(runtime_paths)),
        evidence_paths=tuple(sorted(evidence_paths)),
    )
    updated.write(ownership_path)
    return updated


def recover_stale_runtime(
    ownership_path: Path,
    *,
    runtime_roots: Sequence[Path],
    read_process_identity: Callable[[int], str | None] = process_start_identity,
    terminate_process: Callable[[int], None] | None = None,
    reset_namespace: Callable[[str], None] | None = None,
) -> RecoveryReport:
    ownership_path = Path(ownership_path)
    if not ownership_path.is_file():
        return RecoveryReport(None, "NO_RECORD", ())
    ownership = RuntimeOwnership.read(ownership_path)
    owner_identity = read_process_identity(ownership.owner_pid)
    if owner_identity == ownership.owner_start_identity:
        raise LiveOwnerActive(
            f"Live Lab session {ownership.session_id} still has a verified live owner"
        )
    terminate = terminate_process or _terminate_process
    reset = reset_namespace or _reset_namespace
    roots = tuple(Path(root).resolve() for root in runtime_roots)
    if not roots:
        raise ValueError("stale recovery requires at least one runtime root")
    actions: list[dict[str, object]] = []

    def attempt(resource: str, action: Callable[[], None]) -> None:
        try:
            action()
        except BaseException as error:
            actions.append(
                {
                    "resource": resource,
                    "status": "FAILED",
                    "error": str(error) or type(error).__name__,
                    "exception_type": type(error).__name__,
                }
            )
        else:
            actions.append({"resource": resource, "status": "REMOVED", "error": None})

    for process in ownership.processes:
        identity = read_process_identity(process.pid)
        if identity is None:
            actions.append(
                {
                    "resource": f"pid:{process.pid}",
                    "status": "ALREADY_ABSENT",
                    "error": None,
                }
            )
        elif identity != process.start_identity:
            actions.append(
                {
                    "resource": f"pid:{process.pid}",
                    "status": "SKIPPED_IDENTITY_MISMATCH",
                    "error": None,
                }
            )
        else:
            attempt(f"pid:{process.pid}", lambda pid=process.pid: terminate(pid))

    for namespace in ownership.namespaces:
        if namespace not in NAMESPACES:
            actions.append(
                {
                    "resource": f"namespace:{namespace}",
                    "status": "FAILED",
                    "error": "namespace is outside the Live Lab allowlist",
                    "exception_type": "ValueError",
                }
            )
            continue
        attempt(f"namespace:{namespace}", lambda name=namespace: reset(name))

    paths = sorted(
        (Path(value).resolve() for value in ownership.runtime_paths),
        key=lambda item: len(item.parts),
        reverse=True,
    )
    for path in paths:
        if not any(path == root or root in path.parents for root in roots):
            actions.append(
                {
                    "resource": f"path:{path}",
                    "status": "FAILED",
                    "error": "path is outside the approved runtime roots",
                    "exception_type": "ValueError",
                }
            )
            continue
        attempt(f"path:{path}", lambda target=path: _remove_exact_path(target))

    status = (
        "PARTIAL"
        if any(action["status"] == "FAILED" for action in actions)
        else "RECOVERED"
    )
    report = RecoveryReport(ownership.session_id, status, tuple(actions))
    write_json_atomic(ownership_path.parent / "runtime-recovery.json", report.to_dict())
    if status == "RECOVERED":
        ownership_path.unlink(missing_ok=True)
    else:
        replace(ownership, last_recovery=report.to_dict()).write(ownership_path)
    return report


def _remove_exact_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
        return
    if path.is_dir():
        path.rmdir()


def _terminate_process(pid: int) -> None:
    os.kill(pid, signal.SIGTERM)
    deadline = monotonic() + 3
    while monotonic() < deadline:
        if process_start_identity(pid) is None:
            return
        sleep(0.05)
    os.kill(pid, signal.SIGKILL)


def _reset_namespace(namespace: str) -> None:
    if namespace not in NAMESPACES:
        raise ValueError("namespace is outside the Live Lab allowlist")
    completed = subprocess.run(
        ["ip", "netns", "del", namespace],
        text=True,
        capture_output=True,
        check=False,
        timeout=5,
    )
    if completed.returncode != 0 and "No such file" not in completed.stderr:
        raise RuntimeError(
            f"namespace cleanup failed for {namespace}: {completed.stderr.strip()}"
        )
