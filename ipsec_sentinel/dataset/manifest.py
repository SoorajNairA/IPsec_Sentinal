from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Callable, TypeVar

from ipsec_sentinel.dataset.config import DatasetConfig
from ipsec_sentinel.dataset.matrix import (
    MatrixSlot,
    attempt_id,
    derive_attempt_seed,
    expand_matrix,
)
from ipsec_sentinel.dataset.models import (
    MANIFEST_SCHEMA_VERSION,
    AttemptOutcome,
    CleanupState,
    RunState,
)


class ManifestMismatch(ValueError):
    """Raised when resume inputs do not describe the persisted dataset."""


@dataclass(frozen=True)
class AttemptPlan:
    attempt_id: str
    slot_id: str
    ordinal: int
    attempt_number: int
    seed: int
    scenario_id: str
    traffic_class: str
    network_profile: str
    artifact_path: str


@dataclass(frozen=True)
class SlotRecord:
    slot_id: str
    ordinal: int
    scenario_id: str
    traffic_class: str
    network_profile: str
    repetition: int
    state: RunState
    successful_attempt_id: str | None


@dataclass(frozen=True)
class AttemptRecord:
    attempt_id: str
    slot_id: str
    attempt_number: int
    seed: int
    state: RunState
    started_at: str | None
    finished_at: str | None
    artifact_path: str
    failure_class: str | None
    failure_message: str | None
    cleanup_state: CleanupState
    cleanup_started_at: str | None
    cleanup_finished_at: str | None
    cleanup_actions: tuple[dict[str, object], ...]
    cleanup_error: str | None
    traffic_verified: bool
    ipsec_verified: bool
    capture_verified: bool
    training_ready: bool
    esp_packets: int
    capture_bytes: int
    duration_seconds: float


SCHEMA = """
PRAGMA user_version = 1;
CREATE TABLE datasets (
    name TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL,
    matrix_fingerprint TEXT NOT NULL,
    config_path TEXT NOT NULL,
    base_seed INTEGER NOT NULL,
    generator_versions_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE slots (
    slot_id TEXT PRIMARY KEY,
    ordinal INTEGER NOT NULL UNIQUE,
    scenario_id TEXT NOT NULL,
    traffic_class TEXT NOT NULL,
    network_profile TEXT NOT NULL,
    repetition INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('PENDING','RUNNING','PASS','FAILED','INCOMPLETE')),
    successful_attempt_id TEXT,
    FOREIGN KEY(successful_attempt_id) REFERENCES attempts(attempt_id)
);
CREATE TABLE attempts (
    attempt_id TEXT PRIMARY KEY,
    slot_id TEXT NOT NULL,
    attempt_number INTEGER NOT NULL,
    seed INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('PENDING','RUNNING','PASS','FAILED','INCOMPLETE')),
    started_at TEXT,
    finished_at TEXT,
    artifact_path TEXT NOT NULL,
    failure_class TEXT,
    failure_message TEXT,
    cleanup_status TEXT NOT NULL CHECK (cleanup_status IN ('NOT_STARTED','PASS','FAILED')),
    cleanup_started_at TEXT,
    cleanup_finished_at TEXT,
    cleanup_json TEXT NOT NULL DEFAULT '[]',
    cleanup_error TEXT,
    traffic_verified INTEGER NOT NULL DEFAULT 0 CHECK (traffic_verified IN (0,1)),
    ipsec_verified INTEGER NOT NULL DEFAULT 0 CHECK (ipsec_verified IN (0,1)),
    capture_verified INTEGER NOT NULL DEFAULT 0 CHECK (capture_verified IN (0,1)),
    training_ready INTEGER NOT NULL DEFAULT 0 CHECK (training_ready IN (0,1)),
    esp_packets INTEGER NOT NULL DEFAULT 0,
    capture_bytes INTEGER NOT NULL DEFAULT 0,
    duration_seconds REAL NOT NULL DEFAULT 0,
    UNIQUE(slot_id, attempt_number),
    FOREIGN KEY(slot_id) REFERENCES slots(slot_id)
);
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attempt_id TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    from_state TEXT,
    to_state TEXT NOT NULL,
    reason TEXT NOT NULL,
    FOREIGN KEY(attempt_id) REFERENCES attempts(attempt_id)
);
"""

T = TypeVar("T")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class Manifest:
    def __init__(self, path: Path) -> None:
        self.path = path
        if not self.path.parent.is_dir():
            raise FileNotFoundError(f"manifest parent does not exist: {self.path.parent}")
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA busy_timeout = 5000")
        self.connection.execute("PRAGMA journal_mode = WAL")

    def close(self) -> None:
        self.connection.close()

    @classmethod
    def open_existing(cls, path: Path) -> "Manifest":
        if not path.is_file():
            raise FileNotFoundError(f"manifest does not exist: {path}")
        manifest = cls(path)
        if manifest.connection.execute("PRAGMA user_version").fetchone()[0] != MANIFEST_SCHEMA_VERSION:
            manifest.close()
            raise ValueError("unsupported manifest schema version")
        return manifest

    def _exclusive(self, operation: Callable[[], T]) -> T:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            value = operation()
        except BaseException:
            self.connection.rollback()
            raise
        self.connection.commit()
        return value

    def initialize(
        self,
        config: DatasetConfig,
        fingerprint: str,
        config_path: str,
        generator_versions: dict[str, str],
    ) -> None:
        if self.connection.execute("PRAGMA user_version").fetchone()[0] != 0:
            raise ValueError("manifest is already initialized")
        slots = expand_matrix(config, generator_versions)
        now = _utc_now()

        def operation() -> None:
            self.connection.executescript(SCHEMA)
            self.connection.execute(
                "INSERT INTO datasets VALUES(?,?,?,?,?,?,?,?)",
                (
                    config.name,
                    config.schema_version,
                    fingerprint,
                    config_path,
                    config.base_seed,
                    json.dumps(generator_versions, sort_keys=True, separators=(",", ":")),
                    now,
                    now,
                ),
            )
            for slot in slots:
                self.connection.execute(
                    "INSERT INTO slots VALUES(?,?,?,?,?,?,?,NULL)",
                    (
                        slot.slot_id,
                        slot.ordinal,
                        slot.scenario_id,
                        slot.traffic_class,
                        slot.network_profile,
                        slot.repetition,
                        RunState.PENDING.value,
                    ),
                )
                identifier = attempt_id(slot.slot_id, 1)
                seed = derive_attempt_seed(config.base_seed, slot.ordinal, 1)
                self.connection.execute(
                    "INSERT INTO attempts(attempt_id,slot_id,attempt_number,seed,state,artifact_path,cleanup_status) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (
                        identifier,
                        slot.slot_id,
                        1,
                        seed,
                        RunState.PENDING.value,
                        f"runs/{identifier}",
                        CleanupState.NOT_STARTED.value,
                    ),
                )
                self._event(identifier, now, None, RunState.PENDING.value, "initialized")

        self._exclusive(operation)

    @property
    def base_seed(self) -> int:
        row = self.connection.execute("SELECT base_seed FROM datasets").fetchone()
        if row is None:
            raise ValueError("manifest is not initialized")
        return int(row[0])

    def assert_compatible(self, fingerprint: str) -> None:
        row = self.connection.execute(
            "SELECT matrix_fingerprint FROM datasets"
        ).fetchone()
        if row is None or row[0] != fingerprint:
            raise ManifestMismatch("matrix fingerprint mismatch")

    def recover_running(self, occurred_at: str) -> tuple[str, ...]:
        def operation() -> tuple[str, ...]:
            rows = self.connection.execute(
                "SELECT attempt_id,slot_id FROM attempts WHERE state='RUNNING' "
                "ORDER BY attempt_id"
            ).fetchall()
            for row in rows:
                self.connection.execute(
                    "UPDATE attempts SET state='INCOMPLETE',finished_at=?,"
                    "failure_class='interrupted',failure_message=?,training_ready=0 "
                    "WHERE attempt_id=?",
                    (
                        occurred_at,
                        "stale RUNNING attempt recovered during resume",
                        row["attempt_id"],
                    ),
                )
                self.connection.execute(
                    "UPDATE slots SET state='INCOMPLETE' WHERE slot_id=?",
                    (row["slot_id"],),
                )
                self._event(
                    row["attempt_id"],
                    occurred_at,
                    "RUNNING",
                    "INCOMPLETE",
                    "resume recovery",
                )
            return tuple(row["attempt_id"] for row in rows)

        return self._exclusive(operation)

    def next_attempt(self, slot_id: str, retry_failed: int) -> AttemptPlan | None:
        def operation() -> AttemptPlan | None:
            slot = self.connection.execute(
                "SELECT * FROM slots WHERE slot_id=?", (slot_id,)
            ).fetchone()
            if slot is None:
                raise KeyError(slot_id)
            if slot["state"] == RunState.PASS.value:
                return None
            pending = self.connection.execute(
                "SELECT * FROM attempts WHERE slot_id=? AND state='PENDING' "
                "ORDER BY attempt_number DESC LIMIT 1",
                (slot_id,),
            ).fetchone()
            if pending is not None:
                return self._attempt_plan(slot, pending)
            count = self.connection.execute(
                "SELECT COUNT(*) FROM attempts WHERE slot_id=?", (slot_id,)
            ).fetchone()[0]
            if count >= 1 + retry_failed:
                return None
            number = count + 1
            identifier = attempt_id(slot_id, number)
            seed = derive_attempt_seed(self.base_seed, slot["ordinal"], number)
            artifact_path = f"runs/{identifier}"
            self.connection.execute(
                "INSERT INTO attempts(attempt_id,slot_id,attempt_number,seed,state,artifact_path,cleanup_status) "
                "VALUES(?,?,?,?,?,?,?)",
                (
                    identifier,
                    slot_id,
                    number,
                    seed,
                    RunState.PENDING.value,
                    artifact_path,
                    CleanupState.NOT_STARTED.value,
                ),
            )
            self.connection.execute(
                "UPDATE slots SET state='PENDING' WHERE slot_id=?", (slot_id,)
            )
            self._event(identifier, _utc_now(), None, "PENDING", "retry scheduled")
            row = self.connection.execute(
                "SELECT * FROM attempts WHERE attempt_id=?", (identifier,)
            ).fetchone()
            return self._attempt_plan(slot, row)

        return self._exclusive(operation)

    def mark_running(self, attempt_id_value: str, started_at: str) -> None:
        def operation() -> None:
            row = self.connection.execute(
                "SELECT slot_id,state FROM attempts WHERE attempt_id=?",
                (attempt_id_value,),
            ).fetchone()
            if row is None or row["state"] != RunState.PENDING.value:
                raise ValueError("only a PENDING attempt can enter RUNNING")
            self.connection.execute(
                "UPDATE attempts SET state='RUNNING',started_at=? WHERE attempt_id=?",
                (started_at, attempt_id_value),
            )
            self.connection.execute(
                "UPDATE slots SET state='RUNNING' WHERE slot_id=?", (row["slot_id"],)
            )
            self._event(
                attempt_id_value, started_at, "PENDING", "RUNNING", "attempt claimed"
            )

        self._exclusive(operation)

    def finish_attempt(
        self,
        attempt_id_value: str,
        state: RunState,
        cleanup_status: CleanupState,
        *,
        training_ready: bool,
        failure_class: str | None,
        failure_message: str | None,
        traffic_verified: bool,
        ipsec_verified: bool,
        capture_verified: bool,
        esp_packets: int,
        capture_bytes: int,
        finished_at: str,
        cleanup_started_at: str,
        cleanup_finished_at: str,
        cleanup_actions: tuple[dict[str, object], ...],
        cleanup_error: str | None,
        duration_seconds: float,
    ) -> None:
        if state is RunState.PASS and cleanup_status is not CleanupState.PASS:
            raise ValueError("PASS requires cleanup PASS")
        if state is RunState.PASS and (
            not training_ready
            or not all((traffic_verified, ipsec_verified, capture_verified))
        ):
            raise ValueError("PASS requires training_ready and all validation")
        if state is not RunState.PASS and training_ready:
            raise ValueError("only PASS may be training_ready")
        if state not in (RunState.PASS, RunState.FAILED, RunState.INCOMPLETE):
            raise ValueError("attempt must finish in a terminal state")

        def operation() -> None:
            row = self.connection.execute(
                "SELECT slot_id,state FROM attempts WHERE attempt_id=?",
                (attempt_id_value,),
            ).fetchone()
            if row is None or row["state"] != RunState.RUNNING.value:
                raise ValueError("only RUNNING may enter a terminal state")
            self.connection.execute(
                "UPDATE attempts SET state=?,finished_at=?,failure_class=?,failure_message=?,"
                "cleanup_status=?,cleanup_started_at=?,cleanup_finished_at=?,cleanup_json=?,"
                "cleanup_error=?,traffic_verified=?,ipsec_verified=?,capture_verified=?,"
                "training_ready=?,esp_packets=?,capture_bytes=?,duration_seconds=? "
                "WHERE attempt_id=?",
                (
                    state.value,
                    finished_at,
                    failure_class,
                    failure_message,
                    cleanup_status.value,
                    cleanup_started_at,
                    cleanup_finished_at,
                    json.dumps(cleanup_actions, sort_keys=True, separators=(",", ":")),
                    cleanup_error,
                    int(traffic_verified),
                    int(ipsec_verified),
                    int(capture_verified),
                    int(training_ready),
                    esp_packets,
                    capture_bytes,
                    duration_seconds,
                    attempt_id_value,
                ),
            )
            self.connection.execute(
                "UPDATE slots SET state=?,successful_attempt_id=? WHERE slot_id=?",
                (
                    state.value,
                    attempt_id_value if state is RunState.PASS else None,
                    row["slot_id"],
                ),
            )
            self._event(
                attempt_id_value,
                finished_at,
                "RUNNING",
                state.value,
                failure_class or "completed",
            )

        self._exclusive(operation)

    def finish_attempt_from_outcome(
        self, outcome: AttemptOutcome, occurred_at: str | None = None
    ) -> None:
        del occurred_at
        self.finish_attempt(
            outcome.run_id,
            outcome.state,
            outcome.cleanup_state,
            training_ready=outcome.training_ready,
            failure_class=outcome.failure_class,
            failure_message=outcome.failure_message,
            traffic_verified=outcome.traffic_verified,
            ipsec_verified=outcome.ipsec_verified,
            capture_verified=outcome.capture_verified,
            esp_packets=outcome.esp_packets,
            capture_bytes=outcome.capture_bytes,
            finished_at=outcome.finished_at,
            cleanup_started_at=outcome.cleanup_started_at,
            cleanup_finished_at=outcome.cleanup_finished_at,
            cleanup_actions=outcome.cleanup_actions,
            cleanup_error=outcome.cleanup_error,
            duration_seconds=outcome.duration_seconds,
        )

    def slots(self) -> tuple[SlotRecord, ...]:
        rows = self.connection.execute("SELECT * FROM slots ORDER BY ordinal").fetchall()
        return tuple(
            SlotRecord(
                row["slot_id"],
                row["ordinal"],
                row["scenario_id"],
                row["traffic_class"],
                row["network_profile"],
                row["repetition"],
                RunState(row["state"]),
                row["successful_attempt_id"],
            )
            for row in rows
        )

    def slots_in_order(self) -> tuple[SlotRecord, ...]:
        return self.slots()

    def attempts(self) -> tuple[AttemptRecord, ...]:
        rows = self.connection.execute(
            "SELECT * FROM attempts ORDER BY slot_id,attempt_number"
        ).fetchall()
        return tuple(self._attempt_record(row) for row in rows)

    def training_ready_attempts(self) -> tuple[AttemptRecord, ...]:
        return tuple(
            attempt
            for attempt in self.attempts()
            if attempt.state is RunState.PASS and attempt.training_ready
        )

    def count_attempts(self, state: RunState) -> int:
        return int(
            self.connection.execute(
                "SELECT COUNT(*) FROM attempts WHERE state=?", (state.value,)
            ).fetchone()[0]
        )

    def latest_attempt(self, slot_id: str) -> AttemptRecord | None:
        row = self.connection.execute(
            "SELECT * FROM attempts WHERE slot_id=? ORDER BY attempt_number DESC LIMIT 1",
            (slot_id,),
        ).fetchone()
        return None if row is None else self._attempt_record(row)

    def _attempt_plan(self, slot: sqlite3.Row, attempt: sqlite3.Row) -> AttemptPlan:
        return AttemptPlan(
            attempt["attempt_id"],
            slot["slot_id"],
            slot["ordinal"],
            attempt["attempt_number"],
            attempt["seed"],
            slot["scenario_id"],
            slot["traffic_class"],
            slot["network_profile"],
            attempt["artifact_path"],
        )

    def _attempt_record(self, row: sqlite3.Row) -> AttemptRecord:
        return AttemptRecord(
            row["attempt_id"],
            row["slot_id"],
            row["attempt_number"],
            row["seed"],
            RunState(row["state"]),
            row["started_at"],
            row["finished_at"],
            row["artifact_path"],
            row["failure_class"],
            row["failure_message"],
            CleanupState(row["cleanup_status"]),
            row["cleanup_started_at"],
            row["cleanup_finished_at"],
            tuple(json.loads(row["cleanup_json"])),
            row["cleanup_error"],
            bool(row["traffic_verified"]),
            bool(row["ipsec_verified"]),
            bool(row["capture_verified"]),
            bool(row["training_ready"]),
            row["esp_packets"],
            row["capture_bytes"],
            row["duration_seconds"],
        )

    def _event(
        self,
        attempt_id_value: str,
        occurred_at: str,
        from_state: str | None,
        to_state: str,
        reason: str,
    ) -> None:
        self.connection.execute(
            "INSERT INTO events(attempt_id,occurred_at,from_state,to_state,reason) "
            "VALUES(?,?,?,?,?)",
            (attempt_id_value, occurred_at, from_state, to_state, reason),
        )
