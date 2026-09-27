from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from threading import Condition
from typing import Any, Callable, Mapping
import json
import os

from ipsec_sentinel.artifacts import write_json_atomic
from ipsec_sentinel.live.models import LiveSessionSnapshot, SessionState


LIVE_EVENT_SCHEMA = "ipsec-sentinel.live-event/v1"


def _utc_timestamp() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


@dataclass(frozen=True)
class LiveEvent:
    event_id: int
    session_id: str
    timestamp: str
    type: str
    state: SessionState
    reason: str
    data: Mapping[str, Any]
    evidence: tuple[Mapping[str, Any], ...]
    schema: str = LIVE_EVENT_SCHEMA

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "event_id": self.event_id,
            "session_id": self.session_id,
            "timestamp": self.timestamp,
            "type": self.type,
            "state": self.state.value,
            "reason": self.reason,
            "data": dict(self.data),
            "evidence": [dict(item) for item in self.evidence],
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> LiveEvent:
        if payload.get("schema") != LIVE_EVENT_SCHEMA:
            raise ValueError("unsupported Live Lab event schema")
        evidence = payload.get("evidence", [])
        if not isinstance(evidence, list) or not all(
            isinstance(item, dict) for item in evidence
        ):
            raise ValueError("event evidence must be a list of objects")
        data = payload.get("data", {})
        if not isinstance(data, dict):
            raise ValueError("event data must be an object")
        return cls(
            event_id=int(payload["event_id"]),
            session_id=str(payload["session_id"]),
            timestamp=str(payload["timestamp"]),
            type=str(payload["type"]),
            state=SessionState(str(payload["state"])),
            reason=str(payload["reason"]),
            data=data,
            evidence=tuple(evidence),
        )


class EventStore:
    def __init__(
        self,
        session_dir: Path,
        snapshot: LiveSessionSnapshot,
        *,
        clock: Callable[[], str] = _utc_timestamp,
    ) -> None:
        self.session_dir = Path(session_dir)
        self.session_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
        self.events_path = self.session_dir / "events.jsonl"
        self.snapshot_path = self.session_dir / "session.json"
        self._clock = clock
        self._condition = Condition()
        self._events = list(self._load_events())
        latest_id = self._events[-1].event_id if self._events else 0
        if any(event.session_id != snapshot.session_id for event in self._events):
            raise ValueError("event log belongs to a different session")
        self._snapshot = replace(snapshot, latest_event_id=latest_id)

    @property
    def snapshot(self) -> LiveSessionSnapshot:
        with self._condition:
            return self._snapshot

    def append(
        self,
        event_type: str,
        state: SessionState,
        reason: str,
        data: Mapping[str, Any],
        evidence: tuple[Mapping[str, Any], ...],
        *,
        snapshot: LiveSessionSnapshot | None = None,
        durable: bool = False,
    ) -> LiveEvent:
        if not event_type.strip():
            raise ValueError("event type must not be empty")
        if not reason.strip():
            raise ValueError("event reason must not be empty")
        with self._condition:
            event_id = self._events[-1].event_id + 1 if self._events else 1
            event = LiveEvent(
                event_id=event_id,
                session_id=self._snapshot.session_id,
                timestamp=self._clock(),
                type=event_type,
                state=state,
                reason=reason.strip(),
                data=dict(data),
                evidence=tuple(dict(item) for item in evidence),
            )
            base_snapshot = self._snapshot if snapshot is None else snapshot
            if base_snapshot.session_id != event.session_id:
                raise ValueError("snapshot belongs to a different session")
            next_snapshot = replace(
                base_snapshot,
                state=state,
                state_reason=event.reason,
                latest_event_id=event_id,
            )
            encoded = (
                json.dumps(event.to_dict(), separators=(",", ":"), sort_keys=True)
                + "\n"
            ).encode("utf-8")
            state_changed = state is not self._snapshot.state
            with self.events_path.open("ab") as stream:
                stream.write(encoded)
                stream.flush()
                if durable or state_changed or evidence:
                    os.fsync(stream.fileno())
            write_json_atomic(self.snapshot_path, next_snapshot.to_dict())
            self._events.append(event)
            self._snapshot = next_snapshot
            self._condition.notify_all()
            return event

    def replay(self, after_id: int) -> tuple[LiveEvent, ...]:
        if after_id < 0:
            raise ValueError("after_id must not be negative")
        with self._condition:
            return tuple(event for event in self._events if event.event_id > after_id)

    def wait(self, after_id: int, timeout: float) -> tuple[LiveEvent, ...]:
        if timeout < 0:
            raise ValueError("timeout must not be negative")
        with self._condition:
            self._condition.wait_for(
                lambda: any(event.event_id > after_id for event in self._events),
                timeout=timeout,
            )
            return tuple(event for event in self._events if event.event_id > after_id)

    def _load_events(self) -> tuple[LiveEvent, ...]:
        if not self.events_path.is_file():
            return ()
        content = self.events_path.read_bytes()
        valid_chunks: list[bytes] = []
        events: list[LiveEvent] = []
        offset = 0
        corrupt_offset: int | None = None
        for chunk in content.splitlines(keepends=True):
            if not chunk.endswith((b"\n", b"\r")):
                corrupt_offset = offset
                break
            try:
                payload = json.loads(chunk.decode("utf-8"))
                event = LiveEvent.from_dict(payload)
            except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
                corrupt_offset = offset
                break
            if events and event.event_id != events[-1].event_id + 1:
                corrupt_offset = offset
                break
            if not events and event.event_id != 1:
                corrupt_offset = offset
                break
            valid_chunks.append(chunk)
            events.append(event)
            offset += len(chunk)
        if corrupt_offset is not None:
            self._quarantine(content[corrupt_offset:])
            self.events_path.write_bytes(b"".join(valid_chunks))
        return tuple(events)

    def _quarantine(self, content: bytes) -> None:
        index = 1
        while True:
            destination = self.session_dir / f"events-quarantine-{index:04d}.jsonl"
            try:
                with destination.open("xb") as stream:
                    stream.write(content)
                return
            except FileExistsError:
                index += 1


def format_sse(event: LiveEvent) -> bytes:
    payload = json.dumps(event.to_dict(), separators=(",", ":"), sort_keys=True)
    return f"id: {event.event_id}\nevent: {event.type}\ndata: {payload}\n\n".encode(
        "utf-8"
    )


def format_heartbeat() -> bytes:
    return b": heartbeat\n\n"
