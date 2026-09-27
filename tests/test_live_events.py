from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
import json
import re
import unittest

from ipsec_sentinel.live.events import (
    EventStore,
    LiveEvent,
    format_heartbeat,
    format_sse,
)
from ipsec_sentinel.live.models import (
    CaptureStatus,
    CleanupStatus,
    LiveSessionSnapshot,
    SessionState,
    TunnelStatus,
)


def initial_snapshot() -> LiveSessionSnapshot:
    return LiveSessionSnapshot(
        session_id="SNT-8A31D2F0",
        display_name="Secure Baseline",
        state=SessionState.CREATING_SESSION,
        state_reason="allocating session",
        tunnel_status=TunnelStatus.INACTIVE,
        capture_status=CaptureStatus.NOT_STARTED,
        cleanup_status=CleanupStatus.NOT_RUN,
    )


class EventStoreTest(unittest.TestCase):
    def test_append_assigns_monotonic_ids_and_utc_timestamps(self) -> None:
        with TemporaryDirectory() as directory:
            store = EventStore(Path(directory), initial_snapshot())
            first = store.append(
                "session.created",
                SessionState.IDLE,
                "session persisted",
                {"display_name": "Secure Baseline"},
                (),
            )
            second = store.append(
                "sandbox.preparing",
                SessionState.PREPARING_SANDBOX,
                "connect action entered sandbox preparation",
                {},
                (),
            )
            self.assertEqual((first.event_id, second.event_id), (1, 2))
            self.assertRegex(
                first.timestamp,
                r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$",
            )
            self.assertEqual(store.replay(0), (first, second))
            self.assertEqual(store.replay(1), (second,))
            self.assertEqual(store.replay(2), ())

    def test_append_persists_event_and_atomic_snapshot_before_waiter_returns(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            store = EventStore(root, initial_snapshot())
            received: list[LiveEvent] = []
            waiter = Thread(target=lambda: received.extend(store.wait(0, 2.0)))
            waiter.start()
            expected_snapshot = replace(
                initial_snapshot(),
                state=SessionState.IDLE,
                state_reason="session persisted",
            )
            event = store.append(
                "session.created",
                SessionState.IDLE,
                "session persisted",
                {},
                ({"source": "orchestrator", "record": "create"},),
                snapshot=expected_snapshot,
                durable=True,
            )
            waiter.join(2.0)
            self.assertFalse(waiter.is_alive())
            self.assertEqual(received, [event])
            lines = (root / "events.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertEqual(json.loads(lines[0])["event_id"], 1)
            persisted = json.loads((root / "session.json").read_text(encoding="utf-8"))
            self.assertEqual(persisted["latest_event_id"], 1)
            self.assertEqual(persisted["state"], "IDLE")
            self.assertEqual(persisted["state_reason"], "session persisted")

    def test_incomplete_final_line_is_quarantined_without_losing_valid_events(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            root.mkdir(exist_ok=True)
            valid = {
                "schema": "ipsec-sentinel.live-event/v1",
                "event_id": 1,
                "session_id": "SNT-8A31D2F0",
                "timestamp": "2026-09-27T14:32:08.000Z",
                "type": "session.created",
                "state": "IDLE",
                "reason": "session persisted",
                "data": {},
                "evidence": [],
            }
            encoded = json.dumps(valid, separators=(",", ":")).encode("utf-8")
            (root / "events.jsonl").write_bytes(encoded + b"\n{\"event_id\":2")

            store = EventStore(root, initial_snapshot())

            self.assertEqual([event.event_id for event in store.replay(0)], [1])
            self.assertEqual((root / "events.jsonl").read_bytes(), encoded + b"\n")
            quarantines = tuple(root.glob("events-quarantine-*.jsonl"))
            self.assertEqual(len(quarantines), 1)
            self.assertEqual(quarantines[0].read_bytes(), b'{"event_id":2')
            next_event = store.append(
                "sandbox.preparing",
                SessionState.PREPARING_SANDBOX,
                "preparing",
                {},
                (),
            )
            self.assertEqual(next_event.event_id, 2)

    def test_concurrent_waiters_receive_one_copy_of_each_committed_event(self) -> None:
        with TemporaryDirectory() as directory:
            store = EventStore(Path(directory), initial_snapshot())
            results: list[list[int]] = [[], []]

            def collect(index: int) -> None:
                results[index] = [event.event_id for event in store.wait(0, 2.0)]

            waiters = [Thread(target=collect, args=(index,)) for index in range(2)]
            for waiter in waiters:
                waiter.start()
            store.append(
                "session.created", SessionState.IDLE, "session persisted", {}, ()
            )
            for waiter in waiters:
                waiter.join(2.0)
            self.assertEqual(results, [[1], [1]])

    def test_sse_frame_contains_id_type_and_compact_json(self) -> None:
        event = LiveEvent(
            event_id=7,
            session_id="SNT-8A31D2F0",
            timestamp="2026-09-27T14:32:10.312Z",
            type="child_sa.established",
            state=SessionState.CHILD_SA_ESTABLISHED,
            reason="swanctl reported an installed CHILD_SA",
            data={"spi": "0x1234"},
            evidence=(),
        )
        frame = format_sse(event).decode("utf-8")
        self.assertTrue(frame.startswith("id: 7\nevent: child_sa.established\ndata: "))
        self.assertTrue(frame.endswith("\n\n"))
        payload = json.loads(re.search(r"data: (.+)\n\n$", frame).group(1))  # type: ignore[union-attr]
        self.assertEqual(payload["state"], "CHILD_SA_ESTABLISHED")
        self.assertEqual(payload["data"], {"spi": "0x1234"})

    def test_heartbeat_is_transport_only_and_does_not_mutate_store(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            store = EventStore(root, initial_snapshot())
            before = store.snapshot
            self.assertEqual(format_heartbeat(), b": heartbeat\n\n")
            self.assertEqual(store.snapshot, before)
            self.assertEqual(store.replay(0), ())
            self.assertFalse((root / "events.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
