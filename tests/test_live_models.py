from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import unittest

from ipsec_sentinel.live.models import (
    CaptureStatus,
    CleanupStatus,
    LiveAction,
    LiveProblem,
    LiveSessionSnapshot,
    SessionState,
    TunnelStatus,
    WorkloadWindow,
    allowed_actions,
    transition,
    validate_action,
)


def snapshot(**changes: object) -> LiveSessionSnapshot:
    base = LiveSessionSnapshot(
        session_id="SNT-8A31D2F0",
        display_name="Secure Baseline",
        state=SessionState.IDLE,
        state_reason="session created",
        tunnel_status=TunnelStatus.INACTIVE,
        capture_status=CaptureStatus.NOT_STARTED,
        cleanup_status=CleanupStatus.NOT_RUN,
    )
    return replace(base, **changes)


def completed_video() -> WorkloadWindow:
    return WorkloadWindow(
        sequence=2,
        workload_id="video",
        seed=4932,
        started_at="2026-09-27T14:32:14.000Z",
        ended_at="2026-09-27T14:32:18.000Z",
        started_unix_ns=1_799_501_534_000_000_000,
        ended_unix_ns=1_799_501_538_000_000_000,
        validated=True,
        metadata={"segments": 6},
    )


class LiveSessionModelTest(unittest.TestCase):
    def test_state_enum_is_the_approved_lifecycle(self) -> None:
        self.assertEqual(
            [state.value for state in SessionState],
            [
                "CREATING_SESSION",
                "IDLE",
                "PREPARING_SANDBOX",
                "STARTING_ENDPOINT",
                "WAITING_FOR_ENDPOINT",
                "STARTING_CAPTURE",
                "IKE_NEGOTIATING",
                "AUTHENTICATING",
                "CHILD_SA_ESTABLISHED",
                "TUNNEL_ACTIVE",
                "TRAFFIC_RUNNING",
                "REKEYING",
                "ANALYZING",
                "READY",
                "DISCONNECTING",
                "CLEANING_UP",
                "COMPLETE",
                "FAILED",
            ],
        )

    def test_statuses_remain_orthogonal_and_snapshot_is_immutable(self) -> None:
        current = snapshot(
            state=SessionState.FAILED,
            tunnel_status=TunnelStatus.FAILED,
            capture_status=CaptureStatus.SEALED,
            cleanup_status=CleanupStatus.SUCCEEDED,
        )
        self.assertEqual(current.state, SessionState.FAILED)
        self.assertEqual(current.capture_status, CaptureStatus.SEALED)
        self.assertEqual(current.cleanup_status, CleanupStatus.SUCCEEDED)
        with self.assertRaises(FrozenInstanceError):
            current.state = SessionState.COMPLETE  # type: ignore[misc]

    def test_idle_session_allows_only_connect_or_disconnect(self) -> None:
        current = snapshot()
        self.assertEqual(
            allowed_actions(current),
            (LiveAction.CONNECT, LiveAction.DISCONNECT),
        )
        validate_action(current, LiveAction.CONNECT)
        with self.assertRaisesRegex(LiveProblem, "active verified tunnel") as caught:
            validate_action(current, LiveAction.TRAFFIC)
        self.assertEqual(caught.exception.code, "TUNNEL_NOT_ACTIVE")
        self.assertEqual(caught.exception.http_status, 409)

    def test_tunnel_actions_require_child_sa_and_successful_workload(self) -> None:
        active = snapshot(
            state=SessionState.TUNNEL_ACTIVE,
            tunnel_status=TunnelStatus.ACTIVE,
            capture_status=CaptureStatus.RUNNING,
        )
        self.assertEqual(
            allowed_actions(active),
            (LiveAction.TRAFFIC, LiveAction.REFRESH, LiveAction.DISCONNECT),
        )
        with self.assertRaises(LiveProblem) as caught:
            validate_action(active, LiveAction.REKEY)
        self.assertEqual(caught.exception.code, "CHILD_SA_NOT_ESTABLISHED")
        with self.assertRaises(LiveProblem) as caught:
            validate_action(active, LiveAction.ANALYZE)
        self.assertEqual(caught.exception.code, "WORKLOAD_REQUIRED")

        ready_for_actions = replace(
            active,
            child_sa_established=True,
            completed_workloads=(completed_video(),),
            latest_completed_workload_sequence=2,
        )
        self.assertEqual(
            allowed_actions(ready_for_actions),
            (
                LiveAction.TRAFFIC,
                LiveAction.REKEY,
                LiveAction.REFRESH,
                LiveAction.ANALYZE,
                LiveAction.DISCONNECT,
            ),
        )

    def test_busy_session_rejects_every_second_command(self) -> None:
        busy = snapshot(
            state=SessionState.TRAFFIC_RUNNING,
            tunnel_status=TunnelStatus.ACTIVE,
            capture_status=CaptureStatus.RUNNING,
            active_action=LiveAction.TRAFFIC,
            child_sa_established=True,
        )
        self.assertEqual(allowed_actions(busy), ())
        with self.assertRaises(LiveProblem) as caught:
            validate_action(busy, LiveAction.DISCONNECT)
        self.assertEqual(caught.exception.code, "SESSION_BUSY")

    def test_ready_session_forbids_capture_changing_actions(self) -> None:
        ready = snapshot(
            state=SessionState.READY,
            tunnel_status=TunnelStatus.ACTIVE,
            capture_status=CaptureStatus.SEALED,
            analysis_available=True,
            mystery=True,
        )
        self.assertEqual(
            allowed_actions(ready),
            (LiveAction.REVEAL, LiveAction.DISCONNECT),
        )
        for action in (LiveAction.TRAFFIC, LiveAction.REKEY, LiveAction.ANALYZE):
            with self.subTest(action=action):
                with self.assertRaises(LiveProblem) as caught:
                    validate_action(ready, action)
                self.assertEqual(caught.exception.code, "CAPTURE_SEALED")

    def test_reveal_requires_analyzed_unrevealed_mystery(self) -> None:
        normal = snapshot(state=SessionState.READY, analysis_available=True)
        with self.assertRaises(LiveProblem) as caught:
            validate_action(normal, LiveAction.REVEAL)
        self.assertEqual(caught.exception.code, "NOT_A_MYSTERY_SESSION")

        revealed = replace(normal, mystery=True, revealed=True)
        with self.assertRaises(LiveProblem) as caught:
            validate_action(revealed, LiveAction.REVEAL)
        self.assertEqual(caught.exception.code, "MYSTERY_ALREADY_REVEALED")

    def test_disconnect_is_idempotent_after_complete(self) -> None:
        complete = snapshot(
            state=SessionState.COMPLETE,
            tunnel_status=TunnelStatus.DISCONNECTED,
            capture_status=CaptureStatus.STOPPED,
            cleanup_status=CleanupStatus.SUCCEEDED,
        )
        self.assertEqual(allowed_actions(complete), (LiveAction.DISCONNECT,))
        validate_action(complete, LiveAction.DISCONNECT)

    def test_transition_requires_an_allowed_edge_and_reason(self) -> None:
        current = snapshot(state=SessionState.CREATING_SESSION)
        idle = transition(current, SessionState.IDLE, "session persisted")
        self.assertEqual(idle.state, SessionState.IDLE)
        self.assertEqual(idle.state_reason, "session persisted")
        with self.assertRaises(LiveProblem) as caught:
            transition(idle, SessionState.TUNNEL_ACTIVE, "skip evidence")
        self.assertEqual(caught.exception.code, "INVALID_STATE_TRANSITION")
        with self.assertRaises(ValueError):
            transition(idle, SessionState.PREPARING_SANDBOX, "  ")

    def test_public_snapshot_has_no_private_mystery_identity_field(self) -> None:
        mystery = snapshot(display_name="Mystery VPN #03", mystery=True)
        payload = mystery.to_dict()
        self.assertEqual(payload["display_name"], "Mystery VPN #03")
        self.assertNotIn("scenario_id", payload)
        self.assertNotIn("ground_truth", payload)
        self.assertEqual(payload["allowed_actions"], ["CONNECT", "DISCONNECT"])
        self.assertEqual(payload["latest_event_id"], 0)
        self.assertEqual(payload["completed_workloads"], [])


if __name__ == "__main__":
    unittest.main()
