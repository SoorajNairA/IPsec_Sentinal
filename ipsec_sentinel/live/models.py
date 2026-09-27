from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Mapping


class SessionState(str, Enum):
    CREATING_SESSION = "CREATING_SESSION"
    IDLE = "IDLE"
    PREPARING_SANDBOX = "PREPARING_SANDBOX"
    STARTING_ENDPOINT = "STARTING_ENDPOINT"
    WAITING_FOR_ENDPOINT = "WAITING_FOR_ENDPOINT"
    STARTING_CAPTURE = "STARTING_CAPTURE"
    IKE_NEGOTIATING = "IKE_NEGOTIATING"
    AUTHENTICATING = "AUTHENTICATING"
    CHILD_SA_ESTABLISHED = "CHILD_SA_ESTABLISHED"
    TUNNEL_ACTIVE = "TUNNEL_ACTIVE"
    TRAFFIC_RUNNING = "TRAFFIC_RUNNING"
    REKEYING = "REKEYING"
    ANALYZING = "ANALYZING"
    READY = "READY"
    DISCONNECTING = "DISCONNECTING"
    CLEANING_UP = "CLEANING_UP"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


class TunnelStatus(str, Enum):
    INACTIVE = "INACTIVE"
    ACTIVE = "ACTIVE"
    DISCONNECTED = "DISCONNECTED"
    FAILED = "FAILED"


class CaptureStatus(str, Enum):
    NOT_STARTED = "NOT_STARTED"
    RUNNING = "RUNNING"
    SEALED = "SEALED"
    STOPPED = "STOPPED"
    FAILED = "FAILED"


class CleanupStatus(str, Enum):
    NOT_RUN = "NOT_RUN"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class LiveAction(str, Enum):
    CONNECT = "CONNECT"
    TRAFFIC = "TRAFFIC"
    REKEY = "REKEY"
    REFRESH = "REFRESH"
    ANALYZE = "ANALYZE"
    REVEAL = "REVEAL"
    DISCONNECT = "DISCONNECT"


class LiveProblem(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        http_status: int = 409,
        session_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status
        self.session_id = session_id

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {"code": self.code, "message": self.message}
        if self.session_id is not None:
            payload["session_id"] = self.session_id
        return {"error": payload}


@dataclass(frozen=True)
class WorkloadWindow:
    sequence: int
    workload_id: str
    seed: int
    started_at: str
    ended_at: str
    started_unix_ns: int
    ended_unix_ns: int
    validated: bool
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "sequence": self.sequence,
            "workload_id": self.workload_id,
            "seed": self.seed,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "started_unix_ns": self.started_unix_ns,
            "ended_unix_ns": self.ended_unix_ns,
            "validated": self.validated,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class LiveSessionSnapshot:
    session_id: str
    display_name: str
    state: SessionState
    state_reason: str
    tunnel_status: TunnelStatus
    capture_status: CaptureStatus
    cleanup_status: CleanupStatus
    active_action: LiveAction | None = None
    child_sa_established: bool = False
    completed_workloads: tuple[WorkloadWindow, ...] = ()
    latest_completed_workload_sequence: int | None = None
    latest_event_id: int = 0
    analysis_available: bool = False
    mystery: bool = False
    revealed: bool = False
    failure: Mapping[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "session_id": self.session_id,
            "display_name": self.display_name,
            "state": self.state.value,
            "state_reason": self.state_reason,
            "tunnel_status": self.tunnel_status.value,
            "capture_status": self.capture_status.value,
            "cleanup_status": self.cleanup_status.value,
            "active_action": (
                None if self.active_action is None else self.active_action.value
            ),
            "child_sa_established": self.child_sa_established,
            "completed_workloads": [
                workload.to_dict() for workload in self.completed_workloads
            ],
            "latest_completed_workload_sequence": (
                self.latest_completed_workload_sequence
            ),
            "latest_event_id": self.latest_event_id,
            "analysis_available": self.analysis_available,
            "mystery": self.mystery,
            "revealed": self.revealed,
            "failure": None if self.failure is None else dict(self.failure),
            "allowed_actions": [action.value for action in allowed_actions(self)],
        }


_TRANSITIONS: dict[SessionState, frozenset[SessionState]] = {
    SessionState.CREATING_SESSION: frozenset(
        (SessionState.IDLE, SessionState.FAILED)
    ),
    SessionState.IDLE: frozenset(
        (
            SessionState.PREPARING_SANDBOX,
            SessionState.DISCONNECTING,
            SessionState.FAILED,
        )
    ),
    SessionState.PREPARING_SANDBOX: frozenset(
        (SessionState.STARTING_ENDPOINT, SessionState.CLEANING_UP, SessionState.FAILED)
    ),
    SessionState.STARTING_ENDPOINT: frozenset(
        (SessionState.WAITING_FOR_ENDPOINT, SessionState.CLEANING_UP, SessionState.FAILED)
    ),
    SessionState.WAITING_FOR_ENDPOINT: frozenset(
        (SessionState.STARTING_CAPTURE, SessionState.CLEANING_UP, SessionState.FAILED)
    ),
    SessionState.STARTING_CAPTURE: frozenset(
        (SessionState.IKE_NEGOTIATING, SessionState.CLEANING_UP, SessionState.FAILED)
    ),
    SessionState.IKE_NEGOTIATING: frozenset(
        (SessionState.AUTHENTICATING, SessionState.CLEANING_UP, SessionState.FAILED)
    ),
    SessionState.AUTHENTICATING: frozenset(
        (
            SessionState.CHILD_SA_ESTABLISHED,
            SessionState.CLEANING_UP,
            SessionState.FAILED,
        )
    ),
    SessionState.CHILD_SA_ESTABLISHED: frozenset(
        (SessionState.TUNNEL_ACTIVE, SessionState.CLEANING_UP, SessionState.FAILED)
    ),
    SessionState.TUNNEL_ACTIVE: frozenset(
        (
            SessionState.TRAFFIC_RUNNING,
            SessionState.REKEYING,
            SessionState.ANALYZING,
            SessionState.DISCONNECTING,
            SessionState.CLEANING_UP,
            SessionState.FAILED,
        )
    ),
    SessionState.TRAFFIC_RUNNING: frozenset(
        (SessionState.TUNNEL_ACTIVE, SessionState.CLEANING_UP, SessionState.FAILED)
    ),
    SessionState.REKEYING: frozenset(
        (SessionState.TUNNEL_ACTIVE, SessionState.CLEANING_UP, SessionState.FAILED)
    ),
    SessionState.ANALYZING: frozenset(
        (SessionState.READY, SessionState.CLEANING_UP, SessionState.FAILED)
    ),
    SessionState.READY: frozenset(
        (SessionState.DISCONNECTING, SessionState.CLEANING_UP, SessionState.FAILED)
    ),
    SessionState.DISCONNECTING: frozenset(
        (SessionState.CLEANING_UP, SessionState.COMPLETE, SessionState.FAILED)
    ),
    SessionState.CLEANING_UP: frozenset(
        (SessionState.COMPLETE, SessionState.FAILED)
    ),
    SessionState.FAILED: frozenset(
        (SessionState.DISCONNECTING, SessionState.CLEANING_UP)
    ),
    SessionState.COMPLETE: frozenset(),
}


def transition(
    snapshot: LiveSessionSnapshot,
    target: SessionState,
    reason: str,
) -> LiveSessionSnapshot:
    normalized_reason = reason.strip()
    if not normalized_reason:
        raise ValueError("state transition reason must not be empty")
    if target not in _TRANSITIONS[snapshot.state]:
        raise LiveProblem(
            "INVALID_STATE_TRANSITION",
            f"Cannot transition from {snapshot.state.value} to {target.value}.",
            session_id=snapshot.session_id,
        )
    return replace(snapshot, state=target, state_reason=normalized_reason)


def allowed_actions(snapshot: LiveSessionSnapshot) -> tuple[LiveAction, ...]:
    if snapshot.active_action is not None:
        return ()
    if snapshot.state is SessionState.IDLE:
        return (LiveAction.CONNECT, LiveAction.DISCONNECT)
    if (
        snapshot.state is SessionState.TUNNEL_ACTIVE
        and snapshot.tunnel_status is TunnelStatus.ACTIVE
        and snapshot.capture_status is CaptureStatus.RUNNING
    ):
        actions = [LiveAction.TRAFFIC]
        if snapshot.child_sa_established:
            actions.append(LiveAction.REKEY)
        actions.append(LiveAction.REFRESH)
        if snapshot.latest_completed_workload_sequence is not None:
            actions.append(LiveAction.ANALYZE)
        actions.append(LiveAction.DISCONNECT)
        return tuple(actions)
    if snapshot.state is SessionState.READY:
        actions: list[LiveAction] = []
        if snapshot.mystery and not snapshot.revealed:
            actions.append(LiveAction.REVEAL)
        actions.append(LiveAction.DISCONNECT)
        return tuple(actions)
    if snapshot.state in (SessionState.FAILED, SessionState.COMPLETE):
        return (LiveAction.DISCONNECT,)
    return ()


def validate_action(snapshot: LiveSessionSnapshot, action: LiveAction) -> None:
    if snapshot.active_action is not None:
        raise LiveProblem(
            "SESSION_BUSY",
            f"Session is already running {snapshot.active_action.value}.",
            session_id=snapshot.session_id,
        )
    if action in allowed_actions(snapshot):
        return
    if action in (LiveAction.TRAFFIC, LiveAction.REKEY, LiveAction.ANALYZE):
        if snapshot.capture_status is CaptureStatus.SEALED:
            raise LiveProblem(
                "CAPTURE_SEALED",
                "The session capture is sealed; this action cannot change it.",
                session_id=snapshot.session_id,
            )
        if snapshot.tunnel_status is not TunnelStatus.ACTIVE:
            raise LiveProblem(
                "TUNNEL_NOT_ACTIVE",
                "This action requires an active verified tunnel.",
                session_id=snapshot.session_id,
            )
    if action is LiveAction.REKEY and not snapshot.child_sa_established:
        raise LiveProblem(
            "CHILD_SA_NOT_ESTABLISHED",
            "Rekey requires an established CHILD_SA.",
            session_id=snapshot.session_id,
        )
    if action is LiveAction.ANALYZE:
        raise LiveProblem(
            "WORKLOAD_REQUIRED",
            "Analyze requires a successfully completed workload.",
            session_id=snapshot.session_id,
        )
    if action is LiveAction.REVEAL:
        if not snapshot.mystery:
            code = "NOT_A_MYSTERY_SESSION"
            message = "Reveal is available only for a Mystery session."
        elif snapshot.revealed:
            code = "MYSTERY_ALREADY_REVEALED"
            message = "Mystery ground truth has already been revealed."
        else:
            code = "ANALYSIS_NOT_READY"
            message = "Mystery ground truth can be revealed only after analysis."
        raise LiveProblem(code, message, session_id=snapshot.session_id)
    if action is LiveAction.CONNECT:
        code, message = "CONNECT_NOT_ALLOWED", "Connect is not valid in this state."
    elif action is LiveAction.DISCONNECT:
        code, message = (
            "DISCONNECT_NOT_ALLOWED",
            "Disconnect is not valid in this state.",
        )
    else:
        code, message = "ACTION_NOT_ALLOWED", "Action is not valid in this state."
    raise LiveProblem(code, message, session_id=snapshot.session_id)
