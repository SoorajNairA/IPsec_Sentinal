from __future__ import annotations

from dataclasses import dataclass
from http import HTTPStatus
from typing import Mapping

from ipsec_sentinel.live.events import LiveEvent
from ipsec_sentinel.live.models import LiveAction, LiveProblem
from ipsec_sentinel.live.orchestrator import LiveLabOrchestrator
from ipsec_sentinel.live.provider import SCENARIO_NAMES
from ipsec_sentinel.traffic.base import SUPERVISED_CLASS_ALLOWLIST


@dataclass(frozen=True)
class ApiResponse:
    status: HTTPStatus
    payload: Mapping[str, object]


class LiveLabApi:
    def __init__(self, orchestrator: LiveLabOrchestrator) -> None:
        self.orchestrator = orchestrator

    def scenarios(self) -> ApiResponse:
        scenarios = [
            {
                "id": scenario_id,
                "display_name": SCENARIO_NAMES[scenario_id],
                "mystery": False,
            }
            for scenario_id in SCENARIO_NAMES
        ]
        scenarios.append(
            {
                "id": "mystery",
                "display_name": "Mystery VPN",
                "mystery": True,
            }
        )
        return ApiResponse(
            HTTPStatus.OK,
            {
                "scenarios": scenarios,
                "workloads": sorted(self.orchestrator.workload_allowlist),
            },
        )

    def create_session(self, payload: Mapping[str, object]) -> ApiResponse:
        _require_keys(payload, {"scenario_id"})
        scenario_id = payload["scenario_id"]
        if not isinstance(scenario_id, str):
            raise LiveProblem(
                "INVALID_REQUEST",
                "scenario_id must be a string.",
                http_status=400,
            )
        snapshot = self.orchestrator.create_session(scenario_id)
        return ApiResponse(HTTPStatus.CREATED, {"session": snapshot.to_dict()})

    def get_session(self, session_id: str) -> ApiResponse:
        return ApiResponse(
            HTTPStatus.OK,
            {"session": self.orchestrator.get_session(session_id).to_dict()},
        )

    def command(
        self,
        session_id: str,
        action_name: str,
        payload: Mapping[str, object],
    ) -> ApiResponse:
        try:
            action = LiveAction(action_name.upper())
        except ValueError as error:
            raise LiveProblem(
                "NOT_FOUND",
                "Unknown Live Lab route.",
                http_status=404,
                session_id=session_id,
            ) from error
        if action is LiveAction.TRAFFIC:
            _require_keys(payload, {"workload_id"})
            workload_id = payload["workload_id"]
            if not isinstance(workload_id, str):
                raise LiveProblem(
                    "INVALID_REQUEST",
                    "workload_id must be a string.",
                    http_status=400,
                    session_id=session_id,
                )
            self.orchestrator.run_traffic(session_id, workload_id)
        else:
            _require_keys(payload, set())
            methods = {
                LiveAction.CONNECT: lambda: self.orchestrator.submit(
                    session_id, action, {}
                ),
                LiveAction.REKEY: lambda: self.orchestrator.trigger_rekey(session_id),
                LiveAction.REFRESH: lambda: self.orchestrator.refresh(session_id),
                LiveAction.ANALYZE: lambda: self.orchestrator.analyze(session_id),
                LiveAction.REVEAL: lambda: self.orchestrator.reveal(session_id),
                LiveAction.DISCONNECT: lambda: self.orchestrator.disconnect(session_id),
            }
            try:
                methods[action]()
            except KeyError as error:
                raise LiveProblem(
                    "NOT_FOUND",
                    "Unknown Live Lab route.",
                    http_status=404,
                    session_id=session_id,
                ) from error
        return ApiResponse(
            HTTPStatus.ACCEPTED,
            {
                "status": "accepted",
                "session_id": session_id,
                "action": action.value,
            },
        )

    def events(self, session_id: str, after_id: int) -> tuple[LiveEvent, ...]:
        return self.orchestrator.events(session_id, after_id)

    def wait_events(
        self,
        session_id: str,
        after_id: int,
        timeout: float,
    ) -> tuple[LiveEvent, ...]:
        return self.orchestrator.wait_events(session_id, after_id, timeout)


def _require_keys(payload: Mapping[str, object], expected: set[str]) -> None:
    if set(payload) != expected:
        raise LiveProblem(
            "INVALID_REQUEST",
            f"request must contain exactly: {', '.join(sorted(expected)) or 'no fields'}.",
            http_status=400,
        )
