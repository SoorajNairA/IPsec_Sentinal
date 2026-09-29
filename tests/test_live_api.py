from __future__ import annotations

from http.client import HTTPConnection
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
from types import SimpleNamespace
import itertools
import json
import unittest

from ipsec_sentinel.frontend.bridge import FrontendServerConfig, create_server
from ipsec_sentinel.live.orchestrator import LiveLabOrchestrator
from ipsec_sentinel.live.provider import LocalLabProvider
from tests.test_live_actions import ActionSession, fake_analysis
from tests.test_live_orchestrator import InlineExecutor
from tests.test_live_traffic import FakeGenerator, esp_summary


class LiveApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        static = root / "static"
        static.mkdir()
        (static / "index.html").write_text("Sentinel", encoding="utf-8")
        traffic_calls: list[object] = []
        times = itertools.count(100, 100)

        def session_factory(run_dir: Path, log: object, **_kwargs: object) -> ActionSession:
            return ActionSession(run_dir, log, pfs_status="VERIFIED_DISABLED")

        def derive(_source: Path, destination: Path, _window: object, _peers: object):
            destination.write_bytes(b"ESP-only API fixture")
            return SimpleNamespace(packet_count=12, capture_bytes=128, duration_seconds=2.0)

        def inspect(_path: Path, _window: object, _peers: object):
            return SimpleNamespace(packet_count=12, capture_bytes=128, duration_seconds=2.0)

        self.orchestrator = LiveLabOrchestrator(
            root / "runs",
            session_factory=session_factory,
            provider_factory=LocalLabProvider,
            executor=InlineExecutor(),
            id_factory=lambda: "SNT-API00001",
            mystery_selector=lambda _choices: "no-pfs",
            generator_factory=lambda name, seed: FakeGenerator(name, seed, traffic_calls),
            seed_factory=lambda: 717,
            time_ns=times.__next__,
            esp_summarizer=lambda _path, _prior: esp_summary(10),
            capture_deriver=derive,
            capture_inspector=inspect,
            analysis_runner=fake_analysis,
            model_dir=Path("missing-model"),
        )
        self.addCleanup(self.orchestrator.close)
        self.server = create_server(
            FrontendServerConfig(
                static_dir=static,
                model_dir=Path("missing-model"),
                port=0,
                enable_live_lab=True,
                live_runs_dir=root / "runs",
                sse_heartbeat_seconds=0.05,
            ),
            live_orchestrator=self.orchestrator,
        )
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.thread.join, 5)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.host, self.port = self.server.server_address

    def request(
        self,
        method: str,
        path: str,
        payload: object | None = None,
        *,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], dict[str, object]]:
        connection = HTTPConnection(self.host, self.port, timeout=10)
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request_headers = dict(headers or {})
        if payload is not None:
            request_headers.setdefault("Content-Type", "application/json")
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        raw = response.read()
        connection.close()
        decoded = {} if not raw else json.loads(raw)
        return response.status, response_headers, decoded

    def create(self, scenario: str = "mystery") -> str:
        status, _, payload = self.request(
            "POST",
            "/api/lab/sessions",
            {"scenario_id": scenario},
        )
        self.assertEqual(status, 201)
        return str(payload["session"]["session_id"])

    def test_all_routes_accept_valid_actions_and_return_public_snapshots(self) -> None:
        status, headers, scenarios = self.request("GET", "/api/lab/scenarios")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/json; charset=utf-8")
        self.assertNotIn("*", headers.get("access-control-allow-origin", ""))
        self.assertEqual(
            {item["id"] for item in scenarios["scenarios"]},
            {"secure-baseline", "aes128-gcm", "aes256-cbc", "no-pfs", "mystery"},
        )

        session_id = self.create()
        status, _, fetched = self.request("GET", f"/api/lab/sessions/{session_id}")
        self.assertEqual(status, 200)
        self.assertEqual(fetched["session"]["display_name"], "Mystery VPN #01")
        self.assertNotIn("no-pfs", json.dumps(fetched))

        actions = (
            ("connect", {}),
            ("traffic", {"workload_id": "video"}),
            ("rekey", {}),
            ("refresh", {}),
            ("analyze", {}),
            ("reveal", {}),
            ("disconnect", {}),
        )
        for action, body in actions:
            with self.subTest(action=action):
                status, _, payload = self.request(
                    "POST",
                    f"/api/lab/sessions/{session_id}/{action}",
                    body,
                )
                self.assertEqual(status, 202, payload)
                self.assertEqual(payload["status"], "accepted")
                self.assertEqual(payload["action"], action.upper())

        status, _, fetched = self.request("GET", f"/api/lab/sessions/{session_id}")
        self.assertEqual(status, 200)
        self.assertEqual(fetched["session"]["state"], "COMPLETE")
        self.assertTrue(fetched["session"]["revealed"])

    def test_problems_content_type_unknown_routes_and_offline_compatibility(self) -> None:
        session_id = self.create("secure-baseline")
        status, _, problem = self.request(
            "POST",
            f"/api/lab/sessions/{session_id}/traffic",
            {"workload_id": "icmp"},
        )
        self.assertEqual((status, problem["error"]["code"]), (409, "TUNNEL_NOT_ACTIVE"))

        status, _, problem = self.request(
            "POST",
            "/api/lab/sessions",
            None,
            headers={"Content-Type": "text/plain"},
        )
        self.assertEqual((status, problem["error"]["code"]), (415, "JSON_REQUIRED"))
        status, _, problem = self.request("GET", "/api/lab/sessions/SNT-MISSING1")
        self.assertEqual((status, problem["error"]["code"]), (404, "SESSION_NOT_FOUND"))
        status, _, problem = self.request("GET", "/api/lab/not-a-route")
        self.assertEqual((status, problem["error"]["code"]), (404, "NOT_FOUND"))

        capture = Path("tests/fixtures/esp-only.pcap").read_bytes()
        connection = HTTPConnection(self.host, self.port, timeout=10)
        connection.request(
            "POST",
            "/api/analyze",
            body=capture,
            headers={
                "Content-Type": "application/octet-stream",
                "X-Capture-Filename": "esp-only.pcap",
            },
        )
        response = connection.getresponse()
        payload = json.loads(response.read())
        connection.close()
        self.assertEqual(response.status, 200)
        self.assertEqual(payload["analysis"]["schema_id"], "ipsec-sentinel.analysis/v1")

    def test_non_loopback_host_is_rejected_without_cors(self) -> None:
        status, headers, payload = self.request(
            "GET",
            "/api/lab/scenarios",
            headers={"Host": "attacker.example"},
        )
        self.assertEqual((status, payload["error"]["code"]), (403, "LOOPBACK_HOST_REQUIRED"))
        self.assertNotIn("access-control-allow-origin", headers)

    def test_sse_replays_header_or_query_boundary_and_emits_heartbeats(self) -> None:
        session_id = self.create("secure-baseline")
        self.request("POST", f"/api/lab/sessions/{session_id}/connect", {})

        connection = HTTPConnection(self.host, self.port, timeout=10)
        connection.request(
            "GET",
            f"/api/lab/sessions/{session_id}/events",
            headers={"Last-Event-ID": "1"},
        )
        response = connection.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader("Content-Type"), "text/event-stream")
        self.assertEqual(response.readline(), b"id: 2\n")
        response.close()
        connection.close()

        latest = self.orchestrator.get_session(session_id).latest_event_id
        connection = HTTPConnection(self.host, self.port, timeout=10)
        connection.request(
            "GET",
            f"/api/lab/sessions/{session_id}/events?lastEventId={latest}",
        )
        response = connection.getresponse()
        self.assertEqual(response.readline(), b": heartbeat\n")
        response.close()
        connection.close()

    def test_sse_wait_notify_has_no_replay_to_live_gap(self) -> None:
        session_id = self.create("secure-baseline")
        latest = self.orchestrator.get_session(session_id).latest_event_id
        connection = HTTPConnection(self.host, self.port, timeout=10)
        connection.request(
            "GET",
            f"/api/lab/sessions/{session_id}/events?last_event_id={latest}",
        )
        response = connection.getresponse()

        self.request("POST", f"/api/lab/sessions/{session_id}/connect", {})

        observed_ids: list[int] = []
        while len(observed_ids) < 2:
            line = response.readline()
            if line.startswith(b"id: "):
                observed_ids.append(int(line.split(b":", 1)[1]))
        response.close()
        connection.close()
        self.assertEqual(observed_ids, [latest + 1, latest + 2])


if __name__ == "__main__":
    unittest.main()
