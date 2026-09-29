from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest

from ipsec_sentinel.live.models import CleanupStatus, LiveProblem, SessionState
from ipsec_sentinel.live.orchestrator import LiveLabOrchestrator
from ipsec_sentinel.live.runtime import LiveLabLock
from ipsec_sentinel.dataset.models import WorkloadWindow
from ipsec_sentinel.pcap import inspect_ml_pcap


LIVE_INTEGRATION_ENABLED = (
    os.environ.get("IPSEC_SENTINEL_LIVE_INTEGRATION") == "1"
    and hasattr(os, "geteuid")
    and os.geteuid() == 0
)


def _event_index(types: list[str], name: str) -> int:
    try:
        return types.index(name)
    except ValueError as error:
        raise AssertionError(f"missing live event: {name}; got {types}") from error


def _assert_no_lab_resources(session_id: str) -> None:
    namespaces = subprocess.run(
        ["ip", "netns", "list"], check=True, capture_output=True, text=True, timeout=5
    ).stdout
    for name in ("ips-client", "ips-gwa", "ips-gwb", "ips-server"):
        if name in namespaces:
            raise AssertionError(f"namespace leaked after Live Lab cleanup: {name}")
    for interface in (
        "veth-c", "veth-a-lan", "veth-a-wan", "veth-b-wan", "veth-b-lan", "veth-s"
    ):
        result = subprocess.run(
            ["ip", "link", "show", interface], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            raise AssertionError(f"root veth leaked after Live Lab cleanup: {interface}")
    processes = subprocess.run(
        ["ps", "-eo", "args="], check=True, capture_output=True, text=True, timeout=5
    ).stdout
    leaked = [line for line in processes.splitlines() if session_id in line and ("charon" in line or "tcpdump" in line)]
    if leaked:
        raise AssertionError(f"Live Lab process leaked: {leaked}")
    if (Path("/run/ipsec-sentinel") / session_id).exists():
        raise AssertionError(f"Live Lab runtime directory leaked: {session_id}")


@unittest.skipUnless(
    LIVE_INTEGRATION_ENABLED,
    "set IPSEC_SENTINEL_LIVE_INTEGRATION=1 and run as Linux root",
)
class LiveLabIntegrationTest(unittest.TestCase):
    def test_real_interactive_session_and_cleanup(self) -> None:
        model_dir_value = os.environ.get("IPSEC_SENTINEL_MODEL_DIR")
        self.assertTrue(model_dir_value, "IPSEC_SENTINEL_MODEL_DIR is required")
        model_dir = Path(str(model_dir_value))
        self.assertTrue((model_dir / "model.joblib").is_file(), model_dir)

        with TemporaryDirectory(prefix="ipsec-sentinel-live-", dir="/tmp") as directory:
            root = Path(directory)
            orchestrator = LiveLabOrchestrator(root, model_dir=model_dir)
            session_id = ""
            try:
                created = orchestrator.create_session("secure-baseline")
                session_id = created.session_id
                with self.assertRaises(LiveProblem) as duplicate:
                    orchestrator.create_session("aes128-gcm")
                self.assertEqual(duplicate.exception.code, "ACTIVE_SESSION_EXISTS")

                orchestrator.submit(session_id, "CONNECT", {}).result(timeout=90)
                connected = orchestrator.get_session(session_id)
                self.assertEqual(connected.state, SessionState.TUNNEL_ACTIVE)
                self.assertTrue(connected.child_sa_established)
                self.assertEqual(connected.capture_status.value, "RUNNING")
                connect_events = orchestrator.events(session_id, 0)
                connect_types = [event.type for event in connect_events]
                ordered = [
                    "capture.started",
                    "ike.sa_init.request",
                    "ike.sa_init.response",
                    "ike.proposal.selected",
                    "child_sa.verified",
                    "xfrm.verified",
                    "tunnel.active",
                ]
                self.assertEqual(
                    [_event_index(connect_types, name) for name in ordered],
                    sorted(_event_index(connect_types, name) for name in ordered),
                )

                orchestrator.run_traffic(session_id, "icmp").result(timeout=90)
                after_icmp_id = orchestrator.get_session(session_id).latest_event_id
                orchestrator.run_traffic(session_id, "video").result(timeout=120)
                traffic_events = orchestrator.events(session_id, after_icmp_id)
                self.assertTrue(any(event.type == "traffic.started" and event.data.get("workload") == "video" for event in traffic_events))
                esp_events = [event for event in traffic_events if event.type == "esp.observed"]
                self.assertTrue(esp_events)
                self.assertGreater(int(esp_events[-1].data["packet_delta"]), 0)
                workload = orchestrator.get_session(session_id).completed_workloads[-1]
                self.assertEqual(workload.workload_id, "video")

                rekey_start = orchestrator.get_session(session_id).latest_event_id
                orchestrator.trigger_rekey(session_id).result(timeout=90)
                rekey_events = orchestrator.events(session_id, rekey_start)
                rekey = next(event for event in rekey_events if event.type == "child_sa.rekeyed")
                self.assertEqual(rekey.data["verification_state"], "enabled")
                self.assertEqual(rekey.data["observed"]["status"], "VERIFIED")  # type: ignore[index]
                self.assertNotEqual(rekey.data["before_spis"], rekey.data["after_spis"])

                replay_cursor = orchestrator.get_session(session_id).latest_event_id
                orchestrator.analyze(session_id).result(timeout=120)
                replayed = orchestrator.events(session_id, replay_cursor)
                self.assertTrue(any(event.type == "capture.sealed" for event in replayed))
                analysis_event = next(event for event in replayed if event.type == "analysis.completed")
                analysis = dict(analysis_event.data["analysis"])  # type: ignore[arg-type]
                self.assertEqual(analysis["summary"]["status"], "COMPLETE")  # type: ignore[index]
                self.assertEqual(analysis["traffic_intelligence"]["predicted_class"], "video")  # type: ignore[index]
                self.assertFalse(analysis["traffic_intelligence"]["payload_decrypted"])  # type: ignore[index]

                run_dir = root / session_id
                truth = json.loads((run_dir / "ground_truth.json").read_text(encoding="utf-8"))
                window = truth["capture"]
                summary = inspect_ml_pcap(
                    run_dir / "encrypted.pcap",
                    WorkloadWindow(
                        int(window["workload_started_unix_ns"]),
                        int(window["workload_finished_unix_ns"]),
                    ),
                    ("192.0.2.1", "192.0.2.2"),
                )
                self.assertGreater(summary.packet_count, 0)
                self.assertEqual(truth["traffic"]["class"], "video")

                last_id = orchestrator.get_session(session_id).latest_event_id
                self.assertEqual(orchestrator.events(session_id, last_id), ())
                self.assertEqual(
                    [event.event_id for event in orchestrator.events(session_id, last_id - 2)],
                    [last_id - 1, last_id],
                )

                orchestrator.disconnect(session_id).result(timeout=90)
                complete = orchestrator.get_session(session_id)
                self.assertEqual(complete.state, SessionState.COMPLETE)
                self.assertEqual(complete.cleanup_status, CleanupStatus.SUCCEEDED)
                _assert_no_lab_resources(session_id)
            finally:
                orchestrator.close()
            probe = LiveLabLock.acquire(root / ".live-lab.lock")
            probe.release()
            if session_id:
                _assert_no_lab_resources(session_id)


if __name__ == "__main__":
    unittest.main()
