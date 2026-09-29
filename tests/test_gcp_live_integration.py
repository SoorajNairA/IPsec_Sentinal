from __future__ import annotations

import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from ipsec_sentinel.cloud import GcpLabConfig, provider_factory, session_factory
from ipsec_sentinel.live.models import CleanupStatus, SessionState, TunnelStatus
from ipsec_sentinel.live.orchestrator import LiveLabOrchestrator


@unittest.skipUnless(
    os.environ.get("IPSEC_SENTINEL_GCP_INTEGRATION") == "1",
    "set IPSEC_SENTINEL_GCP_INTEGRATION=1 for the billable GCP smoke",
)
class GcpLiveIntegrationTest(unittest.TestCase):
    def test_mystery_icmp_video_rekey_analysis_and_cleanup(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("GCP Live Lab integration requires Linux root")
        config_path = os.environ.get("IPSEC_SENTINEL_GCP_CONFIG")
        model_dir = os.environ.get("IPSEC_SENTINEL_MODEL_DIR")
        if not config_path or not model_dir:
            self.fail("IPSEC_SENTINEL_GCP_CONFIG and IPSEC_SENTINEL_MODEL_DIR are required")
        config = GcpLabConfig.load(Path(config_path))
        with TemporaryDirectory(prefix="ipsec-sentinel-gcp-e2e-") as directory:
            orchestrator = LiveLabOrchestrator(
                Path(directory),
                session_factory=session_factory(config),
                provider_factory=provider_factory(config),
                workload_allowlist=frozenset({"icmp", "video"}),
                model_dir=Path(model_dir),
            )
            session_id = ""
            try:
                created = orchestrator.create_session("mystery")
                session_id = created.session_id
                orchestrator.submit(session_id, "CONNECT", {}).result(timeout=420)
                active = orchestrator.get_session(session_id)
                self.assertEqual(active.state, SessionState.TUNNEL_ACTIVE)
                self.assertEqual(active.tunnel_status, TunnelStatus.ACTIVE)
                baseline_event_id = active.latest_event_id
                orchestrator.run_traffic(session_id, "icmp").result(timeout=90)
                orchestrator.run_traffic(session_id, "video").result(timeout=120)
                orchestrator.trigger_rekey(session_id).result(timeout=120)
                orchestrator.analyze(session_id).result(timeout=240)
                ready = orchestrator.get_session(session_id)
                self.assertEqual(ready.state, SessionState.READY)
                self.assertTrue(ready.analysis_available)
                replay = orchestrator.events(session_id, baseline_event_id)
                event_types = {event.type for event in replay}
                self.assertIn("traffic.completed", event_types)
                self.assertIn("esp.observed", event_types)
                self.assertIn("child_sa.rekeyed", event_types)
                self.assertIn("analysis.completed", event_types)
                orchestrator.reveal(session_id).result(timeout=30)
                orchestrator.disconnect(session_id).result(timeout=300)
                complete = orchestrator.get_session(session_id)
                self.assertEqual(complete.state, SessionState.COMPLETE)
                self.assertEqual(complete.cleanup_status, CleanupStatus.SUCCEEDED)
            finally:
                if session_id:
                    snapshot = orchestrator.get_session(session_id)
                    if snapshot.state is not SessionState.COMPLETE:
                        try:
                            orchestrator.disconnect(session_id).result(timeout=300)
                        except BaseException:
                            pass
                orchestrator.close()


if __name__ == "__main__":
    unittest.main()
