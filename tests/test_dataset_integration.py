from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest

from ipsec_sentinel.dataset.manifest import AttemptPlan, Manifest
from ipsec_sentinel.dataset.models import AttemptOutcome, RunState, WorkloadWindow
from ipsec_sentinel.dataset.runner import generate_dataset, run_dataset_attempt
from ipsec_sentinel.pcap import inspect_ml_pcap


DATASET_INTEGRATION_ENABLED = (
    os.environ.get("IPSEC_SENTINEL_DATASET_INTEGRATION") == "1"
    and hasattr(os, "geteuid")
    and os.geteuid() == 0
)


def write_one_slot_config(
    root: Path,
    dataset_name: str,
    traffic_class: str,
    seed: int,
    retry_failed: int = 0,
) -> Path:
    path = root / f"{dataset_name}.yaml"
    path.write_text(
        f"""dataset:
  name: {dataset_name}
  schema_version: ipsec-sentinel.dataset-ground-truth/v1
  seed: {seed}
traffic:
  classes: [{traffic_class}]
ipsec:
  scenarios: [secure-baseline]
network_profiles: [clean]
runs_per_combination: 1
execution:
  workers: 1
  retry_failed: {retry_failed}
""",
        encoding="utf-8",
    )
    return path


def assert_no_lab_resources(run_id: str) -> None:
    namespaces = subprocess.run(
        ["ip", "netns", "list"],
        text=True,
        capture_output=True,
        check=True,
        timeout=5,
    ).stdout
    for name in ("ips-client", "ips-gwa", "ips-gwb", "ips-server"):
        if name in namespaces:
            raise AssertionError(f"namespace leaked: {name}")
    for interface in (
        "veth-c",
        "veth-a-lan",
        "veth-a-wan",
        "veth-b-wan",
        "veth-b-lan",
        "veth-s",
    ):
        result = subprocess.run(
            ["ip", "link", "show", interface],
            text=True,
            capture_output=True,
            timeout=5,
        )
        if result.returncode == 0:
            raise AssertionError(f"root veth leaked: {interface}")
    if (Path("/run/ipsec-sentinel") / run_id).exists():
        raise AssertionError(f"runtime directory leaked: {run_id}")


@unittest.skipUnless(
    DATASET_INTEGRATION_ENABLED,
    "set IPSEC_SENTINEL_DATASET_INTEGRATION=1 and run as Linux root",
)
class DatasetIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_capture_roles(
        self, run_dir: Path, truth: dict[str, object]
    ) -> None:
        capture = truth["capture"]
        self.assertIsInstance(capture, dict)
        capture = dict(capture)
        window = WorkloadWindow(
            int(capture["workload_started_unix_ns"]),
            int(capture["workload_finished_unix_ns"]),
        )
        summary = inspect_ml_pcap(
            run_dir / "encrypted.pcap",
            window,
            ("192.0.2.1", "192.0.2.2"),
        )
        self.assertEqual(summary.packet_count, capture["ml_esp_packets"])
        self.assertEqual(capture["ml_input_file"], "encrypted.pcap")

        full = subprocess.run(
            ["tcpdump", "-nn", "-r", str(run_dir / "full-evidence.pcap")],
            text=True,
            capture_output=True,
            check=True,
            timeout=10,
        ).stdout.lower()
        ml = subprocess.run(
            ["tcpdump", "-nn", "-r", str(run_dir / "encrypted.pcap")],
            text=True,
            capture_output=True,
            check=True,
            timeout=10,
        ).stdout.lower()
        self.assertIn("isakmp", full)
        self.assertIn("esp", full)
        self.assertIn("esp", ml)
        self.assertNotIn("isakmp", ml)
        self.assertNotIn(".4500", ml)

        rekey_log = (run_dir / "pfs-rekey.log").read_text(
            encoding="utf-8", errors="replace"
        )
        self.assertTrue(rekey_log.strip())
        for gateway in ("gateway-a", "gateway-b"):
            before = (run_dir / f"swanctl-before-rekey-{gateway}.txt").read_text(
                encoding="utf-8", errors="replace"
            )
            after = (run_dir / f"swanctl-after-rekey-{gateway}.txt").read_text(
                encoding="utf-8", errors="replace"
            )
            self.assertNotEqual(before, after)
        pfs = truth["ipsec"]["observed"]["pfs"]
        self.assertEqual(pfs["status"], "VERIFIED")
        self.assertTrue(pfs["rekey_observed"])
        self.assertIn("fresh_dh_selected=True", pfs["evidence"])

    def run_class(
        self, traffic_class: str, seed: int
    ) -> tuple[Path, dict[str, object]]:
        dataset_name = f"integration-{traffic_class}-{seed}"
        config = write_one_slot_config(
            self.root, dataset_name, traffic_class, seed
        )
        summary = generate_dataset(config, self.root / "dataset")
        self.assertEqual(summary.successful_runs, 1)
        self.assertEqual(summary.training_ready_runs, 1)
        run_dir = next(
            path
            for path in (self.root / "dataset" / dataset_name / "runs").iterdir()
            if path.is_dir()
        )
        truth = json.loads(
            (run_dir / "ground_truth.json").read_text(encoding="utf-8")
        )
        traffic = json.loads(
            (run_dir / "traffic.json").read_text(encoding="utf-8")
        )
        self.assertEqual(truth["traffic"]["class"], traffic_class)
        self.assertEqual(traffic["class"], traffic_class)
        self.assertEqual(truth["traffic"]["parameters"], traffic["parameters"])
        self.assertTrue(truth["training_ready"])
        self.assertTrue((run_dir / "full-evidence.pcap").is_file())
        self.assertTrue((run_dir / "encrypted.pcap").is_file())
        self.assertGreater(truth["capture"]["ml_esp_packets"], 0)
        self.assert_capture_roles(run_dir, truth)
        assert_no_lab_resources(run_dir.name)
        return run_dir, truth

    def test_real_icmp_dataset_run(self) -> None:
        self.run_class("icmp", 1001)

    def test_real_web_dataset_run(self) -> None:
        self.run_class("web", 2001)

    def test_real_video_dataset_run(self) -> None:
        self.run_class("video", 3001)

    def test_retry_creates_a_new_tunnel_session_and_resume_skips_passes(self) -> None:
        dataset_name = "integration-retry-4001"
        config = write_one_slot_config(
            self.root, dataset_name, "icmp", 4001, retry_failed=1
        )
        calls = 0

        def runner(
            plan: AttemptPlan, root: Path, fingerprint: str
        ) -> AttemptOutcome:
            nonlocal calls
            calls += 1

            def stage_hook(stage: str) -> None:
                if calls == 1 and stage == "traffic_run":
                    raise RuntimeError(
                        "injected failure after tunnel establishment"
                    )

            return run_dataset_attempt(
                plan, root, fingerprint, stage_hook=stage_hook
            )

        first = generate_dataset(
            config, self.root / "dataset", attempt_runner=runner
        )
        self.assertEqual(first.successful_runs, 1)
        dataset_root = self.root / "dataset" / dataset_name
        manifest = Manifest(dataset_root / "manifest.sqlite3")
        try:
            attempts = manifest.attempts()
        finally:
            manifest.close()
        self.assertEqual(
            [item.state for item in attempts], [RunState.FAILED, RunState.PASS]
        )
        self.assertNotEqual(attempts[0].seed, attempts[1].seed)
        self.assertEqual(attempts[0].cleanup_state.value, "PASS")
        self.assertEqual(attempts[1].cleanup_state.value, "PASS")
        first_dir = dataset_root / attempts[0].artifact_path
        second_dir = dataset_root / attempts[1].artifact_path
        self.assertTrue((first_dir / "verification.json").is_file())
        self.assertIn(
            "injected failure after tunnel establishment",
            (first_dir / "verification.json").read_text(encoding="utf-8"),
        )
        first_sa = (first_dir / "swanctl-gateway-a.txt").read_bytes()
        second_sa = (second_dir / "swanctl-gateway-a.txt").read_bytes()
        self.assertNotEqual(first_sa, second_sa)
        self.assertNotEqual(
            hashlib.sha256(first_sa).digest(),
            hashlib.sha256(second_sa).digest(),
        )

        before = tuple(sorted(path.name for path in (dataset_root / "runs").iterdir()))
        resumed = generate_dataset(config, self.root / "dataset", resume=True)
        after = tuple(sorted(path.name for path in (dataset_root / "runs").iterdir()))
        self.assertEqual(resumed.successful_runs, 1)
        self.assertEqual(after, before)
        self.assertEqual(calls, 2)
        assert_no_lab_resources(first_dir.name)
        assert_no_lab_resources(second_dir.name)


if __name__ == "__main__":
    unittest.main()
