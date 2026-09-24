from pathlib import Path
from tempfile import TemporaryDirectory
from io import StringIO
import json
import unittest

from ipsec_sentinel.dataset.artifacts import (
    publish_terminal_json,
    stage_terminal_json,
)
from ipsec_sentinel.dataset.models import CleanupState, RunState
from ipsec_sentinel.dataset.manifest import AttemptPlan
from ipsec_sentinel.dataset.manifest import Manifest, ManifestMismatch
from ipsec_sentinel.dataset.runner import (
    classify_failure,
    finalize_attempt_state,
    generate_dataset,
    run_dataset_attempt,
)
from ipsec_sentinel.models import CaptureEvidence, PfsObservation
from ipsec_sentinel.scenario import Scenario
from ipsec_sentinel.traffic.base import TrafficRunResult, TrafficValidation
from tests.pcap_helpers import ethernet_ipv4, write_pcap
from tests.test_evidence import fixture


class FakeClock:
    def __init__(self) -> None:
        self.values = iter((1_000_000_000, 2_000_000_000))

    def time_ns(self) -> int:
        return next(self.values)


class FakeGenerator:
    name = "icmp"
    version = "1"

    def __init__(self, seed: int, events: list[str]) -> None:
        self.seed = seed
        self.events = events

    def prepare(self, context) -> None:
        self.events.append("traffic_prepare")

    def run(self, context) -> TrafficRunResult:
        self.events.append("traffic_run")
        return TrafficRunResult({"stdout": "5 packets transmitted, 5 received"})

    def validate(self, context, result) -> TrafficValidation:
        self.events.append("traffic_validate")
        return TrafficValidation(True, {"received": 5}, ())

    def cleanup(self, context) -> None:
        self.events.append("traffic_cleanup")

    def metadata(self) -> dict[str, object]:
        return {
            "class": "icmp",
            "known_training_class": True,
            "generator": "ping",
            "generator_version": "1",
            "seed": self.seed,
            "parameters": {
                "count": 5,
                "interval_seconds": 0.1,
                "payload_bytes": 56,
            },
            "result": {"received": 5},
        }


class FakeProfile:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def apply(self, log) -> None:
        return None

    def verify(self, log) -> dict[str, object]:
        return {
            "profile": "clean",
            "latency_ms": 0,
            "jitter_ms": 0,
            "packet_loss_percent": 0,
            "bandwidth_limit_bps": None,
        }

    def cleanup(self, log) -> None:
        self.events.append("profile_cleanup")


class FakeSession:
    def __init__(self, run_dir: Path, log: StringIO, *, events: list[str], **kwargs) -> None:
        del log, kwargs
        self.run_dir = run_dir
        self.events = events
        self.scenario = None
        self.scenario_yaml = ""
        self.sas = {
            "gateway-a": fixture("swanctl-gateway-a.txt"),
            "gateway-b": fixture("swanctl-gateway-b.txt"),
        }
        self.xfrm = {
            "gateway-a": fixture("xfrm-gateway-a.txt"),
            "gateway-b": fixture("xfrm-gateway-b.txt"),
        }
        self.pfs = PfsObservation.not_tested()
        self.capture_evidence = None

    def preflight(self) -> None: return None
    def reset(self) -> None: return None

    def load_scenario(self, scenario_id: str) -> Scenario:
        self.scenario_yaml = Path("scenarios/secure-baseline.yaml").read_text()
        self.scenario = Scenario.load(Path("scenarios/secure-baseline.yaml"))
        return self.scenario

    def setup_topology(self) -> None: return None
    def start_daemons(self) -> None: return None
    def start_captures(self) -> None: self.events.append("capture_start")
    def load_configuration(self): return {}
    def initiate(self): self.events.append("initiate"); return "ok"
    def wait_for_sa(self): return self.sas
    def collect_xfrm(self): return self.xfrm

    def rekey(self) -> PfsObservation:
        self.events.append("pfs_rekey")
        self.pfs = PfsObservation("VERIFIED", True, ("fresh DH",))
        return self.pfs

    def stop_captures(self) -> None:
        records = [
            (900_000_000, ethernet_ipv4("192.0.2.1", "192.0.2.2", 17, b"ike")),
            *[
                (1_100_000_000 + index, ethernet_ipv4(
                    "192.0.2.1" if index % 2 == 0 else "192.0.2.2",
                    "192.0.2.2" if index % 2 == 0 else "192.0.2.1",
                    50, b"esp" + bytes([index]),
                ))
                for index in range(12)
            ],
            (2_100_000_000, ethernet_ipv4("192.0.2.1", "192.0.2.2", 17, b"rekey")),
        ]
        write_pcap(self.run_dir / "full-evidence.pcap", records)
        write_pcap(self.run_dir / "cleartext-audit-gateway-a.pcap", [])
        write_pcap(self.run_dir / "cleartext-audit-gateway-b.pcap", [])

    def validate_captures(self) -> CaptureEvidence:
        self.capture_evidence = CaptureEvidence("full-evidence.pcap", 14, 2, 12, 0, 0)
        return self.capture_evidence

    def preserve_diagnostics(self) -> None:
        (self.run_dir / "pfs-rekey.log").write_text("fresh DH", encoding="utf-8")

    def cleanup(self) -> None:
        self.events.append("session_cleanup")


def plan_fixture() -> AttemptPlan:
    return AttemptPlan(
        "run_000001", "run_000001", 1, 1, 41,
        "secure-baseline", "icmp", "clean", "runs/run_000001",
    )


def outcome_for(
    plan: AttemptPlan,
    state: RunState,
    failure_class: str | None = None,
) -> object:
    from ipsec_sentinel.dataset.models import AttemptOutcome

    passed = state is RunState.PASS
    return AttemptOutcome(
        plan.attempt_id, plan.slot_id, plan.attempt_number, state,
        CleanupState.PASS, passed, failure_class,
        None if passed else "injected", plan.artifact_path,
        "2026-09-25T00:00:00Z", "2026-09-25T00:00:01Z",
        "2026-09-25T00:00:00Z", "2026-09-25T00:00:01Z",
        ({"name": "cleanup", "status": "PASS", "error": None},), None,
        passed, passed, passed, 12 if passed else 0, 672 if passed else 0,
        1.0 if passed else 0.0,
    )


class DatasetRunnerTest(unittest.TestCase):
    def matrix_path(
        self, directory: Path, *, seed: int = 1, runs: int = 2, retry_failed: int = 1
    ) -> Path:
        path = directory / f"matrix-{seed}-{runs}-{retry_failed}.yaml"
        path.write_text(
            f"""dataset:
  name: test-dataset
  schema_version: ipsec-sentinel.dataset-ground-truth/v1
  seed: {seed}
traffic:
  classes: [icmp]
ipsec:
  scenarios: [secure-baseline]
network_profiles: [clean]
runs_per_combination: {runs}
execution:
  workers: 1
  retry_failed: {retry_failed}
""",
            encoding="utf-8",
        )
        return path

    def test_failure_classification_is_stable(self) -> None:
        self.assertEqual(
            classify_failure("sa_wait", TimeoutError("no SA")),
            "tunnel_establishment_failed",
        )
        self.assertEqual(
            classify_failure("traffic_validate", ValueError("receipts")),
            "traffic_validation_failed",
        )
        self.assertEqual(
            classify_failure("pcap_derive", ValueError("pcap")),
            "pcap_derivation_failed",
        )

    def test_cleanup_failure_excludes_otherwise_valid_data(self) -> None:
        state, ready, failure_class = finalize_attempt_state(
            interrupted=False,
            primary_error=None,
            cleanup_state=CleanupState.FAILED,
            validations=(True, True, True),
        )
        self.assertEqual(state, RunState.FAILED)
        self.assertFalse(ready)
        self.assertEqual(failure_class, "cleanup_failed")

    def test_interruption_remains_incomplete_even_when_cleanup_passes(self) -> None:
        state, ready, failure_class = finalize_attempt_state(
            interrupted=True,
            primary_error=KeyboardInterrupt(),
            cleanup_state=CleanupState.PASS,
            validations=(False, False, False),
        )
        self.assertEqual(state, RunState.INCOMPLETE)
        self.assertFalse(ready)
        self.assertEqual(failure_class, "interrupted")

    def test_terminal_json_is_published_only_after_cleanup_result(self) -> None:
        with TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run_000001"
            run_dir.mkdir()
            payloads = {
                "ground_truth.json": {
                    "status": "FAILED",
                    "training_ready": False,
                    "cleanup_status": "FAILED",
                },
                "verification.json": {"status": "FAILED", "checks": []},
                "traffic.json": {"schema_version": "ipsec-sentinel.traffic/v1"},
                "environment.json": {"git_commit_sha": "a" * 40},
            }
            staged = stage_terminal_json(run_dir, payloads)
            self.assertFalse((run_dir / "ground_truth.json").exists())
            publish_terminal_json(staged)
            truth = json.loads((run_dir / "ground_truth.json").read_text())
            self.assertEqual(truth["status"], "FAILED")
            self.assertFalse(truth["training_ready"])

    def test_attempt_orders_capture_and_derives_esp_only_workload(self) -> None:
        with TemporaryDirectory() as directory:
            events: list[str] = []
            outcome = run_dataset_attempt(
                plan_fixture(), Path(directory), "b" * 64,
                clock=FakeClock(), stage_hook=lambda stage: events.append(stage),
                session_factory=lambda *args, **kwargs: FakeSession(
                    *args, events=events, **kwargs
                ),
                generator_factory=lambda name, seed: FakeGenerator(seed, events),
                profile_factory=lambda: FakeProfile(events),
            )
            self.assertEqual(outcome.state, RunState.PASS, repr(outcome))
            self.assertTrue(outcome.training_ready)
            self.assertLess(events.index("capture_start"), events.index("initiate"))
            self.assertLess(events.index("traffic_run"), events.index("pfs_rekey"))
            self.assertEqual(outcome.esp_packets, 12)
            run_dir = Path(directory) / "runs/run_000001"
            encrypted = (run_dir / "encrypted.pcap").read_bytes()
            self.assertNotIn(b"ike", encrypted)
            self.assertNotIn(b"rekey", encrypted)
            cleanup = [events.index(name) for name in (
                "traffic_cleanup", "profile_cleanup", "session_cleanup"
            )]
            self.assertEqual(cleanup, sorted(cleanup))
            self.assertLess(events.index("session_cleanup"), events.index("metadata"))
            self.assertLess(events.index("metadata"), events.index("terminal_publish"))

    def test_injected_failure_preserves_diagnostics_and_runs_all_cleanup(self) -> None:
        with TemporaryDirectory() as directory:
            events: list[str] = []

            def hook(stage: str) -> None:
                events.append(stage)
                if stage == "traffic_validate":
                    raise ValueError("injected receipts failure")

            outcome = run_dataset_attempt(
                plan_fixture(), Path(directory), "b" * 64,
                clock=FakeClock(), stage_hook=hook,
                session_factory=lambda *args, **kwargs: FakeSession(
                    *args, events=events, **kwargs
                ),
                generator_factory=lambda name, seed: FakeGenerator(seed, events),
                profile_factory=lambda: FakeProfile(events),
            )
            self.assertEqual(outcome.state, RunState.FAILED)
            self.assertEqual(outcome.failure_class, "traffic_validation_failed")
            cleanup = [events.index(name) for name in (
                "traffic_cleanup", "profile_cleanup", "session_cleanup"
            )]
            self.assertEqual(cleanup, sorted(cleanup))
            self.assertLess(events.index("session_cleanup"), events.index("metadata"))
            self.assertLess(events.index("metadata"), events.index("terminal_publish"))
            run_dir = Path(directory) / "runs/run_000001"
            self.assertTrue((run_dir / "traffic.json").is_file())
            self.assertTrue((run_dir / "pfs-rekey.log").is_file())

    def test_resume_skips_pass_and_retries_failed_once(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            calls: list[str] = []

            def runner(plan, dataset_root, fingerprint):
                del dataset_root, fingerprint
                calls.append(plan.attempt_id)
                if plan.slot_id == "run_000001" and plan.attempt_number == 1:
                    return outcome_for(plan, RunState.FAILED, "traffic_generator_failed")
                return outcome_for(plan, RunState.PASS)

            summary = generate_dataset(
                self.matrix_path(root), root / "datasets", attempt_runner=runner
            )
            self.assertEqual(
                calls, ["run_000001", "run_000001-attempt02", "run_000002"]
            )
            self.assertEqual(summary.successful_runs, 2)
            calls.clear()
            resumed = generate_dataset(
                self.matrix_path(root), root / "datasets", resume=True,
                attempt_runner=runner,
            )
            self.assertEqual(calls, [])
            self.assertEqual(resumed.successful_runs, 2)

    def test_resume_recovers_running_as_incomplete_then_retries(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = self.matrix_path(root, runs=1)

            def crash(plan, dataset_root, fingerprint):
                del plan, dataset_root, fingerprint
                raise RuntimeError("simulated process crash")

            with self.assertRaisesRegex(RuntimeError, "simulated"):
                generate_dataset(config, root / "datasets", attempt_runner=crash)
            calls: list[str] = []

            def recover(plan, dataset_root, fingerprint):
                del dataset_root, fingerprint
                calls.append(plan.attempt_id)
                return outcome_for(plan, RunState.PASS)

            summary = generate_dataset(
                config, root / "datasets", resume=True, attempt_runner=recover
            )
            self.assertEqual(calls, ["run_000001-attempt02"])
            self.assertEqual(summary.attempts_by_state["INCOMPLETE"], 1)
            self.assertEqual(summary.successful_runs, 1)

    def test_exhausted_retry_and_nonretriable_failure_are_not_hidden(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            calls: list[str] = []

            def fail(plan, dataset_root, fingerprint):
                del dataset_root, fingerprint
                calls.append(plan.attempt_id)
                return outcome_for(plan, RunState.FAILED, "traffic_generator_failed")

            summary = generate_dataset(
                self.matrix_path(root, runs=1), root / "datasets", attempt_runner=fail
            )
            self.assertEqual(calls, ["run_000001", "run_000001-attempt02"])
            self.assertEqual(summary.failed_runs, 1)
            self.assertEqual(summary.failures_by_class, {"traffic_generator_failed": 2})

            root2 = root / "nonretriable"
            root2.mkdir()
            calls.clear()

            def config_fail(plan, dataset_root, fingerprint):
                del dataset_root, fingerprint
                calls.append(plan.attempt_id)
                return outcome_for(plan, RunState.FAILED, "configuration_failed")

            nonretry = generate_dataset(
                self.matrix_path(root2, runs=1), root2 / "datasets",
                attempt_runner=config_fail,
            )
            self.assertEqual(calls, ["run_000001"])
            self.assertEqual(nonretry.failed_runs, 1)

    def test_resume_rejects_changed_fingerprint_and_no_resume_refuses_existing(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = self.matrix_path(root, seed=1, runs=1)
            passing = lambda plan, dataset_root, fingerprint: outcome_for(plan, RunState.PASS)
            generate_dataset(config, root / "datasets", attempt_runner=passing)
            with self.assertRaises(FileExistsError):
                generate_dataset(config, root / "datasets", attempt_runner=passing)
            with self.assertRaisesRegex(ManifestMismatch, "fingerprint"):
                generate_dataset(
                    self.matrix_path(root, seed=2, runs=1),
                    root / "datasets", resume=True,
                    attempt_runner=lambda *args: self.fail("must not run"),
                )


if __name__ == "__main__":
    unittest.main()
