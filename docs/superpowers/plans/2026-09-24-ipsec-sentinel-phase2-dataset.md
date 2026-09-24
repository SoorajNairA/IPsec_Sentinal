# IPsec Sentinel Phase 2 Dataset Factory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a serial, resumable, reproducible factory that generates independently labeled ICMP, web, and segmented-video sessions through the validated IPsec tunnel and publishes workload-only ESP captures plus complete validation evidence.

**Architecture:** Extract a reusable secure-session lifecycle from the Phase 1 runner without changing `run_secure_baseline()` behavior, then inject small seeded traffic generators into a dataset attempt runner. Persist matrix slots, attempts, state transitions, cleanup outcomes, and retry history in SQLite; capture the full tunnel session once and deterministically derive the future-ML ESP PCAP from recorded workload boundaries.

**Tech Stack:** Python 3.14 standard library, PyYAML, SQLite, Linux network namespaces/XFRM, strongSwan, tcpdump legacy PCAP, `unittest`, WSL2/Linux root-gated integration tests.

**Spec:** `docs/superpowers/specs/2026-09-24-ipsec-sentinel-phase2-dataset-design.md`

## Global Constraints

- Work on `feat/ipsec-sentinel-phase2-dataset`, whose required base is Phase 1 commit `a251bb21693b6876844a4f2d002d045e9f0a29c0`; do not merge or silently rebase onto stale `main`.
- Preserve the public `run_secure_baseline()` entry point, `run_scenario.py secure-baseline`, Phase 1 schema meanings, stage ordering, topology, native ESP behavior, rekey proof, cleanup behavior, and tests.
- Dataset captures use `full-evidence.pcap` for complete IKE/ESP/rekey evidence and a deterministically derived `encrypted.pcap` containing only workload-window outer ESP. Phase 1 retains its existing `encrypted.pcap` semantics.
- Dataset schemas are `ipsec-sentinel.dataset-ground-truth/v1`, `ipsec-sentinel.dataset-verification/v1`, `ipsec-sentinel.traffic/v1`, and `ipsec-sentinel.scenario/v1`; SQLite `PRAGMA user_version` is `1`.
- Run states are exactly `PENDING`, `RUNNING`, `PASS`, `FAILED`, and `INCOMPLETE`. Cleanup states are exactly `NOT_STARTED`, `PASS`, and `FAILED`.
- A run is training-ready only when every required quality check and cleanup passes; failed and incomplete artifacts remain retained and indexed.
- Use only the `clean` network profile, serial execution (`workers: 1`), and bounded retries. Do not add netem impairment, parallel workers, extra traffic classes, feature extraction, ML, APIs, or UI.
- Traffic generators use only local protected-network services and argument-vector process execution. Do not depend on public websites or new third-party Python packages.
- All production changes follow red-green-refactor: add the named test, run it and observe the expected failure, implement the minimum behavior, run the focused test, then run the relevant regression set before committing.
- Preserve configured-versus-observed IPsec evidence. Never populate observed values from requested configuration.

## File Structure

### New production files

- `ipsec_sentinel/session.py` — reusable Phase 1 secure-session lifecycle and evidence container.
- `ipsec_sentinel/pcap.py` — strict legacy-PCAP parsing, workload-window ESP derivation, and ML-capture inspection.
- `ipsec_sentinel/traffic/base.py` — traffic context, result, validation, protocol, and registry.
- `ipsec_sentinel/traffic/icmp.py` — seeded ICMP planning, execution, validation, and metadata.
- `ipsec_sentinel/traffic/http_service.py` — deterministic protected HTTP service and tracked server process.
- `ipsec_sentinel/traffic/http_client.py` — deterministic sequential HTTP client used inside `ips-client`.
- `ipsec_sentinel/traffic/web.py` — seeded web request plan and class-specific validation.
- `ipsec_sentinel/traffic/video.py` — seeded segmented-video plan, pacing, and validation.
- `ipsec_sentinel/dataset/models.py` — versioned dataset, reproducibility, capture, validation, and outcome models.
- `ipsec_sentinel/dataset/config.py` — strict matrix YAML parser.
- `ipsec_sentinel/dataset/matrix.py` — deterministic expansion, IDs, seeds, and fingerprint.
- `ipsec_sentinel/dataset/manifest.py` — SQLite schema and transactional lifecycle operations.
- `ipsec_sentinel/dataset/artifacts.py` — durable dataset-attempt artifact publication.
- `ipsec_sentinel/dataset/network.py` — clean-profile apply/verify/cleanup contract.
- `ipsec_sentinel/dataset/runner.py` — one dataset-attempt lifecycle.
- `ipsec_sentinel/dataset/summary.py` — manifest-derived summary model and JSON/CLI rendering.
- `ipsec_sentinel/dataset/validation.py` — offline dataset/artifact validation.
- `ipsec_sentinel/dataset/cli.py` and `ipsec_sentinel/dataset/__main__.py` — list, run, generate, resume, and validate commands.
- `configs/smoke-v1.yaml` — nine-slot smoke matrix.

### Modified production files

- `ipsec_sentinel/runner.py` — delegate Phase 1 mechanics to `SecureSession` while preserving its public contract.
- `ipsec_sentinel/__init__.py` — describe Phase 1 plus Phase 2 without changing imports.
- `.gitignore` — ignore generated `dataset/` artifacts.
- `README.md` — document the dataset factory and unattended use.

### New test files

- `tests/test_dataset_models.py`
- `tests/test_dataset_config.py`
- `tests/test_dataset_matrix.py`
- `tests/test_dataset_manifest.py`
- `tests/test_traffic_contract.py`
- `tests/test_traffic_icmp.py`
- `tests/test_traffic_web.py`
- `tests/test_traffic_video.py`
- `tests/test_pcap_workload.py`
- `tests/test_session.py`
- `tests/test_dataset_runner.py`
- `tests/test_dataset_summary.py`
- `tests/test_dataset_cli.py`
- `tests/test_dataset_validation.py`
- `tests/test_dataset_integration.py`

## Review Focus

1. A crash after artifacts are durable but before the manifest commit must recover the stale `RUNNING` attempt as `INCOMPLETE`, never infer `PASS`, and schedule at most the allowed independent retry. Covered in Task 3 manifest recovery tests and Task 10 resume tests.
2. PCAP timestamp endianness/resolution, inclusive boundary packets, VLAN tags, and packets from the rekey period must not leak IKE or out-of-window ESP into `encrypted.pcap`. Covered in Task 7 derivation tests.
3. A valid workload and capture followed by cleanup failure must finish as `FAILED`, record `cleanup_status=FAILED`, and set `training_ready=false`. Covered in Task 9 attempt-runner tests.
4. Resuming with a modified matrix, generator version, list order, or base seed must fail on fingerprint mismatch before creating an attempt. Covered in Tasks 2, 3, and 10.
5. A matching seed/version/scenario must reproduce a generator plan, a different attempt seed must vary sensible parameters, and client-only success without matching server receipts must fail. Covered in Tasks 4–6.

---

### Task 1: Dataset Models and Traffic Contract

**Files:**
- Create: `ipsec_sentinel/dataset/__init__.py`
- Create: `ipsec_sentinel/dataset/models.py`
- Create: `ipsec_sentinel/traffic/__init__.py`
- Create: `ipsec_sentinel/traffic/base.py`
- Test: `tests/test_dataset_models.py`
- Test: `tests/test_traffic_contract.py`

**Interfaces:**
- Consumes: Phase 1 `ConfiguredPolicy`, `ObservedState`, `PfsObservation`, `Check`, and `_json_ready` semantics from `ipsec_sentinel.models`.
- Produces: `RunState`, `CleanupState`, `ReproducibilityMetadata`, `WorkloadWindow`, `DatasetCaptureEvidence`, `DatasetTrafficEvidence`, `DatasetValidation`, `DatasetGroundTruth`, `DatasetVerification`, `AttemptOutcome`, `TrafficContext`, `TrafficRunResult`, `TrafficValidation`, `TrafficGenerator`, `register_generator()`, `create_generator()`, and `generator_versions()`.

- [ ] **Step 1: Write failing serialization and state-invariant tests**

```python
# tests/test_dataset_models.py
import json
import unittest

from ipsec_sentinel.dataset.models import (
    CleanupState, DatasetCaptureEvidence, DatasetGroundTruth,
    DatasetTrafficEvidence, DatasetValidation, DatasetVerification,
    ReproducibilityMetadata,
    RunState, WorkloadWindow,
)
from ipsec_sentinel.models import (
    Check, ConfiguredPolicy, ObservedState, PfsObservation, StageRecord,
)


def example_truth(
    *, status: RunState = RunState.PASS,
    cleanup_status: CleanupState = CleanupState.PASS,
    training_ready: bool = True,
) -> DatasetGroundTruth:
    return DatasetGroundTruth(
        schema_version="ipsec-sentinel.dataset-ground-truth/v1",
        run_id="run_000001", slot_id="run_000001", attempt_number=1,
        status=status, training_ready=training_ready,
        traffic=DatasetTrafficEvidence(
            "video", True, "local-segmented-video", "1", 7,
            {"segments": 5}, {"completed_segments": 5},
        ),
        scenario_id="secure-baseline",
        scenario_schema_version="ipsec-sentinel.scenario/v1",
        configured=ConfiguredPolicy(
            2, "tunnel", "aes256gcm16-prfsha384-ecp384",
            "aes256gcm16-ecp384", True, 4,
            "10.10.0.0/24", "10.20.0.0/24", "192.0.2.0/30",
        ),
        observed=ObservedState(
            2, "AES_GCM_16_256/PRF_HMAC_SHA2_384/ECP_384",
            "AES_GCM_16_256/NO_EXT_SEQ", PfsObservation("VERIFIED", True, ("fresh DH",)),
        ),
        network={"profile": "clean", "latency_ms": 0, "jitter_ms": 0,
                 "packet_loss_percent": 0, "bandwidth_limit_bps": None},
        capture=DatasetCaptureEvidence(
            "full-evidence.pcap", "encrypted.pcap", 1_000, 2_000,
            30, 8, 22, 14, 4096, 0.000001, "pcap-workload-window-esp/v1",
        ),
        validation=DatasetValidation(True, True, True, cleanup_status is CleanupState.PASS),
        cleanup_status=cleanup_status,
        reproducibility=ReproducibilityMetadata(
            "a" * 40, False, None, "ipsec-sentinel.dataset-ground-truth/v1",
            "ipsec-sentinel.scenario/v1", 1, "strongSwan 6.0.4",
            "6.18.33.2-microsoft-standard-WSL2", "#1 SMP", "CPython", "3.14.0",
            "Linux", "x86_64", "local-segmented-video", "1",
            "sha256-slot-attempt/v1", 7, "b" * 64,
            "2026-09-24T10:00:00Z", "2026-09-24T10:00:01Z", 1_000, 2_000,
            (),
        ),
    )


class DatasetModelTest(unittest.TestCase):
    def test_ground_truth_keeps_ipsec_views_and_capture_roles_separate(self) -> None:
        truth = example_truth()
        payload = truth.to_dict()
        self.assertEqual(payload["schema_version"], "ipsec-sentinel.dataset-ground-truth/v1")
        self.assertEqual(payload["ipsec"]["configured"]["esp_proposal"], "aes256gcm16-ecp384")
        self.assertEqual(payload["ipsec"]["observed"]["esp_proposal"], "AES_GCM_16_256/NO_EXT_SEQ")
        self.assertEqual(payload["capture"]["full_evidence_file"], "full-evidence.pcap")
        self.assertEqual(payload["capture"]["ml_input_file"], "encrypted.pcap")
        self.assertTrue(payload["training_ready"])
        self.assertEqual(json.loads(json.dumps(payload)), payload)

    def test_training_ready_requires_pass_and_successful_cleanup(self) -> None:
        with self.assertRaisesRegex(ValueError, "training_ready"):
            example_truth(
                status=RunState.FAILED,
                cleanup_status=CleanupState.PASS,
                training_ready=True,
            )
        with self.assertRaisesRegex(ValueError, "cleanup"):
            example_truth(
                status=RunState.PASS,
                cleanup_status=CleanupState.FAILED,
                training_ready=True,
            )

    def test_dataset_verification_serializes_schema_stages_and_checks(self) -> None:
        verification = DatasetVerification(
            "ipsec-sentinel.dataset-verification/v1", "run_000001",
            RunState.FAILED,
            (StageRecord("traffic_validate", "FAIL", "missing receipt"),),
            (Check("traffic.web.receipts", False, ("expected=6", "actual=5")),),
            ({"name": "topology_reset", "status": "PASS", "error": None},),
        )
        payload = verification.to_dict()
        self.assertEqual(payload["schema_version"], "ipsec-sentinel.dataset-verification/v1")
        self.assertEqual(payload["status"], "FAILED")
        self.assertFalse(payload["checks"][0]["passed"])
```

- [ ] **Step 2: Write a failing runtime traffic-contract test**

```python
# tests/test_traffic_contract.py
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from ipsec_sentinel.traffic.base import (
    TrafficContext, TrafficGenerator, TrafficRunResult,
    TrafficValidation, create_generator, register_generator,
)


class ExampleGenerator:
    name = "example"
    version = "1"

    def prepare(self, context: TrafficContext) -> None:
        return None

    def run(self, context: TrafficContext) -> TrafficRunResult:
        return TrafficRunResult(metrics={"requests": 1})

    def validate(self, context: TrafficContext, result: TrafficRunResult) -> TrafficValidation:
        return TrafficValidation(True, {"requests": 1}, ())

    def cleanup(self, context: TrafficContext) -> None:
        return None

    def metadata(self) -> dict[str, object]:
        return {"generator": self.name, "version": self.version}


class TrafficContractTest(unittest.TestCase):
    def test_registry_returns_a_runtime_conforming_generator(self) -> None:
        register_generator("example", lambda seed: ExampleGenerator())
        generator = create_generator("example", seed=7)
        self.assertIsInstance(generator, TrafficGenerator)
        self.assertEqual(generator.metadata()["version"], "1")

    def test_unknown_generator_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported traffic class"):
            create_generator("unknown", seed=7)
```

- [ ] **Step 3: Run the new tests and verify the missing-module failure**

Run:

```bash
python3 -m unittest tests.test_dataset_models tests.test_traffic_contract -v
```

Expected: import errors for `ipsec_sentinel.dataset.models` and `ipsec_sentinel.traffic.base`.

- [ ] **Step 4: Implement versioned models with invariant checks**

```python
# ipsec_sentinel/dataset/models.py
from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from enum import StrEnum
from typing import Any

from ipsec_sentinel.models import Check, ConfiguredPolicy, ObservedState, StageRecord

DATASET_SCHEMA_VERSION = "ipsec-sentinel.dataset-ground-truth/v1"
VERIFICATION_SCHEMA_VERSION = "ipsec-sentinel.dataset-verification/v1"
TRAFFIC_SCHEMA_VERSION = "ipsec-sentinel.traffic/v1"
SCENARIO_SCHEMA_VERSION = "ipsec-sentinel.scenario/v1"
MANIFEST_SCHEMA_VERSION = 1
SEED_DERIVATION_VERSION = "sha256-slot-attempt/v1"
PCAP_DERIVATION_VERSION = "pcap-workload-window-esp/v1"


class RunState(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    PASS = "PASS"
    FAILED = "FAILED"
    INCOMPLETE = "INCOMPLETE"


class CleanupState(StrEnum):
    NOT_STARTED = "NOT_STARTED"
    PASS = "PASS"
    FAILED = "FAILED"


@dataclass(frozen=True)
class WorkloadWindow:
    started_unix_ns: int
    finished_unix_ns: int

    def __post_init__(self) -> None:
        if self.started_unix_ns <= 0 or self.finished_unix_ns < self.started_unix_ns:
            raise ValueError("invalid workload window")


@dataclass(frozen=True)
class ReproducibilityMetadata:
    git_commit_sha: str
    git_dirty: bool
    git_diff_sha256: str | None
    dataset_schema_version: str
    scenario_schema_version: str
    manifest_schema_version: int
    strongswan_version: str
    kernel_release: str
    kernel_version: str
    python_implementation: str
    python_version: str
    platform: str
    architecture: str
    generator: str
    generator_version: str
    seed_derivation_version: str
    random_seed: int
    matrix_fingerprint: str
    run_started_at: str
    run_finished_at: str
    workload_started_unix_ns: int
    workload_finished_unix_ns: int
    collection_errors: tuple[str, ...]


@dataclass(frozen=True)
class DatasetCaptureEvidence:
    full_evidence_file: str
    ml_input_file: str
    workload_started_unix_ns: int
    workload_finished_unix_ns: int
    full_packet_count: int
    ike_packets: int
    esp_packets: int
    ml_esp_packets: int
    ml_capture_bytes: int
    ml_duration_seconds: float
    derivation: str


@dataclass(frozen=True)
class DatasetTrafficEvidence:
    traffic_class: str
    known_training_class: bool
    generator: str
    generator_version: str
    seed: int
    parameters: dict[str, object]
    result: dict[str, object]


@dataclass(frozen=True)
class DatasetValidation:
    traffic_verified: bool
    ipsec_verified: bool
    capture_verified: bool
    cleanup_verified: bool

    @property
    def passed(self) -> bool:
        return all((self.traffic_verified, self.ipsec_verified,
                    self.capture_verified, self.cleanup_verified))


@dataclass(frozen=True)
class DatasetGroundTruth:
    schema_version: str
    run_id: str
    slot_id: str
    attempt_number: int
    status: RunState
    training_ready: bool
    traffic: DatasetTrafficEvidence
    scenario_id: str
    scenario_schema_version: str
    configured: ConfiguredPolicy
    observed: ObservedState
    network: dict[str, object]
    capture: DatasetCaptureEvidence
    validation: DatasetValidation
    cleanup_status: CleanupState
    reproducibility: ReproducibilityMetadata

    def __post_init__(self) -> None:
        if self.training_ready and self.status is not RunState.PASS:
            raise ValueError("training_ready requires PASS")
        if self.training_ready and self.cleanup_status is not CleanupState.PASS:
            raise ValueError("training_ready requires cleanup PASS")
        if self.training_ready and not self.validation.passed:
            raise ValueError("training_ready requires all validation")

    def to_dict(self) -> dict[str, object]:
        payload = _json_ready(self)
        payload["traffic"]["class"] = payload["traffic"].pop("traffic_class")
        payload["ipsec"] = {
            "scenario_id": payload.pop("scenario_id"),
            "scenario_schema_version": payload.pop("scenario_schema_version"),
            "configured": payload.pop("configured"),
            "observed": payload.pop("observed"),
        }
        return payload


@dataclass(frozen=True)
class DatasetVerification:
    schema_version: str
    run_id: str
    status: RunState
    stages: tuple[StageRecord, ...]
    checks: tuple[Check, ...]
    cleanup: tuple[dict[str, object], ...]

    def to_dict(self) -> dict[str, object]:
        return _json_ready(self)


@dataclass(frozen=True)
class AttemptOutcome:
    run_id: str
    slot_id: str
    attempt_number: int
    state: RunState
    cleanup_state: CleanupState
    training_ready: bool
    failure_class: str | None
    failure_message: str | None
    artifact_path: str
    started_at: str
    finished_at: str
    cleanup_started_at: str
    cleanup_finished_at: str
    cleanup_actions: tuple[dict[str, object], ...]
    cleanup_error: str | None
    traffic_verified: bool
    ipsec_verified: bool
    capture_verified: bool
    esp_packets: int
    capture_bytes: int
    duration_seconds: float


def _json_ready(value: Any) -> Any:
    if isinstance(value, StrEnum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _json_ready(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, tuple):
        return [_json_ready(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_ready(item) for key, item in value.items()}
    return value
```

- [ ] **Step 5: Implement the traffic protocol and guarded registry**

```python
# ipsec_sentinel/traffic/base.py
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol, TextIO, runtime_checkable


@dataclass(frozen=True)
class TrafficContext:
    run_dir: Path
    log: TextIO
    seed: int
    scenario_id: str
    network_profile: str
    client_namespace: str = "ips-client"
    server_namespace: str = "ips-server"
    client_ip: str = "10.10.0.2"
    server_ip: str = "10.20.0.2"


@dataclass(frozen=True)
class TrafficRunResult:
    metrics: dict[str, object]


@dataclass(frozen=True)
class TrafficValidation:
    passed: bool
    evidence: dict[str, object]
    errors: tuple[str, ...]


@runtime_checkable
class TrafficGenerator(Protocol):
    name: str
    version: str
    def prepare(self, context: TrafficContext) -> None: raise NotImplementedError
    def run(self, context: TrafficContext) -> TrafficRunResult: raise NotImplementedError
    def validate(self, context: TrafficContext, result: TrafficRunResult) -> TrafficValidation: raise NotImplementedError
    def cleanup(self, context: TrafficContext) -> None: raise NotImplementedError
    def metadata(self) -> dict[str, object]: raise NotImplementedError


GeneratorFactory = Callable[[int], TrafficGenerator]
_REGISTRY: dict[str, GeneratorFactory] = {}


def register_generator(name: str, factory: GeneratorFactory) -> None:
    if not name or name in _REGISTRY:
        raise ValueError(f"duplicate or empty traffic class: {name}")
    _REGISTRY[name] = factory


def create_generator(name: str, seed: int) -> TrafficGenerator:
    try:
        generator = _REGISTRY[name](seed)
    except KeyError as error:
        raise ValueError(f"unsupported traffic class: {name}") from error
    if not isinstance(generator, TrafficGenerator):
        raise TypeError(f"generator does not satisfy TrafficGenerator: {name}")
    return generator


def traffic_classes() -> tuple[str, ...]:
    return tuple(sorted(_REGISTRY))


def generator_versions(names: tuple[str, ...]) -> dict[str, str]:
    return {name: create_generator(name, seed=0).version for name in names}
```

- [ ] **Step 6: Run focused and Phase 1 regression tests**

Run:

```bash
python3 -m unittest tests.test_dataset_models tests.test_traffic_contract -v
python3 -m unittest discover -s tests -v
```

Expected: new tests pass; full suite passes with only the guarded privileged test skipped.

- [ ] **Step 7: Commit the model and contract foundation**

```bash
git add ipsec_sentinel/dataset ipsec_sentinel/traffic tests/test_dataset_models.py tests/test_traffic_contract.py
git commit -m "feat: add dataset models and traffic contract"
```

### Task 2: Strict Matrix Configuration, IDs, Seeds, and Fingerprint

**Files:**
- Create: `ipsec_sentinel/dataset/config.py`
- Create: `ipsec_sentinel/dataset/matrix.py`
- Create: `configs/smoke-v1.yaml`
- Test: `tests/test_dataset_config.py`
- Test: `tests/test_dataset_matrix.py`

**Interfaces:**
- Consumes: schema constants from `ipsec_sentinel.dataset.models` and registered generator versions supplied as `dict[str, str]`.
- Produces: `DatasetConfig.load(path)`, `MatrixSlot`, `expand_matrix(config, generator_versions)`, `matrix_fingerprint(config, generator_versions)`, `attempt_id(slot_id, attempt_number)`, and `derive_attempt_seed(base_seed, ordinal, attempt_number)`.

- [ ] **Step 1: Write strict configuration tests**

```python
# tests/test_dataset_config.py
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from ipsec_sentinel.dataset.config import DatasetConfig, DatasetConfigError

VALID = """dataset:
  name: cipherlens-smoke-v1
  schema_version: ipsec-sentinel.dataset-ground-truth/v1
  seed: 20260924
traffic:
  classes: [icmp, web, video]
ipsec:
  scenarios: [secure-baseline]
network_profiles: [clean]
runs_per_combination: 3
execution:
  workers: 1
  retry_failed: 1
"""


class DatasetConfigTest(unittest.TestCase):
    def load(self, text: str) -> DatasetConfig:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "matrix.yaml"
            path.write_text(text, encoding="utf-8")
            return DatasetConfig.load(path)

    def test_loads_exact_smoke_contract(self) -> None:
        config = self.load(VALID)
        self.assertEqual(config.name, "cipherlens-smoke-v1")
        self.assertEqual(config.traffic_classes, ("icmp", "web", "video"))
        self.assertEqual(config.runs_per_combination, 3)
        self.assertEqual(config.workers, 1)

    def test_rejects_unknown_fields_parallelism_and_unsupported_profiles(self) -> None:
        for text, message in (
            (VALID + "extra: true\n", "unknown field"),
            (VALID.replace("workers: 1", "workers: 2"), "workers"),
            (VALID.replace("[clean]", "[latency-40ms]"), "network profile"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(DatasetConfigError, message):
                self.load(text)
```

- [ ] **Step 2: Write deterministic matrix and fingerprint tests**

```python
# tests/test_dataset_matrix.py
from dataclasses import replace
import unittest

from ipsec_sentinel.dataset.config import DatasetConfig
from ipsec_sentinel.dataset.matrix import (
    attempt_id, derive_attempt_seed, expand_matrix, matrix_fingerprint,
)


class MatrixTest(unittest.TestCase):
    def setUp(self) -> None:
        self.config = DatasetConfig(
            name="cipherlens-smoke-v1",
            schema_version="ipsec-sentinel.dataset-ground-truth/v1",
            base_seed=20260924,
            traffic_classes=("icmp", "web", "video"),
            scenarios=("secure-baseline",),
            network_profiles=("clean",),
            runs_per_combination=3,
            workers=1,
            retry_failed=1,
        )
        self.versions = {"icmp": "1", "web": "1", "video": "1"}

    def test_expands_nine_stable_slots_in_declared_order(self) -> None:
        slots = expand_matrix(self.config, self.versions)
        self.assertEqual(len(slots), 9)
        self.assertEqual(slots[0].slot_id, "run_000001")
        self.assertEqual(slots[0].traffic_class, "icmp")
        self.assertEqual(slots[3].traffic_class, "web")
        self.assertEqual(slots[6].traffic_class, "video")
        self.assertEqual(slots[-1].slot_id, "run_000009")

    def test_seed_is_repeatable_and_changes_for_retry(self) -> None:
        first = derive_attempt_seed(20260924, ordinal=1, attempt_number=1)
        self.assertEqual(first, derive_attempt_seed(20260924, 1, 1))
        self.assertNotEqual(first, derive_attempt_seed(20260924, 1, 2))
        self.assertEqual(attempt_id("run_000001", 1), "run_000001")
        self.assertEqual(attempt_id("run_000001", 2), "run_000001-attempt02")

    def test_fingerprint_changes_for_order_seed_or_generator_version(self) -> None:
        original = matrix_fingerprint(self.config, self.versions)
        reordered = replace(self.config, traffic_classes=("web", "icmp", "video"))
        reseeded = replace(self.config, base_seed=7)
        self.assertNotEqual(original, matrix_fingerprint(reordered, self.versions))
        self.assertNotEqual(original, matrix_fingerprint(reseeded, self.versions))
        self.assertNotEqual(original, matrix_fingerprint(self.config, {**self.versions, "web": "2"}))
```

- [ ] **Step 3: Run tests and verify missing APIs fail**

Run:

```bash
python3 -m unittest tests.test_dataset_config tests.test_dataset_matrix -v
```

Expected: import errors for the new configuration and matrix modules.

- [ ] **Step 4: Implement exact immutable configuration parsing**

```python
# ipsec_sentinel/dataset/config.py
@dataclass(frozen=True)
class DatasetConfig:
    name: str
    schema_version: str
    base_seed: int
    traffic_classes: tuple[str, ...]
    scenarios: tuple[str, ...]
    network_profiles: tuple[str, ...]
    runs_per_combination: int
    workers: int
    retry_failed: int

    @classmethod
    def load(cls, path: Path) -> "DatasetConfig":
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        root = _exact_mapping(raw, {
            "dataset", "traffic", "ipsec", "network_profiles",
            "runs_per_combination", "execution",
        }, "matrix")
        dataset = _exact_mapping(root["dataset"], {"name", "schema_version", "seed"}, "dataset")
        traffic = _exact_mapping(root["traffic"], {"classes"}, "traffic")
        ipsec = _exact_mapping(root["ipsec"], {"scenarios"}, "ipsec")
        execution = _exact_mapping(root["execution"], {"workers", "retry_failed"}, "execution")
        config = cls(
            name=_slug(dataset["name"]),
            schema_version=_string(dataset["schema_version"], "schema_version"),
            base_seed=_nonnegative_int(dataset["seed"], "seed"),
            traffic_classes=_unique_strings(traffic["classes"], "traffic.classes"),
            scenarios=_unique_strings(ipsec["scenarios"], "ipsec.scenarios"),
            network_profiles=_unique_strings(root["network_profiles"], "network_profiles"),
            runs_per_combination=_positive_int(root["runs_per_combination"], "runs_per_combination"),
            workers=_positive_int(execution["workers"], "workers"),
            retry_failed=_nonnegative_int(execution["retry_failed"], "retry_failed"),
        )
        if config.schema_version != DATASET_SCHEMA_VERSION:
            raise DatasetConfigError("unsupported dataset schema_version")
        if config.workers != 1:
            raise DatasetConfigError("workers must be 1 in Phase 2")
        if config.network_profiles != ("clean",):
            raise DatasetConfigError("unsupported network profile")
        if config.scenarios != ("secure-baseline",):
            raise DatasetConfigError("unsupported IPsec scenario")
        return config
```

Implement `_exact_mapping`, `_slug`, `_string`, `_unique_strings`, `_positive_int`, and `_nonnegative_int`. Reject booleans where integers are required.

- [ ] **Step 5: Implement canonical expansion, fingerprint, IDs, and seeds**

```python
# ipsec_sentinel/dataset/matrix.py
@dataclass(frozen=True)
class MatrixSlot:
    slot_id: str
    ordinal: int
    scenario_id: str
    traffic_class: str
    network_profile: str
    repetition: int


def expand_matrix(config: DatasetConfig, generator_versions: dict[str, str]) -> tuple[MatrixSlot, ...]:
    unknown = set(config.traffic_classes) - set(generator_versions)
    if unknown:
        raise ValueError(f"unregistered traffic class: {sorted(unknown)[0]}")
    slots: list[MatrixSlot] = []
    ordinal = 0
    for scenario_id in config.scenarios:
        for traffic_class in config.traffic_classes:
            for network_profile in config.network_profiles:
                for repetition in range(1, config.runs_per_combination + 1):
                    ordinal += 1
                    slots.append(MatrixSlot(
                        slot_id=f"run_{ordinal:06d}", ordinal=ordinal,
                        scenario_id=scenario_id, traffic_class=traffic_class,
                        network_profile=network_profile, repetition=repetition,
                    ))
    return tuple(slots)


def derive_attempt_seed(base_seed: int, ordinal: int, attempt_number: int) -> int:
    material = f"sha256-slot-attempt/v1:{base_seed}:{ordinal}:{attempt_number}".encode("ascii")
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big") & ((1 << 63) - 1)


def attempt_id(slot_id: str, attempt_number: int) -> str:
    if attempt_number < 1:
        raise ValueError("attempt_number must be positive")
    return slot_id if attempt_number == 1 else f"{slot_id}-attempt{attempt_number:02d}"
```

Implement `matrix_fingerprint()` with sorted-key compact JSON while preserving list order. Include dataset name/schema, base seed, ordered class/scenario/profile lists, repetitions, and each selected generator version.

- [ ] **Step 6: Add the exact smoke matrix and run tests**

```yaml
# configs/smoke-v1.yaml
dataset:
  name: cipherlens-smoke-v1
  schema_version: ipsec-sentinel.dataset-ground-truth/v1
  seed: 20260924
traffic:
  classes:
    - icmp
    - web
    - video
ipsec:
  scenarios:
    - secure-baseline
network_profiles:
  - clean
runs_per_combination: 3
execution:
  workers: 1
  retry_failed: 1
```

Run:

```bash
python3 -m unittest tests.test_dataset_config tests.test_dataset_matrix -v
python3 -m unittest discover -s tests -v
```

Expected: focused and full non-privileged suites pass.

- [ ] **Step 7: Commit deterministic matrix support**

```bash
git add configs/smoke-v1.yaml ipsec_sentinel/dataset/config.py ipsec_sentinel/dataset/matrix.py tests/test_dataset_config.py tests/test_dataset_matrix.py
git commit -m "feat: add deterministic dataset matrix"
```

### Task 3: Transactional SQLite Manifest and Recovery

**Files:**
- Create: `ipsec_sentinel/dataset/manifest.py`
- Test: `tests/test_dataset_manifest.py`

**Interfaces:**
- Consumes: `DatasetConfig`, `MatrixSlot`, `AttemptOutcome`, `RunState`, `CleanupState`, `attempt_id()`, and `derive_attempt_seed()`.
- Produces: `AttemptPlan`, `Manifest.initialize()`, `Manifest.assert_compatible()`, `Manifest.recover_running()`, `Manifest.next_attempt()`, `Manifest.latest_attempt()`, `Manifest.mark_running()`, `Manifest.finish_attempt()`, `Manifest.finish_attempt_from_outcome()`, `Manifest.slots()`, and `Manifest.attempts()`.

- [ ] **Step 1: Write failing initialization and transition tests**

```python
# tests/test_dataset_manifest.py
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from ipsec_sentinel.dataset.config import DatasetConfig
from ipsec_sentinel.dataset.manifest import Manifest, ManifestMismatch
from ipsec_sentinel.dataset.models import CleanupState, RunState


def config_fixture(runs: int = 3) -> DatasetConfig:
    return DatasetConfig(
        name="cipherlens-smoke-v1",
        schema_version="ipsec-sentinel.dataset-ground-truth/v1",
        base_seed=20260924,
        traffic_classes=("icmp", "web", "video"),
        scenarios=("secure-baseline",), network_profiles=("clean",),
        runs_per_combination=runs, workers=1, retry_failed=1,
    )


class ManifestTest(unittest.TestCase):
    def test_initialization_materializes_pending_first_attempts(self) -> None:
        with TemporaryDirectory() as directory:
            manifest = Manifest(Path(directory) / "manifest.sqlite3")
            manifest.initialize(config_fixture(), "fingerprint", "configs/smoke-v1.yaml",
                                {"icmp": "1", "web": "1", "video": "1"})
            self.assertEqual(len(manifest.slots()), 9)
            attempts = manifest.attempts()
            self.assertEqual(len(attempts), 9)
            self.assertTrue(all(row.state is RunState.PENDING for row in attempts))

    def test_pass_requires_cleanup_and_training_ready(self) -> None:
        manifest, first = self.make_manifest_and_claim()
        with self.assertRaisesRegex(ValueError, "cleanup"):
            manifest.finish_attempt(first.attempt_id, RunState.PASS,
                CleanupState.FAILED, training_ready=True, failure_class=None,
                failure_message=None, traffic_verified=True, ipsec_verified=True,
                capture_verified=True, esp_packets=20, capture_bytes=4096,
                finished_at="2026-09-24T10:00:01Z",
                cleanup_started_at="2026-09-24T10:00:00Z",
                cleanup_finished_at="2026-09-24T10:00:01Z",
                cleanup_actions=(), cleanup_error="injected cleanup failure",
                duration_seconds=1.0)

    def test_stale_running_becomes_incomplete_and_retry_is_independent(self) -> None:
        manifest, first = self.make_manifest_and_claim()
        recovered = manifest.recover_running("2026-09-24T10:00:00Z")
        self.assertEqual(recovered, (first.attempt_id,))
        retry = manifest.next_attempt(first.slot_id, retry_failed=1)
        self.assertEqual(retry.attempt_number, 2)
        self.assertNotEqual(retry.seed, first.seed)
        self.assertEqual(retry.attempt_id, f"{first.slot_id}-attempt02")
        manifest.mark_running(retry.attempt_id, "2026-09-24T10:00:01Z")
        manifest.finish_attempt(
            retry.attempt_id, RunState.FAILED, CleanupState.PASS,
            training_ready=False, failure_class="traffic_generator_failed",
            failure_message="injected", traffic_verified=False,
            ipsec_verified=True, capture_verified=False,
            esp_packets=0, capture_bytes=24,
            finished_at="2026-09-24T10:00:02Z",
            cleanup_started_at="2026-09-24T10:00:01Z",
            cleanup_finished_at="2026-09-24T10:00:02Z",
            cleanup_actions=({"name": "topology_reset", "status": "PASS"},),
            cleanup_error=None, duration_seconds=1.0,
        )
        self.assertIsNone(manifest.next_attempt(first.slot_id, retry_failed=1))

    def test_fingerprint_mismatch_fails_before_mutation(self) -> None:
        manifest, _ = self.make_manifest_and_claim()
        with self.assertRaises(ManifestMismatch):
            manifest.assert_compatible("different")
```

Implement `make_manifest_and_claim()` with a `TemporaryDirectory` registered through `self.addCleanup()`. It initializes `config_fixture(runs=1)` restricted to `traffic_classes=("icmp",)`, obtains its pending attempt through `next_attempt()`, calls `mark_running()`, and returns the open manifest plus plan.

- [ ] **Step 2: Run the manifest test and verify it fails on the missing module**

```bash
python3 -m unittest tests.test_dataset_manifest -v
```

Expected: import error for `ipsec_sentinel.dataset.manifest`.

- [ ] **Step 3: Implement the schema with constraints and event history**

```sql
PRAGMA user_version = 1;
PRAGMA foreign_keys = ON;

CREATE TABLE datasets (
    name TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL,
    matrix_fingerprint TEXT NOT NULL,
    config_path TEXT NOT NULL,
    base_seed INTEGER NOT NULL,
    generator_versions_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE slots (
    slot_id TEXT PRIMARY KEY,
    ordinal INTEGER NOT NULL UNIQUE,
    scenario_id TEXT NOT NULL,
    traffic_class TEXT NOT NULL,
    network_profile TEXT NOT NULL,
    repetition INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('PENDING','RUNNING','PASS','FAILED','INCOMPLETE')),
    successful_attempt_id TEXT,
    FOREIGN KEY(successful_attempt_id) REFERENCES attempts(attempt_id)
);

CREATE TABLE attempts (
    attempt_id TEXT PRIMARY KEY,
    slot_id TEXT NOT NULL,
    attempt_number INTEGER NOT NULL,
    seed INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('PENDING','RUNNING','PASS','FAILED','INCOMPLETE')),
    started_at TEXT,
    finished_at TEXT,
    artifact_path TEXT NOT NULL,
    failure_class TEXT,
    failure_message TEXT,
    cleanup_status TEXT NOT NULL CHECK (cleanup_status IN ('NOT_STARTED','PASS','FAILED')),
    cleanup_started_at TEXT,
    cleanup_finished_at TEXT,
    cleanup_json TEXT NOT NULL DEFAULT '[]',
    cleanup_error TEXT,
    traffic_verified INTEGER NOT NULL DEFAULT 0 CHECK (traffic_verified IN (0,1)),
    ipsec_verified INTEGER NOT NULL DEFAULT 0 CHECK (ipsec_verified IN (0,1)),
    capture_verified INTEGER NOT NULL DEFAULT 0 CHECK (capture_verified IN (0,1)),
    training_ready INTEGER NOT NULL DEFAULT 0 CHECK (training_ready IN (0,1)),
    esp_packets INTEGER NOT NULL DEFAULT 0,
    capture_bytes INTEGER NOT NULL DEFAULT 0,
    duration_seconds REAL NOT NULL DEFAULT 0,
    UNIQUE(slot_id, attempt_number),
    FOREIGN KEY(slot_id) REFERENCES slots(slot_id)
);

CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attempt_id TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    from_state TEXT,
    to_state TEXT NOT NULL,
    reason TEXT NOT NULL,
    FOREIGN KEY(attempt_id) REFERENCES attempts(attempt_id)
);
```

Create `slots` before adding the `successful_attempt_id` foreign key if the local SQLite version rejects the forward reference; the final schema must retain referential integrity.

- [ ] **Step 4: Implement transactional state operations**

```python
# ipsec_sentinel/dataset/manifest.py
@dataclass(frozen=True)
class AttemptPlan:
    attempt_id: str
    slot_id: str
    ordinal: int
    attempt_number: int
    seed: int
    scenario_id: str
    traffic_class: str
    network_profile: str
    artifact_path: str


class Manifest:
    def __init__(self, path: Path) -> None:
        self.path = path
        if not self.path.parent.is_dir():
            raise FileNotFoundError(f"manifest parent does not exist: {self.path.parent}")
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA busy_timeout = 5000")
        self.connection.execute("PRAGMA journal_mode = WAL")

    def recover_running(self, occurred_at: str) -> tuple[str, ...]:
        with self.connection:
            rows = self.connection.execute(
                "SELECT attempt_id, slot_id FROM attempts WHERE state = 'RUNNING' ORDER BY attempt_id"
            ).fetchall()
            for row in rows:
                self.connection.execute(
                    "UPDATE attempts SET state='INCOMPLETE', finished_at=?, failure_class='interrupted', "
                    "failure_message='stale RUNNING attempt recovered during resume', training_ready=0 "
                    "WHERE attempt_id=?", (occurred_at, row["attempt_id"]),
                )
                self.connection.execute(
                    "UPDATE slots SET state='INCOMPLETE' WHERE slot_id=?", (row["slot_id"],)
                )
                self._event(row["attempt_id"], occurred_at, "RUNNING", "INCOMPLETE", "resume recovery")
        return tuple(row["attempt_id"] for row in rows)

    def next_attempt(self, slot_id: str, retry_failed: int) -> AttemptPlan | None:
        with self.connection:
            slot = self.connection.execute(
                "SELECT * FROM slots WHERE slot_id=?", (slot_id,)
            ).fetchone()
            if slot is None:
                raise KeyError(slot_id)
            if slot["state"] == "PASS":
                return None
            pending = self.connection.execute(
                "SELECT * FROM attempts WHERE slot_id=? AND state='PENDING' "
                "ORDER BY attempt_number DESC LIMIT 1", (slot_id,),
            ).fetchone()
            if pending is not None:
                return self._attempt_plan(slot, pending)
            count = self.connection.execute(
                "SELECT COUNT(*) FROM attempts WHERE slot_id=?", (slot_id,)
            ).fetchone()[0]
            if count >= 1 + retry_failed:
                return None
            number = count + 1
            identifier = attempt_id(slot_id, number)
            seed = derive_attempt_seed(self.base_seed, slot["ordinal"], number)
            artifact_path = f"runs/{identifier}"
            self.connection.execute(
                "INSERT INTO attempts(attempt_id,slot_id,attempt_number,seed,state,artifact_path,cleanup_status) "
                "VALUES(?,?,?,?,?,?,?)",
                (identifier, slot_id, number, seed, "PENDING", artifact_path, "NOT_STARTED"),
            )
            self.connection.execute(
                "UPDATE slots SET state='PENDING' WHERE slot_id=?", (slot_id,)
            )
            row = self.connection.execute(
                "SELECT * FROM attempts WHERE attempt_id=?", (identifier,)
            ).fetchone()
            return self._attempt_plan(slot, row)

    def mark_running(self, attempt_id_value: str, started_at: str) -> None:
        with self.connection:
            row = self.connection.execute(
                "SELECT slot_id,state FROM attempts WHERE attempt_id=?", (attempt_id_value,)
            ).fetchone()
            if row is None or row["state"] != "PENDING":
                raise ValueError("only a PENDING attempt can enter RUNNING")
            self.connection.execute(
                "UPDATE attempts SET state='RUNNING',started_at=? WHERE attempt_id=?",
                (started_at, attempt_id_value),
            )
            self.connection.execute(
                "UPDATE slots SET state='RUNNING' WHERE slot_id=?", (row["slot_id"],)
            )
            self._event(attempt_id_value, started_at, "PENDING", "RUNNING", "attempt claimed")

    def finish_attempt(
        self, attempt_id_value: str, state: RunState, cleanup_status: CleanupState,
        *, training_ready: bool, failure_class: str | None,
        failure_message: str | None, traffic_verified: bool,
        ipsec_verified: bool, capture_verified: bool, esp_packets: int,
        capture_bytes: int, finished_at: str, cleanup_started_at: str,
        cleanup_finished_at: str,
        cleanup_actions: tuple[dict[str, object], ...],
        cleanup_error: str | None, duration_seconds: float,
    ) -> None:
        if state is RunState.PASS and (
            cleanup_status is not CleanupState.PASS or not training_ready
            or not all((traffic_verified, ipsec_verified, capture_verified))
        ):
            raise ValueError("PASS requires cleanup and all validation")
        if state is not RunState.PASS and training_ready:
            raise ValueError("only PASS may be training_ready")
        with self.connection:
            row = self.connection.execute(
                "SELECT slot_id,state FROM attempts WHERE attempt_id=?", (attempt_id_value,)
            ).fetchone()
            if row is None or row["state"] != "RUNNING":
                raise ValueError("only RUNNING may enter a terminal state")
            self.connection.execute(
                "UPDATE attempts SET state=?,finished_at=?,failure_class=?,failure_message=?,"
                "cleanup_status=?,cleanup_started_at=?,cleanup_finished_at=?,cleanup_json=?,"
                "cleanup_error=?,traffic_verified=?,ipsec_verified=?,capture_verified=?,"
                "training_ready=?,esp_packets=?,capture_bytes=?,duration_seconds=? WHERE attempt_id=?",
                (state.value, finished_at, failure_class, failure_message, cleanup_status.value,
                 cleanup_started_at, cleanup_finished_at,
                 json.dumps(cleanup_actions, sort_keys=True), cleanup_error,
                 int(traffic_verified), int(ipsec_verified), int(capture_verified),
                 int(training_ready), esp_packets, capture_bytes, duration_seconds,
                 attempt_id_value),
            )
            self.connection.execute(
                "UPDATE slots SET state=?,successful_attempt_id=? WHERE slot_id=?",
                (state.value, attempt_id_value if state is RunState.PASS else None, row["slot_id"]),
            )
            self._event(attempt_id_value, finished_at, "RUNNING", state.value,
                        failure_class or "completed")
```

Implement all declared methods with `BEGIN IMMEDIATE` transactions where a claim or terminal transition must be exclusive. Enforce the transition table in Python before SQL updates. `finish_attempt(PASS, ...)` must require cleanup `PASS`, all three verification flags true, and `training_ready=True`; all other states require `training_ready=False`. A passing attempt sets its slot to `PASS` and `successful_attempt_id`. A failed/incomplete attempt preserves its terminal state until `next_attempt()` inserts a new `PENDING` row.

`finish_attempt_from_outcome()` maps every timestamp, cleanup action/error, validation flag, failure field, count, and byte total from `AttemptOutcome` into `attempts`, calls the same invariant-checked terminal transition, and writes one event row. It must not recompute success from files.

- [ ] **Step 5: Add a crash-window test for durable files without manifest success**

```python
def test_files_do_not_turn_a_stale_running_attempt_into_pass(self) -> None:
    manifest, attempt = self.make_manifest_and_claim()
    artifact = manifest.path.parent / attempt.artifact_path
    artifact.mkdir(parents=True)
    (artifact / "ground_truth.json").write_text('{"status":"PASS"}', encoding="utf-8")
    manifest.recover_running("2026-09-24T10:00:00Z")
    row = next(item for item in manifest.attempts() if item.attempt_id == attempt.attempt_id)
    self.assertEqual(row.state, RunState.INCOMPLETE)
    self.assertFalse(row.training_ready)
```

- [ ] **Step 6: Run focused and full tests**

```bash
python3 -m unittest tests.test_dataset_manifest -v
python3 -m unittest discover -s tests -v
```

Expected: manifest tests pass, including crash recovery and retry budget; full suite remains green.

- [ ] **Step 7: Commit the transactional manifest**

```bash
git add ipsec_sentinel/dataset/manifest.py tests/test_dataset_manifest.py
git commit -m "feat: add resumable dataset manifest"
```

### Task 4: Seeded ICMP Generator

**Files:**
- Create: `ipsec_sentinel/traffic/icmp.py`
- Modify: `ipsec_sentinel/traffic/__init__.py`
- Test: `tests/test_traffic_icmp.py`

**Interfaces:**
- Consumes: `TrafficContext`, `TrafficRunResult`, `TrafficValidation`, `run_checked()`, and `parse_ping()`.
- Produces: `IcmpPlan`, `resolve_icmp_plan(seed)`, `IcmpGenerator`, generator name `icmp`, version `1`.

- [ ] **Step 1: Write failing seeded-plan and validation tests**

```python
# tests/test_traffic_icmp.py
import unittest

from ipsec_sentinel.traffic.icmp import IcmpGenerator, resolve_icmp_plan


PING_OK = "5 packets transmitted, 5 received, 0% packet loss, time 408ms\n"
PING_PARTIAL = "5 packets transmitted, 4 received, 20% packet loss, time 408ms\n"


class IcmpGeneratorTest(unittest.TestCase):
    def test_same_seed_reproduces_plan_and_different_seed_varies_it(self) -> None:
        self.assertEqual(resolve_icmp_plan(41), resolve_icmp_plan(41))
        plans = {resolve_icmp_plan(seed) for seed in range(41, 51)}
        self.assertGreater(len(plans), 1)
        plan = resolve_icmp_plan(41)
        self.assertIn(plan.count, (5, 7, 9))
        self.assertIn(plan.interval_seconds, (0.1, 0.2, 0.3))
        self.assertIn(plan.payload_bytes, (56, 128, 512))

    def test_validation_requires_every_planned_reply(self) -> None:
        generator = IcmpGenerator(seed=41)
        ok = generator.validate_output(PING_OK.replace("5 packets", f"{generator.plan.count} packets", 1)
            .replace("5 received", f"{generator.plan.count} received"))
        failed = generator.validate_output(PING_PARTIAL)
        self.assertTrue(ok.passed)
        self.assertFalse(failed.passed)
        self.assertIn("received", failed.errors[0])

    def test_metadata_contains_every_resolved_parameter(self) -> None:
        metadata = IcmpGenerator(seed=41).metadata()
        self.assertEqual(metadata["generator_version"], "1")
        self.assertEqual(set(metadata["parameters"]), {"count", "interval_seconds", "payload_bytes"})
```

Adjust the success fixture to format exactly the resolved `count`; do not weaken the production validator to accommodate inconsistent fixtures.

- [ ] **Step 2: Run the test and verify the missing-module failure**

```bash
python3 -m unittest tests.test_traffic_icmp -v
```

Expected: import error for `ipsec_sentinel.traffic.icmp`.

- [ ] **Step 3: Implement deterministic planning and real execution**

```python
# ipsec_sentinel/traffic/icmp.py
@dataclass(frozen=True)
class IcmpPlan:
    count: int
    interval_seconds: float
    payload_bytes: int


def resolve_icmp_plan(seed: int) -> IcmpPlan:
    random = Random(seed)
    return IcmpPlan(
        count=random.choice((5, 7, 9)),
        interval_seconds=random.choice((0.1, 0.2, 0.3)),
        payload_bytes=random.choice((56, 128, 512)),
    )


class IcmpGenerator:
    name = "icmp"
    version = "1"

    def __init__(self, seed: int) -> None:
        self.seed = seed
        self.plan = resolve_icmp_plan(seed)
        self._result: TrafficRunResult | None = None

    def prepare(self, context: TrafficContext) -> None:
        return None

    def run(self, context: TrafficContext) -> TrafficRunResult:
        result = run_checked([
            "ip", "netns", "exec", context.client_namespace, "ping",
            "-I", context.client_ip, "-c", str(self.plan.count),
            "-i", str(self.plan.interval_seconds), "-s", str(self.plan.payload_bytes),
            "-W", "2", context.server_ip,
        ], timeout=max(15.0, self.plan.count * (self.plan.interval_seconds + 2.0)), log=context.log)
        self._result = TrafficRunResult({"stdout": result.stdout, "duration_seconds": result.duration_seconds})
        return self._result

    def validate_output(self, stdout: str) -> TrafficValidation:
        evidence = parse_ping(stdout)
        passed = evidence.sent == self.plan.count and evidence.received == self.plan.count and evidence.success
        errors = () if passed else (f"expected {self.plan.count} replies, received {evidence.received}",)
        return TrafficValidation(passed, {
            "sent": evidence.sent, "received": evidence.received,
            "success": evidence.success,
        }, errors)

    def validate(self, context: TrafficContext, result: TrafficRunResult) -> TrafficValidation:
        return self.validate_output(str(result.metrics["stdout"]))

    def cleanup(self, context: TrafficContext) -> None:
        return None

    def metadata(self) -> dict[str, object]:
        return {
            "class": self.name, "known_training_class": True,
            "generator": "ping", "generator_version": self.version,
            "seed": self.seed, "parameters": asdict(self.plan),
            "result": {} if self._result is None else dict(self._result.metrics),
        }
```

Register `icmp` once in `traffic/__init__.py` through an idempotent `register_builtin_generators()` function rather than at unpredictable import sites.

- [ ] **Step 4: Run focused and full tests**

```bash
python3 -m unittest tests.test_traffic_icmp -v
python3 -m unittest discover -s tests -v
```

Expected: deterministic planning and strict reply validation pass; Phase 1 remains green.

- [ ] **Step 5: Commit ICMP traffic support**

```bash
git add ipsec_sentinel/traffic/__init__.py ipsec_sentinel/traffic/icmp.py tests/test_traffic_icmp.py
git commit -m "feat: add seeded ICMP traffic generator"
```

### Task 5: Deterministic Local HTTP Service and Web Generator

**Files:**
- Create: `ipsec_sentinel/traffic/http_service.py`
- Create: `ipsec_sentinel/traffic/http_client.py`
- Create: `ipsec_sentinel/traffic/web.py`
- Modify: `ipsec_sentinel/traffic/__init__.py`
- Test: `tests/test_traffic_web.py`

**Interfaces:**
- Consumes: the traffic contract, `run_checked()`, and only standard-library HTTP/process modules.
- Produces: `HttpResource`, `HttpRequest`, `HttpPlan`, `HttpServiceProcess`, `run_http_client()`, `WebPlan`, `resolve_web_plan(seed)`, `validate_http_receipts()`, `WebGenerator`, generator name `web`, version `1`.

- [ ] **Step 1: Write failing plan, local-service, and receipt-validation tests**

```python
# tests/test_traffic_web.py
from pathlib import Path
from tempfile import TemporaryDirectory
import json
import unittest

from ipsec_sentinel.traffic.http_service import deterministic_body
from ipsec_sentinel.traffic.web import resolve_web_plan, validate_web_result


class WebGeneratorTest(unittest.TestCase):
    def test_seed_reproduces_complete_plan_and_other_seeds_vary(self) -> None:
        first = resolve_web_plan(101)
        self.assertEqual(first, resolve_web_plan(101))
        self.assertNotEqual(first, resolve_web_plan(102))
        self.assertGreaterEqual(len(first.requests), 6)
        self.assertTrue(all(request.think_seconds >= 0 for request in first.requests))

    def test_deterministic_body_has_exact_size(self) -> None:
        first = deterministic_body(seed=101, path="/assets/a.bin", size=4096)
        self.assertEqual(len(first), 4096)
        self.assertEqual(first, deterministic_body(101, "/assets/a.bin", 4096))
        self.assertNotEqual(first, deterministic_body(102, "/assets/a.bin", 4096))

    def test_client_success_without_matching_server_receipts_fails(self) -> None:
        plan = resolve_web_plan(101)
        client = [{"path": request.path, "status": 200, "bytes": request.expected_bytes}
                  for request in plan.requests]
        receipts = client[:-1]
        validation = validate_web_result(plan, client, receipts)
        self.assertFalse(validation.passed)
        self.assertTrue(any("server receipt" in error for error in validation.errors))

    def test_matching_client_and_server_records_pass(self) -> None:
        plan = resolve_web_plan(101)
        records = [{"path": request.path, "status": 200, "bytes": request.expected_bytes}
                   for request in plan.requests]
        self.assertTrue(validate_web_result(plan, records, records).passed)
```

- [ ] **Step 2: Run the web test and verify missing modules fail**

```bash
python3 -m unittest tests.test_traffic_web -v
```

Expected: import errors for the HTTP service and web generator modules.

- [ ] **Step 3: Implement deterministic resource serving and receipt logging**

```python
# ipsec_sentinel/traffic/http_service.py
def deterministic_body(seed: int, path: str, size: int) -> bytes:
    if size < 0:
        raise ValueError("resource size must be nonnegative")
    block = hashlib.sha256(f"{seed}:{path}".encode("utf-8")).digest()
    return (block * ((size + len(block) - 1) // len(block)))[:size]


class ResourceHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        resource = self.server.resources.get(self.path)
        if resource is None:
            self.send_error(404)
            return
        body = deterministic_body(self.server.seed, self.path, resource["size"])
        self.send_response(200)
        self.send_header("Content-Type", resource["content_type"])
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        receipt = {
            "path": self.path, "status": 200, "bytes": len(body),
            "received_unix_ns": time.time_ns(),
        }
        with self.server.receipt_path.open("a", encoding="utf-8") as output:
            output.write(json.dumps(receipt, sort_keys=True) + "\n")
            output.flush()

    def log_message(self, format: str, *args: object) -> None:
        return None
```

Implement a CLI `main()` that loads a strict JSON service plan, binds `ThreadingHTTPServer((bind_address, port), ResourceHandler)`, writes a readiness file only after binding, and serves until SIGTERM/SIGINT. `HttpServiceProcess.start()` launches it with:

```python
[
    "ip", "netns", "exec", context.server_namespace,
    sys.executable, "-m", "ipsec_sentinel.traffic.http_service",
    "--config", str(config_path), "--receipts", str(receipt_path),
    "--ready", str(ready_path),
]
```

It waits with a deadline for the readiness file and fails if the child exits. `stop()` sends SIGTERM, waits, escalates to kill on timeout, closes logs, and is idempotent.

- [ ] **Step 4: Implement the reusable HTTP client**

```python
# ipsec_sentinel/traffic/http_client.py
def execute_plan(plan: dict[str, object]) -> list[dict[str, object]]:
    connection = http.client.HTTPConnection(
        str(plan["server_ip"]), int(plan["port"]), timeout=float(plan["timeout_seconds"])
    )
    results: list[dict[str, object]] = []
    try:
        for request in plan["requests"]:
            started = time.monotonic_ns()
            connection.request("GET", str(request["path"]))
            response = connection.getresponse()
            body = response.read()
            results.append({
                "path": request["path"], "status": response.status,
                "bytes": len(body), "duration_ns": time.monotonic_ns() - started,
            })
            time.sleep(float(request["think_seconds"]))
    finally:
        connection.close()
    return results
```

The CLI reads the plan file and atomically writes JSON results. Non-200 responses, truncated bodies, timeouts, or malformed plans return nonzero.

- [ ] **Step 5: Implement seeded web planning and strict two-sided validation**

```python
# ipsec_sentinel/traffic/web.py
@dataclass(frozen=True)
class WebRequest:
    path: str
    expected_bytes: int
    content_type: str
    think_seconds: float


@dataclass(frozen=True)
class WebPlan:
    port: int
    requests: tuple[WebRequest, ...]


def resolve_web_plan(seed: int) -> WebPlan:
    random = Random(seed)
    pages = [
        ("/pages/home.html", random.choice((4096, 6144, 8192)), "text/html"),
        ("/pages/about.html", random.choice((3072, 5120, 7168)), "text/html"),
        ("/assets/app.css", random.choice((8192, 12288, 16384)), "text/css"),
        ("/assets/app.js", random.choice((16384, 24576, 32768)), "application/javascript"),
        ("/assets/hero.bin", random.choice((65536, 98304, 131072)), "application/octet-stream"),
        ("/assets/icon.bin", random.choice((4096, 8192, 12288)), "application/octet-stream"),
    ]
    random.shuffle(pages)
    request_count = random.randint(6, len(pages))
    requests = tuple(WebRequest(path, size, content_type, random.choice((0.02, 0.05, 0.1)))
                     for path, size, content_type in pages[:request_count])
    return WebPlan(port=8080, requests=requests)
```

`WebGenerator.prepare()` writes its exact resource plan and starts `HttpServiceProcess`. `run()` writes the client plan, invokes `http_client` inside `ips-client`, and loads its result. `validate()` compares every planned path, status, and byte count against both client results and server receipts in order. `cleanup()` stops the tracked service. `metadata()` includes the full request plan and realized records.

- [ ] **Step 6: Run focused and full tests**

```bash
python3 -m unittest tests.test_traffic_web -v
python3 -m unittest discover -s tests -v
```

Expected: seeded variation, exact bodies, and two-sided validation pass; full suite stays green.

- [ ] **Step 7: Commit the controlled web workload**

```bash
git add ipsec_sentinel/traffic tests/test_traffic_web.py
git commit -m "feat: add controlled web traffic generator"
```

### Task 6: Seeded Segmented-video Generator

**Files:**
- Create: `ipsec_sentinel/traffic/video.py`
- Modify: `ipsec_sentinel/traffic/__init__.py`
- Test: `tests/test_traffic_video.py`

**Interfaces:**
- Consumes: `HttpServiceProcess`, `http_client`, and the traffic contract.
- Produces: `VideoProfile`, `VideoSegment`, `VideoPlan`, `resolve_video_plan(seed)`, `validate_video_result()`, `VideoGenerator`, generator name `video`, version `1`.

- [ ] **Step 1: Write failing segmented-plan and validation tests**

```python
# tests/test_traffic_video.py
import unittest

from ipsec_sentinel.traffic.video import resolve_video_plan, validate_video_result


class VideoGeneratorTest(unittest.TestCase):
    def test_plan_is_seeded_multi_segment_and_bounded(self) -> None:
        plan = resolve_video_plan(301)
        self.assertEqual(plan, resolve_video_plan(301))
        self.assertNotEqual(plan, resolve_video_plan(302))
        self.assertGreaterEqual(len(plan.segments), 5)
        self.assertGreater(sum(segment.expected_bytes for segment in plan.segments), 250_000)
        self.assertGreaterEqual(plan.target_duration_seconds, 4.0)
        self.assertTrue(all(segment.path.startswith("/video/segment-") for segment in plan.segments))

    def test_one_large_response_cannot_validate_as_video(self) -> None:
        plan = resolve_video_plan(301)
        one = [{"path": "/video/all.bin", "status": 200,
                "bytes": sum(item.expected_bytes for item in plan.segments)}]
        validation = validate_video_result(plan, one, one, realized_duration_seconds=plan.target_duration_seconds)
        self.assertFalse(validation.passed)
        self.assertTrue(any("segment" in error for error in validation.errors))

    def test_matching_segments_bytes_and_duration_pass(self) -> None:
        plan = resolve_video_plan(301)
        records = [{"path": item.path, "status": 200, "bytes": item.expected_bytes}
                   for item in plan.segments]
        validation = validate_video_result(
            plan, records, records,
            realized_duration_seconds=plan.target_duration_seconds,
        )
        self.assertTrue(validation.passed)
```

- [ ] **Step 2: Run the test and verify the missing-module failure**

```bash
python3 -m unittest tests.test_traffic_video -v
```

Expected: import error for `ipsec_sentinel.traffic.video`.

- [ ] **Step 3: Implement deterministic HLS-like segment planning**

```python
# ipsec_sentinel/traffic/video.py
@dataclass(frozen=True)
class VideoProfile:
    name: str
    bitrate_bps: int
    segment_duration_seconds: float


@dataclass(frozen=True)
class VideoSegment:
    sequence: int
    path: str
    expected_bytes: int
    pace_after_seconds: float


@dataclass(frozen=True)
class VideoPlan:
    port: int
    profile: VideoProfile
    target_duration_seconds: float
    segments: tuple[VideoSegment, ...]


PROFILES = (
    VideoProfile("low", 600_000, 1.0),
    VideoProfile("medium", 1_000_000, 1.0),
    VideoProfile("high", 1_500_000, 1.0),
)


def resolve_video_plan(seed: int) -> VideoPlan:
    random = Random(seed)
    profile = random.choice(PROFILES)
    segment_count = random.randint(5, 7)
    sequence_start = random.randint(0, 200)
    segments = tuple(
        VideoSegment(
            sequence=sequence_start + index,
            path=f"/video/segment-{sequence_start + index:04d}.bin",
            expected_bytes=max(1, round(profile.bitrate_bps * profile.segment_duration_seconds / 8
                                        * random.uniform(0.9, 1.1))),
            pace_after_seconds=(profile.segment_duration_seconds
                                if index < segment_count - 1 else 0.0),
        )
        for index in range(segment_count)
    )
    target_duration = sum(segment.pace_after_seconds for segment in segments)
    return VideoPlan(8081, profile, target_duration, segments)
```

Use the HTTP client request `think_seconds` as segment pacing. Record monotonic start/end around the complete segment sequence. Validation requires exact ordered client and server segment records, expected byte totals, at least five responses, and realized duration within `[target * 0.8, target * 1.5]`. The final segment has zero post-receipt sleep, and `target_duration_seconds` is the sum of the recorded per-segment pacing values.

- [ ] **Step 4: Register video and run focused/full tests**

```bash
python3 -m unittest tests.test_traffic_video -v
python3 -m unittest discover -s tests -v
```

Expected: multi-segment validation passes and the monolithic-response adversarial case fails.

- [ ] **Step 5: Commit segmented-video support**

```bash
git add ipsec_sentinel/traffic/__init__.py ipsec_sentinel/traffic/video.py tests/test_traffic_video.py
git commit -m "feat: add segmented video traffic generator"
```

### Task 7: Deterministic Workload-only ESP PCAP Derivation

**Files:**
- Create: `ipsec_sentinel/pcap.py`
- Test: `tests/test_pcap_workload.py`

**Interfaces:**
- Consumes: `WorkloadWindow`; legacy libpcap files written by tcpdump.
- Produces: `PcapFormatError`, `PcapSummary`, `derive_workload_esp(source, destination, window, peers)`, and `inspect_ml_pcap(path, window, peers)`.

- [ ] **Step 1: Write failing microsecond/nanosecond and boundary tests**

```python
# tests/test_pcap_workload.py
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from ipsec_sentinel.dataset.models import WorkloadWindow
from ipsec_sentinel.pcap import PcapFormatError, derive_workload_esp, inspect_ml_pcap
from tests.pcap_helpers import ethernet_ipv4, write_pcap


class WorkloadPcapTest(unittest.TestCase):
    def test_derives_only_peer_esp_inside_inclusive_window(self) -> None:
        with TemporaryDirectory() as directory:
            source = Path(directory) / "full-evidence.pcap"
            output = Path(directory) / "encrypted.pcap"
            write_pcap(source, [
                (999_999_999, ethernet_ipv4("192.0.2.1", "192.0.2.2", 50, b"before")),
                (1_000_000_000, ethernet_ipv4("192.0.2.1", "192.0.2.2", 50, b"start")),
                (1_100_000_000, ethernet_ipv4("192.0.2.1", "192.0.2.2", 17, b"ike")),
                (2_000_000_000, ethernet_ipv4("192.0.2.2", "192.0.2.1", 50, b"end")),
                (2_000_000_001, ethernet_ipv4("192.0.2.1", "192.0.2.2", 50, b"rekey-period")),
            ], nanoseconds=True)
            summary = derive_workload_esp(
                source, output, WorkloadWindow(1_000_000_000, 2_000_000_000),
                peers=("192.0.2.1", "192.0.2.2"),
            )
            self.assertEqual(summary.packet_count, 2)
            self.assertEqual(inspect_ml_pcap(output, WorkloadWindow(1_000_000_000, 2_000_000_000),
                                             ("192.0.2.1", "192.0.2.2")).packet_count, 2)

    def test_supports_big_endian_microseconds_and_vlan(self) -> None:
        with TemporaryDirectory() as directory:
            source = Path(directory) / "source.pcap"
            output = Path(directory) / "output.pcap"
            frame = ethernet_ipv4("192.0.2.1", "192.0.2.2", 50, b"esp", vlan=True)
            write_pcap(source, [(1_500_000_000, frame)], nanoseconds=False, big_endian=True)
            summary = derive_workload_esp(source, output, WorkloadWindow(1_000_000_000, 2_000_000_000),
                                          ("192.0.2.1", "192.0.2.2"))
            self.assertEqual(summary.packet_count, 1)

    def test_rejects_unsupported_link_type_and_truncated_record(self) -> None:
        with TemporaryDirectory() as directory:
            bad = Path(directory) / "bad.pcap"
            write_pcap(bad, [], link_type=113)
            with self.assertRaisesRegex(PcapFormatError, "link type"):
                derive_workload_esp(bad, Path(directory) / "out.pcap",
                                    WorkloadWindow(1, 2), ("192.0.2.1", "192.0.2.2"))
            bad.write_bytes(bad.read_bytes() + b"\x00\x01")
            with self.assertRaises(PcapFormatError):
                inspect_ml_pcap(bad, WorkloadWindow(1, 2), ("192.0.2.1", "192.0.2.2"))
```

Create `tests/pcap_helpers.py` in this task with real global/record header writers for both byte orders and resolutions plus minimal Ethernet/optional-VLAN/IPv4 frame construction.

- [ ] **Step 2: Run tests and verify the missing-module failure**

```bash
python3 -m unittest tests.test_pcap_workload -v
```

Expected: import error for `ipsec_sentinel.pcap`.

- [ ] **Step 3: Implement strict legacy-PCAP record parsing**

```python
# ipsec_sentinel/pcap.py
MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1),
    b"\xa1\xb2\x3c\x4d": (">", 1),
}


@dataclass(frozen=True)
class PcapSummary:
    packet_count: int
    capture_bytes: int
    first_timestamp_ns: int
    last_timestamp_ns: int
    duration_seconds: float


def _read_header(source: BinaryIO) -> tuple[bytes, str, int]:
    header = source.read(24)
    if len(header) != 24 or header[:4] not in MAGIC:
        raise PcapFormatError("unsupported or truncated legacy PCAP header")
    endian, fraction_to_ns = MAGIC[header[:4]]
    _, major, minor, _, _, _, link_type = struct.unpack(f"{endian}IHHIIII", header)
    if (major, minor) != (2, 4):
        raise PcapFormatError("unsupported PCAP version")
    if link_type != 1:
        raise PcapFormatError(f"unsupported link type: {link_type}")
    return header, endian, fraction_to_ns
```

Iterate 16-byte record headers, require exact captured payload length, reject `included_length > original_length`, and compute `timestamp_ns = seconds * 1_000_000_000 + fraction * fraction_to_ns`. Reject impossible microsecond/nanosecond fractions.

- [ ] **Step 4: Implement Ethernet/VLAN/IPv4 peer ESP selection and atomic output**

```python
def _outer_ipv4(frame: bytes) -> tuple[str, str, int] | None:
    if len(frame) < 14:
        raise PcapFormatError("truncated Ethernet frame")
    offset = 14
    ether_type = int.from_bytes(frame[12:14], "big")
    while ether_type in (0x8100, 0x88A8):
        if len(frame) < offset + 4:
            raise PcapFormatError("truncated VLAN header")
        ether_type = int.from_bytes(frame[offset + 2:offset + 4], "big")
        offset += 4
    if ether_type != 0x0800:
        return None
    if len(frame) < offset + 20 or frame[offset] >> 4 != 4:
        raise PcapFormatError("truncated or invalid IPv4 packet")
    ihl = (frame[offset] & 0x0F) * 4
    if ihl < 20 or len(frame) < offset + ihl:
        raise PcapFormatError("invalid IPv4 header length")
    return (
        str(ipaddress.ip_address(frame[offset + 12:offset + 16])),
        str(ipaddress.ip_address(frame[offset + 16:offset + 20])),
        frame[offset + 9],
    )
```

`derive_workload_esp()` writes the original global header and only matching record-header/payload pairs to a same-directory temporary file, `fsync()`s it, and atomically replaces the destination. `inspect_ml_pcap()` rejects every non-ESP, wrong-peer, or out-of-window record and rejects zero records. Both return exact count, size, first/last timestamp, and duration.

- [ ] **Step 5: Add adversarial timestamp-resolution and wrong-peer assertions, then run all tests**

```python
def test_rejects_wrong_peer_and_out_of_window_packets_in_ml_capture(self) -> None:
    # Build an output-like PCAP containing one 198.51.100.0/24 ESP frame and assert failure.
    with self.assertRaisesRegex(PcapFormatError, "peer"):
        inspect_ml_pcap(path, window, ("192.0.2.1", "192.0.2.2"))
```

Run:

```bash
python3 -m unittest tests.test_pcap_workload -v
python3 -m unittest discover -s tests -v
```

Expected: all PCAP edge cases and full suite pass.

- [ ] **Step 6: Commit PCAP derivation**

```bash
git add ipsec_sentinel/pcap.py tests/pcap_helpers.py tests/test_pcap_workload.py
git commit -m "feat: derive workload-only ESP captures"
```

### Task 8: Extract the Reusable Secure-session Lifecycle

**Files:**
- Create: `ipsec_sentinel/session.py`
- Modify: `ipsec_sentinel/runner.py`
- Test: `tests/test_session.py`
- Modify: `tests/test_runner.py`
- Verify: `tests/test_secure_baseline_integration.py`

**Interfaces:**
- Consumes: existing `Topology`, `StrongSwanPair`, `CaptureSession`, `Scenario`, capture validators, SA/XFRM/PFS evaluators, and artifact helpers.
- Produces: `SecureSession`, `SecureSessionEvidence`, and unchanged `run_secure_baseline(scenario, keep_lab=False, *, runs_root=Path("runs")) -> int`.

- [ ] **Step 1: Write failing lifecycle ownership and capture-name tests**

```python
# tests/test_session.py
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from ipsec_sentinel.session import SecureSession


class SecureSessionTest(unittest.TestCase):
    def test_dataset_and_phase_one_primary_capture_names_do_not_overlap_semantics(self) -> None:
        with TemporaryDirectory() as directory:
            phase_one = SecureSession(Path(directory) / "phase1", StringIO(),
                                      primary_capture_name="encrypted.pcap")
            dataset = SecureSession(Path(directory) / "dataset", StringIO(),
                                    primary_capture_name="full-evidence.pcap")
            self.assertEqual(phase_one.primary_destination.name, "encrypted.pcap")
            self.assertEqual(dataset.primary_destination.name, "full-evidence.pcap")

    def test_cleanup_attempts_traffic_independent_session_layers(self) -> None:
        observed: list[str] = []
        session = SecureSession.for_test(
            capture_cleanup=lambda: observed.append("captures"),
            log_cleanup=lambda: observed.append("logs"),
            daemon_cleanup=lambda: observed.append("daemons"),
            topology_cleanup=lambda: observed.append("topology"),
        )
        session.cleanup()
        self.assertEqual(observed, ["captures", "logs", "daemons", "topology"])
```

Extend `tests/test_runner.py` so its exact existing `ORDERED_STAGES` assertion remains unchanged after refactoring.

- [ ] **Step 2: Run session and runner tests and verify the new API is absent**

```bash
python3 -m unittest tests.test_session tests.test_runner -v
```

Expected: import error for `SecureSession`; existing runner tests still demonstrate the Phase 1 contract.

- [ ] **Step 3: Move existing mechanics into `SecureSession` without changing behavior**

```python
# ipsec_sentinel/session.py
@dataclass(frozen=True)
class SecureSessionEvidence:
    scenario: Scenario
    scenario_yaml: str
    sas: dict[str, str]
    xfrm: dict[str, str]
    pfs: PfsObservation
    capture: CaptureEvidence
    capture_started_at: float
    capture_ended_at: float
    rekey: RekeyEvidence


class SecureSession:
    def __init__(
        self,
        run_dir: Path,
        log: TextIO,
        *,
        primary_capture_name: str,
        keep_lab: bool = False,
    ) -> None:
        if primary_capture_name not in ("encrypted.pcap", "full-evidence.pcap"):
            raise ValueError("unsupported primary capture name")
        self.run_dir = run_dir
        self.log = log
        self.keep_lab = keep_lab
        self.topology = Topology(log)
        self.pair = StrongSwanPair(log)
        self.primary_destination = run_dir / primary_capture_name
        self.runtime_dir = Path("/run/ipsec-sentinel") / run_dir.name / "capture"
        self.temporary_pcaps = {
            "primary": self.runtime_dir / primary_capture_name,
            "gateway-a": self.runtime_dir / "cleartext-audit-gateway-a.pcap",
            "gateway-b": self.runtime_dir / "cleartext-audit-gateway-b.pcap",
        }
        self.destinations = {
            "primary": self.primary_destination,
            "gateway-a": run_dir / "cleartext-audit-gateway-a.pcap",
            "gateway-b": run_dir / "cleartext-audit-gateway-b.pcap",
        }
        self.captures = {
            "primary": CaptureSession(self.temporary_pcaps["primary"], run_dir / "tcpdump.log"),
            "gateway-a": CaptureSession(
                self.temporary_pcaps["gateway-a"], run_dir / "tcpdump-audit-gateway-a.log",
                capture_filter=AUDIT_FILTER,
            ),
            "gateway-b": CaptureSession(
                self.temporary_pcaps["gateway-b"], run_dir / "tcpdump-audit-gateway-b.log",
                namespace="ips-gwb", capture_filter=AUDIT_FILTER,
            ),
        }
        self.scenario: Scenario | None = None
        self.scenario_yaml = ""
        self.sas: dict[str, str] = {}
        self.xfrm: dict[str, str] = {}
        self.rekey_evidence: RekeyEvidence | None = None
        self.pfs = PfsObservation.not_tested()
        self.capture_evidence: CaptureEvidence | None = None
        self.capture_started_at = 0.0
        self.capture_ended_at = 0.0

    def preflight(self) -> None:
        if os.geteuid() != 0:
            raise PermissionError("IPsec Sentinel must run as Linux root")
        for program in ("ip", "swanctl", "charon-systemd", "tcpdump", "ping"):
            if shutil.which(program) is None:
                raise RuntimeError(f"required program is missing: {program}")
        run_checked(["ip", "xfrm", "state"], 5, self.log)
        run_checked(["ip", "xfrm", "policy"], 5, self.log)
        if not Path("/proc/net/xfrm_stat").is_file():
            raise RuntimeError("kernel XFRM statistics are unavailable")
        if "rfc4106(gcm(aes))" not in Path("/proc/crypto").read_text(encoding="utf-8"):
            raise RuntimeError("kernel RFC 4106 AES-GCM support is unavailable")

    def reset(self) -> None:
        self.topology.reset()

    def load_scenario(self, scenario: str | Path) -> Scenario:
        path = scenario if isinstance(scenario, Path) else Path("scenarios") / f"{scenario}.yaml"
        self.scenario_yaml = path.read_text(encoding="utf-8")
        self.scenario = Scenario.load(path)
        return self.scenario

    def setup_topology(self) -> None:
        self.topology.setup()
        failures = [check.name for check in self.topology.verify() if not check.passed]
        if failures:
            raise RuntimeError(f"topology readback failed: {', '.join(failures)}")

    def start_daemons(self) -> None:
        self.pair.start(self.run_dir)

    def start_captures(self) -> None:
        self.runtime_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.runtime_dir, 0o700)
        self.capture_started_at = time()
        for capture in self.captures.values():
            capture.start()

    def load_configuration(self) -> dict[str, str]:
        return self.pair.load()

    def initiate(self) -> str:
        return self.pair.initiate()

    def wait_for_sa(self) -> dict[str, str]:
        deadline = monotonic() + 10
        while monotonic() < deadline:
            self.sas = self.pair.list_sas()
            if all(parse_sa(self.sas[name]).ike_state == "ESTABLISHED"
                   and parse_sa(self.sas[name]).child_state == "INSTALLED"
                   for name in ("gateway-a", "gateway-b")):
                return self.sas
            sleep(0.1)
        raise TimeoutError("IKE and CHILD SAs did not become established")

    def collect_xfrm(self) -> dict[str, str]:
        for gateway, namespace in (("gateway-a", "ips-gwa"), ("gateway-b", "ips-gwb")):
            state = run_checked(
                ["ip", "netns", "exec", namespace, "ip", "xfrm", "state"], 5, self.log
            ).stdout
            policy = run_checked(
                ["ip", "netns", "exec", namespace, "ip", "xfrm", "policy"], 5, self.log
            ).stdout
            self.xfrm[gateway] = f"STATE\n{state}POLICY\n{policy}"
        return self.xfrm

    def rekey(self) -> PfsObservation:
        self.rekey_evidence = self.pair.rekey()
        self.pfs = evaluate_pfs(
            self.rekey_evidence.before_sas, self.rekey_evidence.after_sas,
            self.rekey_evidence.log_segment, attempted=self.rekey_evidence.attempted,
            completed=self.rekey_evidence.completed,
        )
        return self.pfs

    def stop_captures(self) -> None:
        run_cleanup_steps(tuple((name, capture.stop) for name, capture in self.captures.items()))
        self.capture_ended_at = time()
        for name, destination in self.destinations.items():
            shutil.move(str(self.temporary_pcaps[name]), destination)
        self.runtime_dir.rmdir()

    def validate_captures(self) -> CaptureEvidence:
        primary = validate_pcap(
            self.primary_destination, ("192.0.2.1", "192.0.2.2"),
            self.capture_started_at, self.capture_ended_at,
        )
        cleartext = validate_wire_cleartext(
            self.destinations["gateway-a"], self.destinations["gateway-b"],
            started_at=self.capture_started_at, ended_at=self.capture_ended_at,
        )
        self.capture_evidence = replace(primary, cleartext_packets=cleartext)
        return self.capture_evidence

    def evidence(self) -> SecureSessionEvidence:
        if self.scenario is None or self.capture_evidence is None or self.rekey_evidence is None:
            raise RuntimeError("secure-session evidence is incomplete")
        if not self.sas or not self.xfrm:
            raise RuntimeError("SA or XFRM evidence is incomplete")
        return SecureSessionEvidence(
            self.scenario, self.scenario_yaml, self.sas, self.xfrm, self.pfs,
            self.capture_evidence, self.capture_started_at, self.capture_ended_at,
            self.rekey_evidence,
        )

    def preserve_diagnostics(self) -> None:
        for name, temporary in self.temporary_pcaps.items():
            destination = self.destinations[name]
            if temporary.is_file() and not destination.exists():
                shutil.move(str(temporary), destination)
        for directory in (self.runtime_dir, self.runtime_dir.parent):
            try:
                directory.rmdir()
            except OSError:
                pass
        for gateway, files in self.pair.files.items():
            if files.log.is_file():
                write_text_atomic(
                    self.run_dir / f"strongswan-{gateway}.log",
                    files.log.read_text(encoding="utf-8", errors="replace"),
                )
        if self.rekey_evidence is not None:
            write_text_atomic(self.run_dir / "pfs-rekey.log", self.rekey_evidence.log_segment)
            for gateway in ("gateway-a", "gateway-b"):
                write_text_atomic(self.run_dir / f"swanctl-before-rekey-{gateway}.txt",
                                  self.rekey_evidence.before_sas[gateway])
                write_text_atomic(self.run_dir / f"swanctl-after-rekey-{gateway}.txt",
                                  self.rekey_evidence.after_sas[gateway])

    def cleanup(self) -> None:
        steps: list[tuple[str, Callable[[], None]]] = [
            ("capture_stop", lambda: run_cleanup_steps(
                tuple((name, capture.stop) for name, capture in self.captures.items()))),
            ("log_copy", self.preserve_diagnostics),
            ("daemon_stop", self.pair.stop),
        ]
        if not self.keep_lab:
            steps.append(("topology_reset", self.topology.reset))
        run_cleanup_steps(tuple(steps))
```

Factor the shared `run_cleanup_steps()` helper into `session.py` or a dependency-free utility imported by both modules. Preserve the exact cleanup order: captures, logs, daemons, optional topology reset. Add focused tests for partial capture startup and repeated cleanup so this extraction retains Phase 1's fail-closed behavior.

- [ ] **Step 4: Convert `run_secure_baseline()` into a compatibility adapter**

```python
# ipsec_sentinel/runner.py
def run_secure_baseline(
    scenario: str | Path,
    keep_lab: bool = False,
    *,
    runs_root: Path = Path("runs"),
) -> int:
    run_dir = create_run_dir(runs_root, datetime.now(timezone.utc))
    run_id = run_dir.name
    log = StringIO()
    session = SecureSession(
        run_dir, log, primary_capture_name="encrypted.pcap", keep_lab=keep_lab
    )
    context: dict[str, object] = {}

    actions = {
        "preflight": session.preflight,
        "reset": session.reset,
        "scenario_load": lambda: context.update(scenario=session.load_scenario(scenario)),
        "topology_setup_readback": session.setup_topology,
        "daemon_start": session.start_daemons,
        "capture_start": session.start_captures,
        "configuration_load": lambda: context.update(load=session.load_configuration()),
        "initiate": lambda: context.update(initiate=session.initiate()),
        "sa_wait": lambda: context.update(sas=session.wait_for_sa()),
        "xfrm_collection": lambda: context.update(xfrm=session.collect_xfrm()),
        "icmp": lambda: context.update(ping=_run_phase_one_ping(session, context["scenario"])),
        "pfs_rekey": lambda: context.update(pfs=session.rekey()),
        "capture_stop": session.stop_captures,
        "pcap_validation": lambda: context.update(capture=session.validate_captures()),
        "verdict": lambda: _phase_one_verdict(run_id, session, context),
        "artifacts": lambda: _write_phase_one_artifacts(run_dir, log, session, context),
        "cleanup": session.cleanup,
    }
```

Preserve the current failure artifact behavior, status output, return codes, `ORDERED_STAGES`, ground-truth schema, and rekey files. Extract private helpers only where their exact unit tests keep behavior visible.

- [ ] **Step 5: Run all ordinary tests, then the real Phase 1 integration**

Run inside WSL/Linux:

```bash
python3 -m unittest discover -s tests -v
sudo env IPSEC_SENTINEL_INTEGRATION=1 \
  python3 -m unittest tests.test_secure_baseline_integration -v
```

Expected: all ordinary tests pass with only the guarded integration skipped; the explicit privileged test passes and confirms real IKE/ESP/PFS plus cleanup.

- [ ] **Step 6: Commit the lifecycle extraction**

```bash
git add ipsec_sentinel/session.py ipsec_sentinel/runner.py tests/test_session.py tests/test_runner.py
git commit -m "refactor: extract reusable secure session lifecycle"
```

### Task 9: Dataset Attempt Runner, Reproducibility, Artifacts, and Failure Semantics

**Files:**
- Modify: `ipsec_sentinel/evidence.py`
- Create: `ipsec_sentinel/dataset/network.py`
- Create: `ipsec_sentinel/dataset/artifacts.py`
- Create: `ipsec_sentinel/dataset/runner.py`
- Modify: `tests/test_evidence.py`
- Test: `tests/test_dataset_runner.py`

**Interfaces:**
- Consumes: `AttemptPlan`, `SecureSession`, traffic registry, PCAP derivation, Phase 1 evidence types, atomic writers, and clean network profile.
- Produces: `collect_reproducibility()`, `classify_failure()`, `minimum_esp_packets()`, `write_raw_attempt_artifacts()`, `build_terminal_payloads()`, `stage_terminal_json()`, `publish_terminal_json()`, `run_dataset_attempt(plan, dataset_root, matrix_fingerprint, clock=time, stage_hook=lambda stage: None) -> AttemptOutcome`, and complete per-attempt artifacts.

- [ ] **Step 1: Write failing reproducibility and failure-state tests**

First add a traffic-independent IPsec evidence test:

```python
# addition to tests/test_evidence.py
def test_ipsec_evaluator_does_not_require_an_icmp_workload(self) -> None:
    sas, xfrm, _, capture = baseline_inputs()
    pfs = PfsObservation("VERIFIED", True, ("fresh ECP_384 DH",))
    tunnel = evaluate_tunnel(sas, xfrm, run_id="dataset-run")
    self.assertEqual(tunnel.status, "PASS")
    verification = evaluate_ipsec(sas, xfrm, capture, run_id="dataset-run", pfs=pfs)
    self.assertEqual(verification.status, "PASS")
    self.assertNotIn("traffic.icmp", {check.name for check in verification.checks})
    self.assertTrue(all(check.passed for check in verification.checks))
```

Import `evaluate_tunnel`, `evaluate_ipsec`, and `PfsObservation` in that test module, then add the dataset-runner cases:

```python
# tests/test_dataset_runner.py
from pathlib import Path
from tempfile import TemporaryDirectory
import json
import unittest

from ipsec_sentinel.dataset.models import CleanupState, RunState
from ipsec_sentinel.dataset.artifacts import stage_terminal_json, publish_terminal_json
from ipsec_sentinel.dataset.runner import classify_failure, finalize_attempt_state


class DatasetRunnerTest(unittest.TestCase):
    def test_failure_classification_is_stable(self) -> None:
        self.assertEqual(classify_failure("sa_wait", TimeoutError("no SA")),
                         "tunnel_establishment_failed")
        self.assertEqual(classify_failure("traffic_validate", ValueError("receipts")),
                         "traffic_validation_failed")
        self.assertEqual(classify_failure("pcap_derive", ValueError("pcap")),
                         "pcap_derivation_failed")

    def test_cleanup_failure_excludes_otherwise_valid_data(self) -> None:
        state, ready, failure_class = finalize_attempt_state(
            interrupted=False, primary_error=None,
            cleanup_state=CleanupState.FAILED,
            validations=(True, True, True),
        )
        self.assertEqual(state, RunState.FAILED)
        self.assertFalse(ready)
        self.assertEqual(failure_class, "cleanup_failed")

    def test_interruption_remains_incomplete_even_when_cleanup_passes(self) -> None:
        state, ready, failure_class = finalize_attempt_state(
            interrupted=True, primary_error=KeyboardInterrupt(),
            cleanup_state=CleanupState.PASS,
            validations=(False, False, False),
        )
        self.assertEqual(state, RunState.INCOMPLETE)
        self.assertFalse(ready)
        self.assertEqual(failure_class, "interrupted")
```

- [ ] **Step 2: Write a failing artifact-publication test using real temporary files**

```python
def test_terminal_json_is_published_only_after_cleanup_result(self) -> None:
    with TemporaryDirectory() as directory:
        run_dir = Path(directory) / "run_000001"
        run_dir.mkdir()
        payloads = {
            "ground_truth.json": {
                "status": "FAILED", "training_ready": False,
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
```

- [ ] **Step 3: Run tests and verify missing APIs fail**

```bash
python3 -m unittest tests.test_dataset_runner -v
```

Expected: import errors for the dataset runner/artifact APIs.

- [ ] **Step 4: Extract traffic-independent IPsec evaluation**

```python
# ipsec_sentinel/evidence.py
def evaluate_tunnel(
    sas: dict[str, str], xfrm: dict[str, str], *, run_id: str = "",
) -> Verification:
    return _verification(run_id, _sa_xfrm_checks(sas, xfrm))


def evaluate_ipsec(
    sas: dict[str, str], xfrm: dict[str, str], capture: CaptureEvidence,
    *, run_id: str = "", pfs: PfsObservation | None = None,
) -> Verification:
    checks = list(evaluate_tunnel(sas, xfrm, run_id=run_id).checks)
    checks.extend(_capture_checks(capture))
    if pfs is not None:
        checks.append(_check(
            "pfs.rekey_fresh_dh",
            pfs.status == "VERIFIED" and pfs.rekey_observed,
            pfs.status,
        ))
    return _verification(run_id, checks)


def evaluate_baseline(
    sas: dict[str, str], xfrm: dict[str, str], ping: str,
    capture: CaptureEvidence, *, run_id: str = "",
    pfs: PfsObservation | None = None,
) -> Verification:
    checks = _sa_xfrm_checks(sas, xfrm)
    traffic = parse_ping(ping)
    checks.append(_check("traffic.icmp", traffic.success and traffic.sent == 5,
                         f"{traffic.received}/{traffic.sent}"))
    checks.extend(_capture_checks(capture))
    if pfs is not None:
        checks.append(_check(
            "pfs.rekey_fresh_dh",
            pfs.status == "VERIFIED" and pfs.rekey_observed,
            pfs.status,
        ))
    return _verification(run_id, checks)
```

Move the existing SA/XFRM check construction unchanged into `_sa_xfrm_checks()`, the four existing capture checks unchanged into `_capture_checks()`, and status/stage construction unchanged into `_verification()`. This preserves Phase 1's five-packet ICMP rule and check names while allowing dataset traffic validation to remain generator-specific.

- [ ] **Step 5: Implement clean network profile and reproducibility collection**

```python
# ipsec_sentinel/dataset/network.py
@dataclass(frozen=True)
class CleanNetworkProfile:
    name: str = "clean"
    def apply(self, log: TextIO) -> None: return None
    def verify(self, log: TextIO) -> dict[str, object]:
        for namespace in ("ips-gwa", "ips-gwb"):
            result = run_checked(["ip", "netns", "exec", namespace,
                                  "tc", "qdisc", "show"], 5, log)
            if "netem" in result.stdout:
                raise RuntimeError(f"unexpected netem state in {namespace}")
        return {"profile": "clean", "latency_ms": 0, "jitter_ms": 0,
                "packet_loss_percent": 0, "bandwidth_limit_bps": None}
    def cleanup(self, log: TextIO) -> None: return None
```

Add dataset-specific preflight requirements before topology creation:

```python
def dataset_preflight() -> None:
    for program in ("git", "tc", "python3"):
        if shutil.which(program) is None:
            raise RuntimeError(f"required dataset program is missing: {program}")
```

Collect the complete reproducibility record after the workload window is known:

```python
def collect_reproducibility(
    *, context: TrafficContext, generator: TrafficGenerator,
    matrix_fingerprint: str, run_started_at: str, run_finished_at: str,
    window: WorkloadWindow | None,
) -> ReproducibilityMetadata:
    errors: list[str] = []
    def optional_command(argv: list[str], name: str) -> str:
        try:
            return run_checked(argv, 10, context.log).stdout.strip()
        except BaseException as error:
            errors.append(f"{name}: {error}")
            return "UNAVAILABLE"

    commit = optional_command(["git", "rev-parse", "HEAD"], "git_commit_sha")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        errors.append("git_commit_sha: invalid or unavailable")
    status = optional_command(["git", "status", "--porcelain"], "git_status")
    dirty = bool(status.strip())
    diff_hash = None
    if dirty and status != "UNAVAILABLE":
        diff = optional_command(["git", "diff", "--binary", "HEAD"], "git_diff")
        diff_hash = hashlib.sha256(diff.encode("utf-8")).hexdigest()
    strongswan = optional_command(["swanctl", "--version"], "strongswan_version")
    return ReproducibilityMetadata(
        git_commit_sha=commit, git_dirty=dirty, git_diff_sha256=diff_hash,
        dataset_schema_version=DATASET_SCHEMA_VERSION,
        scenario_schema_version=SCENARIO_SCHEMA_VERSION,
        manifest_schema_version=MANIFEST_SCHEMA_VERSION,
        strongswan_version=strongswan,
        kernel_release=platform.release(), kernel_version=platform.version(),
        python_implementation=platform.python_implementation(),
        python_version=platform.python_version(), platform=platform.platform(),
        architecture=platform.machine(), generator=generator.name,
        generator_version=generator.version,
        seed_derivation_version=SEED_DERIVATION_VERSION,
        random_seed=context.seed, matrix_fingerprint=matrix_fingerprint,
        run_started_at=run_started_at, run_finished_at=run_finished_at,
        workload_started_unix_ns=0 if window is None else window.started_unix_ns,
        workload_finished_unix_ns=0 if window is None else window.finished_unix_ns,
        collection_errors=tuple(errors),
    )


def unavailable_reproducibility(
    *, context: TrafficContext, generator: TrafficGenerator,
    matrix_fingerprint: str, run_started_at: str, run_finished_at: str,
    window: WorkloadWindow | None, error: BaseException,
) -> ReproducibilityMetadata:
    return ReproducibilityMetadata(
        git_commit_sha="UNAVAILABLE", git_dirty=False, git_diff_sha256=None,
        dataset_schema_version=DATASET_SCHEMA_VERSION,
        scenario_schema_version=SCENARIO_SCHEMA_VERSION,
        manifest_schema_version=MANIFEST_SCHEMA_VERSION,
        strongswan_version="UNAVAILABLE", kernel_release=platform.release(),
        kernel_version=platform.version(),
        python_implementation=platform.python_implementation(),
        python_version=platform.python_version(), platform=platform.platform(),
        architecture=platform.machine(), generator=generator.name,
        generator_version=generator.version,
        seed_derivation_version=SEED_DERIVATION_VERSION,
        random_seed=context.seed, matrix_fingerprint=matrix_fingerprint,
        run_started_at=run_started_at, run_finished_at=run_finished_at,
        workload_started_unix_ns=0 if window is None else window.started_unix_ns,
        workload_finished_unix_ns=0 if window is None else window.finished_unix_ns,
        collection_errors=(f"metadata collector: {error}",),
    )
```

Always publish this record, including `UNAVAILABLE` values and `collection_errors`, for failed and incomplete attempts. A would-be successful attempt becomes `FAILED` with `failure_class=metadata_collection_failed` when `collection_errors` is nonempty.

- [ ] **Step 6: Implement the exact attempt orchestration**

```python
# ipsec_sentinel/dataset/runner.py
DATASET_STAGES = (
    "preflight", "reset", "scenario_load", "topology_setup_readback",
    "network_profile", "daemon_start", "traffic_prepare", "capture_start", "configuration_load",
    "initiate", "sa_wait", "xfrm_collection", "traffic_run",
    "traffic_validate", "pfs_rekey", "capture_stop", "full_pcap_validate",
    "pcap_derive", "ml_pcap_validate", "artifacts", "cleanup",
    "metadata", "terminal_publish",
)

FAILURE_BY_STAGE = {
    "preflight": "preflight_failed",
    "reset": "topology_failed",
    "scenario_load": "configuration_failed",
    "topology_setup_readback": "topology_failed",
    "network_profile": "topology_failed",
    "daemon_start": "tunnel_establishment_failed",
    "traffic_prepare": "traffic_prepare_failed",
    "capture_start": "capture_failed",
    "configuration_load": "tunnel_establishment_failed",
    "initiate": "tunnel_establishment_failed",
    "sa_wait": "tunnel_establishment_failed",
    "xfrm_collection": "ipsec_evidence_failed",
    "traffic_run": "traffic_generator_failed",
    "traffic_validate": "traffic_validation_failed",
    "pfs_rekey": "ipsec_evidence_failed",
    "capture_stop": "capture_failed",
    "full_pcap_validate": "capture_failed",
    "pcap_derive": "pcap_derivation_failed",
    "ml_pcap_validate": "zero_or_insufficient_esp",
    "artifacts": "artifact_publication_failed",
    "metadata": "metadata_collection_failed",
    "terminal_publish": "artifact_publication_failed",
}


def classify_failure(stage: str, error: BaseException) -> str:
    if isinstance(error, KeyboardInterrupt):
        return "interrupted"
    return FAILURE_BY_STAGE.get(stage, "unexpected_error")


def finalize_attempt_state(
    *, interrupted: bool, primary_error: BaseException | None,
    primary_failure_class: str | None = None,
    cleanup_state: CleanupState, validations: tuple[bool, bool, bool],
) -> tuple[RunState, bool, str | None]:
    if interrupted:
        return RunState.INCOMPLETE, False, "interrupted"
    if cleanup_state is CleanupState.FAILED:
        return RunState.FAILED, False, "cleanup_failed"
    if primary_error is not None:
        return RunState.FAILED, False, primary_failure_class or "unexpected_error"
    if not all(validations):
        return RunState.FAILED, False, "dataset_validation_failed"
    return RunState.PASS, True, None
```

`run_dataset_attempt()` implements the numbered lifecycle in the spec. It records `workload_started_unix_ns = time.time_ns()` immediately before `generator.run(context)` and `workload_finished_unix_ns` immediately after it returns. It validates traffic before calling `session.rekey()`, then stops/validates `full-evidence.pcap`, derives `encrypted.pcap`, and calls `inspect_ml_pcap()`.

Call `stage_hook(stage_name)` immediately before every stage action. Its default is a no-op; tests may inject a failure at a named boundary without adding environment-variable behavior to production.

Use explicit minimum ML ESP counts derived from the resolved workload metadata:

```python
def minimum_esp_packets(traffic_class: str, parameters: dict[str, object]) -> int:
    if traffic_class == "icmp":
        return 2 * int(parameters["count"])
    if traffic_class == "web":
        return max(10, 2 * len(parameters["requests"]))
    if traffic_class == "video":
        return max(20, 3 * len(parameters["segments"]))
    raise ValueError(f"unsupported traffic class: {traffic_class}")
```

Fail with `zero_or_insufficient_esp` when the derived ML capture is below this threshold. Traffic validation remains the source of the label; this count only rejects empty or control-only captures.

Implement the orchestration with an explicit current stage, real workload boundaries, and cleanup that is independent of the primary failure:

```python
def _noop_stage(stage: str) -> None:
    return None


def run_dataset_attempt(
    plan: AttemptPlan,
    dataset_root: Path,
    matrix_fingerprint: str,
    *,
    clock: object = time,
    stage_hook: Callable[[str], None] = _noop_stage,
    session_factory: Callable[..., SecureSession] = SecureSession,
    generator_factory: Callable[[str, int], TrafficGenerator] = create_generator,
) -> AttemptOutcome:
    run_dir = dataset_root / plan.artifact_path
    run_dir.mkdir(parents=True, mode=0o750)
    log = StringIO()
    generator = generator_factory(plan.traffic_class, plan.seed)
    context = TrafficContext(run_dir, log, plan.seed, plan.scenario_id,
                             plan.network_profile)
    session = session_factory(run_dir, log, primary_capture_name="full-evidence.pcap")
    profile = CleanNetworkProfile()
    stages: list[StageRecord] = []
    cleanup_actions: list[dict[str, object]] = []
    current_stage = "preflight"
    primary_error: BaseException | None = None
    failure_class: str | None = None
    interrupted = False
    traffic_verified = False
    ipsec_verified = False
    capture_verified = False
    workload_window: WorkloadWindow | None = None
    traffic_result: TrafficRunResult | None = None
    traffic_validation: TrafficValidation | None = None
    tunnel_verification: Verification | None = None
    ipsec_verification: Verification | None = None
    ml_summary: PcapSummary | None = None
    scenario: Scenario | None = None
    network_metadata: dict[str, object] | None = None
    run_started_at = utc_now()

    def execute(name: str, action: Callable[[], object]) -> object:
        nonlocal current_stage
        current_stage = name
        stage_hook(name)
        value = action()
        stages.append(StageRecord(name, "PASS", "completed"))
        return value

    try:
        execute("preflight", lambda: (dataset_preflight(), session.preflight()))
        execute("reset", session.reset)
        scenario = execute("scenario_load", lambda: session.load_scenario(plan.scenario_id))
        execute("topology_setup_readback", session.setup_topology)
        network_metadata = execute(
            "network_profile", lambda: (profile.apply(log), profile.verify(log))[1]
        )
        execute("daemon_start", session.start_daemons)
        execute("traffic_prepare", lambda: generator.prepare(context))
        execute("capture_start", session.start_captures)
        execute("configuration_load", session.load_configuration)
        execute("initiate", session.initiate)
        sas = execute("sa_wait", session.wait_for_sa)
        xfrm = execute("xfrm_collection", session.collect_xfrm)
        tunnel_verification = evaluate_tunnel(sas, xfrm, run_id=plan.attempt_id)
        if tunnel_verification.status != "PASS":
            raise RuntimeError("tunnel SA/XFRM evidence failed")

        current_stage = "traffic_run"
        stage_hook(current_stage)
        started_ns = clock.time_ns()
        try:
            traffic_result = generator.run(context)
        finally:
            finished_ns = clock.time_ns()
            workload_window = WorkloadWindow(started_ns, finished_ns)
            stages.append(StageRecord("traffic_run", "PASS" if traffic_result else "FAIL",
                                      "workload process returned" if traffic_result else "workload raised"))

        traffic_validation = execute(
            "traffic_validate", lambda: generator.validate(context, traffic_result)
        )
        traffic_verified = traffic_validation.passed
        if not traffic_verified:
            raise RuntimeError("traffic validation failed: " + "; ".join(traffic_validation.errors))

        pfs = execute("pfs_rekey", session.rekey)
        execute("capture_stop", session.stop_captures)
        full_capture = execute("full_pcap_validate", session.validate_captures)
        ipsec_verification = evaluate_ipsec(
            session.sas, session.xfrm, full_capture,
            run_id=plan.attempt_id, pfs=pfs,
        )
        ipsec_verified = ipsec_verification.status == "PASS"
        if not ipsec_verified:
            raise RuntimeError("complete IPsec evidence failed")

        execute("pcap_derive", lambda: derive_workload_esp(
            run_dir / "full-evidence.pcap", run_dir / "encrypted.pcap",
            workload_window, ("192.0.2.1", "192.0.2.2"),
        ))
        ml_summary = execute("ml_pcap_validate", lambda: inspect_ml_pcap(
            run_dir / "encrypted.pcap", workload_window,
            ("192.0.2.1", "192.0.2.2"),
        ))
        minimum = minimum_esp_packets(plan.traffic_class, generator.metadata()["parameters"])
        if ml_summary.packet_count < minimum:
            failure_class = "zero_or_insufficient_esp"
            raise RuntimeError(f"ML ESP packets {ml_summary.packet_count} below minimum {minimum}")
        capture_verified = True
        execute("artifacts", lambda: write_raw_attempt_artifacts(
            run_dir, session, generator.metadata(), log.getvalue()
        ))
    except BaseException as error:
        interrupted = isinstance(error, KeyboardInterrupt)
        primary_error = error
        failure_class = failure_class or classify_failure(current_stage, error)
        if not stages or stages[-1].name != current_stage or stages[-1].status == "PASS":
            stages.append(StageRecord(
                current_stage, "INTERRUPTED" if interrupted else "FAIL",
                str(error) or type(error).__name__,
            ))

    cleanup_started_at = utc_now()
    for name, action in (
        ("traffic_cleanup", lambda: generator.cleanup(context)),
        ("profile_cleanup", lambda: profile.cleanup(log)),
        ("session_cleanup", session.cleanup),
    ):
        try:
            action()
        except BaseException as error:
            cleanup_actions.append({"name": name, "status": "FAILED", "error": str(error)})
        else:
            cleanup_actions.append({"name": name, "status": "PASS", "error": None})
    cleanup_finished_at = utc_now()
    cleanup_state = (CleanupState.PASS if all(item["status"] == "PASS" for item in cleanup_actions)
                     else CleanupState.FAILED)
    stages.append(StageRecord("cleanup", cleanup_state.value,
                              "all cleanup actions attempted"))

    if not any(stage.name == "artifacts" and stage.status == "PASS" for stage in stages):
        current_stage = "artifacts"
        try:
            write_raw_attempt_artifacts(
                run_dir, session, generator.metadata(), log.getvalue()
            )
        except BaseException as error:
            stages.append(StageRecord("artifacts", "FAIL", str(error)))
            if primary_error is None:
                primary_error = error
                failure_class = "artifact_publication_failed"
        else:
            stages.append(StageRecord(
                "artifacts", "PASS", "available failure evidence preserved"
            ))

    run_finished_at = utc_now()
    current_stage = "metadata"
    try:
        stage_hook(current_stage)
        reproducibility = collect_reproducibility(
            context=context, generator=generator, matrix_fingerprint=matrix_fingerprint,
            run_started_at=run_started_at, run_finished_at=run_finished_at,
            window=workload_window,
        )
    except BaseException as error:
        reproducibility = unavailable_reproducibility(
            context=context, generator=generator, matrix_fingerprint=matrix_fingerprint,
            run_started_at=run_started_at, run_finished_at=run_finished_at,
            window=workload_window, error=error,
        )
        stages.append(StageRecord("metadata", "FAIL", str(error)))
        if primary_error is None:
            primary_error = error
            failure_class = "metadata_collection_failed"
    else:
        if reproducibility.collection_errors:
            stages.append(StageRecord(
                "metadata", "FAIL", "; ".join(reproducibility.collection_errors)
            ))
            if primary_error is None:
                primary_error = RuntimeError("; ".join(reproducibility.collection_errors))
                failure_class = "metadata_collection_failed"
        else:
            stages.append(StageRecord("metadata", "PASS", "complete"))

    state, training_ready, terminal_class = finalize_attempt_state(
        interrupted=interrupted, primary_error=primary_error,
        primary_failure_class=failure_class, cleanup_state=cleanup_state,
        validations=(traffic_verified, ipsec_verified, capture_verified),
    )
    failure_class = terminal_class
    payloads = build_terminal_payloads(
        plan=plan, state=state, training_ready=training_ready,
        cleanup_state=cleanup_state, stages=tuple(stages),
        cleanup_actions=tuple(cleanup_actions), generator=generator,
        scenario=scenario, session=session, traffic_result=traffic_result,
        traffic_validation=traffic_validation,
        ipsec_verification=ipsec_verification,
        workload_window=workload_window, ml_summary=ml_summary,
        reproducibility=reproducibility, traffic_verified=traffic_verified,
        ipsec_verified=ipsec_verified, capture_verified=capture_verified,
        failure_class=failure_class, primary_error=primary_error,
        network_metadata=network_metadata,
    )
    try:
        current_stage = "terminal_publish"
        stage_hook(current_stage)
        write_text_atomic(run_dir / "run.log", log.getvalue())
        validate_terminal_payloads(run_dir, payloads, require_pass_bundle=training_ready)
        staged = stage_terminal_json(run_dir, payloads)
        publish_terminal_json(staged)
    except BaseException as error:
        stages.append(StageRecord("terminal_publish", "FAIL", str(error)))
        state = RunState.FAILED
        training_ready = False
        failure_class = "artifact_publication_failed"
        primary_error = error
    return AttemptOutcome(
        run_id=plan.attempt_id, slot_id=plan.slot_id,
        attempt_number=plan.attempt_number, state=state,
        cleanup_state=cleanup_state, training_ready=training_ready,
        failure_class=failure_class,
        failure_message=None if primary_error is None else str(primary_error),
        artifact_path=plan.artifact_path, started_at=run_started_at,
        finished_at=run_finished_at, cleanup_started_at=cleanup_started_at,
        cleanup_finished_at=cleanup_finished_at,
        cleanup_actions=tuple(cleanup_actions),
        cleanup_error="; ".join(str(item["error"]) for item in cleanup_actions
                                if item["status"] == "FAILED") or None,
        traffic_verified=traffic_verified, ipsec_verified=ipsec_verified,
        capture_verified=capture_verified,
        esp_packets=0 if ml_summary is None else ml_summary.packet_count,
        capture_bytes=0 if ml_summary is None else ml_summary.capture_bytes,
        duration_seconds=0.0 if ml_summary is None else ml_summary.duration_seconds,
    )
```

`build_terminal_payloads()` must always return `verification.json`, `traffic.json`, and `environment.json`. It adds `ground_truth.json` only when scenario, configured/observed IPsec evidence, workload window, network metadata, and capture evidence exist. It builds `DatasetVerification` from all stage/check/cleanup records, uses `generator.metadata()` verbatim for `traffic.json`, serializes `ReproducibilityMetadata` for `environment.json`, and builds `DatasetGroundTruth` with actual Phase 1 `ConfiguredPolicy`, parsed gateway-A `ObservedState`, network metadata, capture counts, validation flags, and final cleanup state.

In a `finally` block it independently attempts generator cleanup, clean-profile cleanup, capture/log/daemon cleanup, and topology reset. Preserve each cleanup action result. Only after cleanup does it call `finalize_attempt_state()`, publish terminal JSON, and return `AttemptOutcome`.

- [ ] **Step 7: Implement complete durable artifacts**

```python
# ipsec_sentinel/dataset/artifacts.py
def write_raw_attempt_artifacts(
    run_dir: Path,
    session: SecureSession,
    traffic_metadata: dict[str, object],
    run_log: str,
) -> None:
    if session.scenario_yaml:
        write_text_atomic(run_dir / "scenario.yaml", session.scenario_yaml)
    for gateway, text in session.sas.items():
        write_text_atomic(run_dir / f"swanctl-{gateway}.txt", text)
    for gateway, text in session.xfrm.items():
        write_text_atomic(run_dir / f"xfrm-{gateway}.txt", text)
    write_json_atomic(run_dir / "traffic-partial.json", traffic_metadata)
    write_text_atomic(run_dir / "run.log", run_log)


REQUIRED_PASS_FILES = frozenset({
    "full-evidence.pcap", "encrypted.pcap",
    "cleartext-audit-gateway-a.pcap", "cleartext-audit-gateway-b.pcap",
    "ground_truth.json", "verification.json", "traffic.json",
    "environment.json", "scenario.yaml", "run.log",
    "swanctl-gateway-a.txt", "swanctl-gateway-b.txt",
    "xfrm-gateway-a.txt", "xfrm-gateway-b.txt", "pfs-rekey.log",
})


def assert_pass_bundle(run_dir: Path) -> None:
    present = {path.name for path in run_dir.iterdir()}
    missing = REQUIRED_PASS_FILES - present
    if missing:
        raise RuntimeError(f"dataset artifact publication incomplete: {sorted(missing)}")
    truth = json.loads((run_dir / "ground_truth.json").read_text(encoding="utf-8"))
    if truth["status"] != "PASS" or truth["training_ready"] is not True:
        raise RuntimeError("PASS bundle has non-training-ready ground truth")


@dataclass(frozen=True)
class StagedTerminalJson:
    run_dir: Path
    temporary_paths: dict[str, Path]


def stage_terminal_json(
    run_dir: Path, payloads: dict[str, dict[str, object]],
) -> StagedTerminalJson:
    common = {"verification.json", "traffic.json", "environment.json"}
    allowed = common | {"ground_truth.json"}
    if not common.issubset(payloads) or not set(payloads).issubset(allowed):
        raise ValueError(f"terminal JSON set mismatch: {sorted(set(payloads) ^ allowed)}")
    temporary_paths: dict[str, Path] = {}
    for name, payload in payloads.items():
        path = run_dir / f".{name}.{uuid4().hex}.staged"
        with path.open("w", encoding="utf-8") as output:
            json.dump(payload, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        temporary_paths[name] = path
    return StagedTerminalJson(run_dir, temporary_paths)


def publish_terminal_json(staged: StagedTerminalJson) -> None:
    for name, temporary in staged.temporary_paths.items():
        temporary.replace(staged.run_dir / name)


def build_terminal_payloads(
    *, plan: AttemptPlan, state: RunState, training_ready: bool,
    cleanup_state: CleanupState, stages: tuple[StageRecord, ...],
    cleanup_actions: tuple[dict[str, object], ...], generator: TrafficGenerator,
    scenario: Scenario | None, session: SecureSession,
    traffic_result: TrafficRunResult | None,
    traffic_validation: TrafficValidation | None,
    ipsec_verification: Verification | None,
    workload_window: WorkloadWindow | None, ml_summary: PcapSummary | None,
    reproducibility: ReproducibilityMetadata,
    network_metadata: dict[str, object] | None,
    traffic_verified: bool, ipsec_verified: bool, capture_verified: bool,
    failure_class: str | None, primary_error: BaseException | None,
) -> dict[str, dict[str, object]]:
    checks = list(ipsec_verification.checks) if ipsec_verification is not None else []
    traffic_errors = () if traffic_validation is None else traffic_validation.errors
    checks.extend((
        Check(f"traffic.{plan.traffic_class}.verified", traffic_verified,
              traffic_errors or (f"verified={traffic_verified}",)),
        Check("capture.ml_workload_esp", capture_verified,
              (f"packets={0 if ml_summary is None else ml_summary.packet_count}",)),
        Check("cleanup.complete", cleanup_state is CleanupState.PASS,
              tuple(f"{item['name']}={item['status']}" for item in cleanup_actions)),
        Check("metadata.complete", not reproducibility.collection_errors,
              reproducibility.collection_errors or ("all required fields recorded",)),
    ))
    verification = DatasetVerification(
        VERIFICATION_SCHEMA_VERSION, plan.attempt_id, state,
        stages, tuple(checks), cleanup_actions,
    )
    traffic_payload = {
        "schema_version": TRAFFIC_SCHEMA_VERSION,
        **generator.metadata(),
        "validation": None if traffic_validation is None else asdict(traffic_validation),
    }
    environment_payload = asdict(reproducibility)
    payloads: dict[str, dict[str, object]] = {
        "verification.json": verification.to_dict(),
        "traffic.json": traffic_payload,
        "environment.json": environment_payload,
    }
    full = session.capture_evidence
    if (scenario is not None and workload_window is not None and ml_summary is not None
            and network_metadata is not None and full is not None and session.sas):
        sa = parse_sa(session.sas["gateway-a"])
        metadata = generator.metadata()
        truth = DatasetGroundTruth(
            schema_version=DATASET_SCHEMA_VERSION,
            run_id=plan.attempt_id, slot_id=plan.slot_id,
            attempt_number=plan.attempt_number, status=state,
            training_ready=training_ready,
            traffic=DatasetTrafficEvidence(
                traffic_class=plan.traffic_class, known_training_class=True,
                generator=str(metadata["generator"]),
                generator_version=generator.version, seed=plan.seed,
                parameters=dict(metadata["parameters"]),
                result={} if traffic_result is None else dict(traffic_result.metrics),
            ),
            scenario_id=scenario.id,
            scenario_schema_version=SCENARIO_SCHEMA_VERSION,
            configured=ConfiguredPolicy(
                scenario.ipsec.ike_version, scenario.ipsec.mode,
                scenario.ipsec.ike_proposal, scenario.ipsec.esp_proposal,
                scenario.ipsec.pfs, scenario.ipsec.ip_version,
                scenario.ipsec.local_subnet, scenario.ipsec.remote_subnet,
                scenario.ipsec.transit_subnet,
            ),
            observed=ObservedState(
                2, sa.ike_proposal, f"{sa.esp_proposal}/NO_EXT_SEQ", session.pfs,
            ),
            network=network_metadata,
            capture=DatasetCaptureEvidence(
                "full-evidence.pcap", "encrypted.pcap",
                workload_window.started_unix_ns, workload_window.finished_unix_ns,
                full.packet_count, full.ike_packets, full.esp_packets,
                ml_summary.packet_count, ml_summary.capture_bytes,
                ml_summary.duration_seconds, PCAP_DERIVATION_VERSION,
            ),
            validation=DatasetValidation(
                traffic_verified, ipsec_verified, capture_verified,
                cleanup_state is CleanupState.PASS,
            ),
            cleanup_status=cleanup_state, reproducibility=reproducibility,
        )
        payloads["ground_truth.json"] = truth.to_dict()
    return payloads
```

Call `write_raw_attempt_artifacts()` again after cleanup when the normal `artifacts` stage was not reached, so failed/incomplete attempts retain all evidence available in memory. Stage terminal JSON in the run directory with unique hidden names. `validate_terminal_payloads()` validates the in-memory payloads plus the already-durable raw files before publication; for a proposed `PASS`, it applies the same checks as offline `assert_pass_bundle()` without requiring the not-yet-published terminal JSON files. After cleanup and final-state computation, write the final payloads to staged files, `fsync()` each, and `replace()` the public JSON paths. Delete `traffic-partial.json` only after final `traffic.json` is durable. Failed/incomplete attempts publish every available raw artifact but never satisfy `assert_pass_bundle()`.

Wrap terminal staging/publication in an `artifact_publication_failed` handler. If it fails, return a `FAILED`, non-training-ready `AttemptOutcome` so the manifest leaves an exact failure record; any already published JSON remains diagnostic and offline validation rejects the incomplete bundle.

- [ ] **Step 8: Add runner tests with fake lifecycle components**

Use dependency injection for `session_factory`, `generator_factory`, `profile_factory`, and clock. Fakes record calls but production evidence evaluation remains exercised with Phase 1 fixture text. Assert:

```python
self.assertLess(events.index("capture_start"), events.index("initiate"))
self.assertLess(events.index("traffic_run"), events.index("pfs_rekey"))
self.assertLess(events.index("traffic_window_end"), events.index("pfs_rekey"))
self.assertEqual(events[-4:], ["traffic_cleanup", "profile_cleanup",
                               "session_cleanup", "terminal_publish"])
```

Also inject failures at every dataset stage and assert later non-cleanup stages do not run, every cleanup does run, failure artifacts remain, and returned state/class match the stage.

- [ ] **Step 9: Run focused and full tests**

```bash
python3 -m unittest tests.test_evidence tests.test_dataset_runner -v
python3 -m unittest discover -s tests -v
```

Expected: runner ordering, failure, interruption, artifact, metadata, and cleanup semantics pass; all prior tests remain green.

- [ ] **Step 10: Commit one-attempt dataset execution**

```bash
git add ipsec_sentinel/evidence.py ipsec_sentinel/dataset/network.py ipsec_sentinel/dataset/artifacts.py ipsec_sentinel/dataset/runner.py tests/test_evidence.py tests/test_dataset_runner.py
git commit -m "feat: execute validated dataset attempts"
```

### Task 10: Manifest-driven Matrix Generation, Retry, Resume, and Summary

**Files:**
- Create: `ipsec_sentinel/dataset/summary.py`
- Modify: `ipsec_sentinel/dataset/runner.py`
- Test: `tests/test_dataset_summary.py`
- Extend: `tests/test_dataset_runner.py`

**Interfaces:**
- Consumes: `DatasetConfig`, matrix APIs, `Manifest`, and `run_dataset_attempt()`.
- Produces: `generate_dataset(config_path, dataset_parent, resume=False, attempt_runner=run_dataset_attempt) -> DatasetSummary`, `DatasetSummary`, `build_summary(manifest)`, and `write_summary()`.

- [ ] **Step 1: Write failing resume/retry orchestration tests**

```python
# additions to tests/test_dataset_runner.py
def test_resume_skips_pass_and_retries_failed_once(self) -> None:
    outcomes = {
        "run_000001": [failed_outcome("traffic_generator_failed"), passing_outcome()],
        "run_000002": [passing_outcome()],
    }
    calls: list[str] = []
    summary = generate_dataset(
        self.matrix_path(runs=2, retry_failed=1), self.root,
        resume=False, attempt_runner=fake_runner(outcomes, calls),
    )
    self.assertEqual(calls, ["run_000001", "run_000001-attempt02", "run_000002"])
    self.assertEqual(summary.successful_runs, 2)
    calls.clear()
    resumed = generate_dataset(self.matrix_path(runs=2, retry_failed=1), self.root,
                               resume=True, attempt_runner=fake_runner(outcomes, calls))
    self.assertEqual(calls, [])
    self.assertEqual(resumed.successful_runs, 2)


def test_resume_rejects_changed_fingerprint_before_attempt_runner(self) -> None:
    generate_dataset(self.matrix_path(seed=1), self.root, attempt_runner=always_pass)
    with self.assertRaisesRegex(ManifestMismatch, "fingerprint"):
        generate_dataset(self.matrix_path(seed=2), self.root, resume=True,
                         attempt_runner=lambda plan, root, fingerprint: self.fail("must not run"))
```

Add cases for exhausted retry, stale `RUNNING` recovery, no-resume refusal on an initialized directory, continuing later slots after a terminal failure, and resume refusing to retry a `configuration_failed` or `preflight_failed` attempt even when nominal retry budget remains.

- [ ] **Step 2: Write failing summary aggregation tests**

```python
# tests/test_dataset_summary.py
class DatasetSummaryTest(unittest.TestCase):
    def test_counts_only_training_ready_attempts_by_class(self) -> None:
        manifest = manifest_with_attempts(
            passing=("icmp", "web", "video"),
            failed=("video",),
            incomplete=("icmp",),
        )
        summary = build_summary(manifest)
        self.assertEqual(summary.successful_runs, 3)
        self.assertEqual(summary.failed_runs, 1)
        self.assertEqual(summary.incomplete_runs, 1)
        self.assertEqual(summary.class_distribution,
                         {"icmp": 1, "video": 1, "web": 1})
        self.assertNotIn("failed", summary.class_distribution)

    def test_json_summary_is_atomic_and_machine_readable(self) -> None:
        write_summary(self.root / "dataset_summary.json", self.summary)
        payload = json.loads((self.root / "dataset_summary.json").read_text())
        self.assertEqual(payload["training_ready_runs"], 3)
        self.assertEqual(list(self.root.glob("*.tmp")), [])
```

- [ ] **Step 3: Run focused tests and verify missing orchestration fails**

```bash
python3 -m unittest tests.test_dataset_runner tests.test_dataset_summary -v
```

Expected: missing `generate_dataset`, `DatasetSummary`, and summary writer failures.

- [ ] **Step 4: Implement serial scheduling and bounded retry**

```python
AttemptRunner = Callable[[AttemptPlan, Path, str], AttemptOutcome]
RETRIABLE_FAILURES = frozenset({
    "topology_failed", "tunnel_establishment_failed", "ipsec_evidence_failed",
    "traffic_prepare_failed", "traffic_generator_failed",
    "traffic_validation_failed", "capture_failed", "zero_or_insufficient_esp",
    "pcap_derivation_failed", "artifact_publication_failed", "cleanup_failed",
    "interrupted", "metadata_collection_failed", "unexpected_error",
})


def is_retriable(failure_class: str | None) -> bool:
    return failure_class in RETRIABLE_FAILURES


def generate_dataset(
    config_path: Path,
    dataset_parent: Path = Path("dataset"),
    *,
    resume: bool = False,
    attempt_runner: AttemptRunner = run_dataset_attempt,
) -> DatasetSummary:
    register_builtin_generators()
    config = DatasetConfig.load(config_path)
    versions = generator_versions(config.traffic_classes)
    fingerprint = matrix_fingerprint(config, versions)
    dataset_root = dataset_parent / config.name
    manifest_path = dataset_root / "manifest.sqlite3"
    if manifest_path.is_file():
        manifest = Manifest(manifest_path)
        if not resume:
            raise FileExistsError(f"dataset already initialized: {dataset_root}")
        manifest.assert_compatible(fingerprint)
        manifest.recover_running(utc_now())
    else:
        if dataset_root.exists() and any(dataset_root.iterdir()):
            raise FileExistsError(f"uninitialized nonempty dataset directory: {dataset_root}")
        dataset_root.mkdir(parents=True, exist_ok=True)
        manifest = Manifest(manifest_path)
        write_text_atomic(dataset_root / "matrix.yaml", config_path.read_text(encoding="utf-8"))
        manifest.initialize(config, fingerprint, str(config_path), versions)

    for slot in manifest.slots_in_order():
        while True:
            latest = manifest.latest_attempt(slot.slot_id)
            if (latest is not None and latest.state in (RunState.FAILED, RunState.INCOMPLETE)
                    and not is_retriable(latest.failure_class)):
                break
            plan = manifest.next_attempt(slot.slot_id, config.retry_failed)
            if plan is None:
                break
            manifest.mark_running(plan.attempt_id, utc_now())
            outcome = attempt_runner(plan, dataset_root, fingerprint)
            manifest.finish_attempt_from_outcome(outcome, utc_now())
            write_summary(dataset_root / "dataset_summary.json", build_summary(manifest))
            if outcome.state is RunState.INCOMPLETE and outcome.failure_class == "interrupted":
                raise KeyboardInterrupt()
            if outcome.state is RunState.PASS:
                break
            if not is_retriable(outcome.failure_class):
                break
    summary = build_summary(manifest)
    write_summary(dataset_root / "dataset_summary.json", summary)
    return summary
```

`is_retriable()` returns false for `configuration_failed` and `preflight_failed` and true only for the explicit runtime failure classes in the spec. `run_dataset_attempt()` converts an interruption into an `INCOMPLETE` outcome after cleanup; generation persists it, regenerates the summary, then raises `KeyboardInterrupt` so the CLI exits 130.

- [ ] **Step 5: Implement manifest-derived summaries**

```python
# ipsec_sentinel/dataset/summary.py
@dataclass(frozen=True)
class DatasetSummary:
    dataset_name: str
    schema_version: str
    matrix_fingerprint: str
    planned_runs: int
    successful_runs: int
    failed_runs: int
    pending_runs: int
    incomplete_runs: int
    attempts_by_state: dict[str, int]
    training_ready_runs: int
    class_distribution: dict[str, int]
    failures_by_class: dict[str, int]
    total_esp_packets: int
    total_capture_bytes: int
    total_duration_seconds: float
    created_at: str
    updated_at: str
```

Aggregate from SQL rows whose attempts are both `PASS` and `training_ready=1`. Render class keys in lexical order. Use `write_json_atomic()` for JSON. The CLI renderer prints dataset name, logical state totals, class distribution, ESP count, bytes, duration, and failure classes.

- [ ] **Step 6: Run focused and full tests**

```bash
python3 -m unittest tests.test_dataset_runner tests.test_dataset_summary -v
python3 -m unittest discover -s tests -v
```

Expected: retry/resume/fingerprint/crash/summary tests and the full suite pass.

- [ ] **Step 7: Commit resumable generation**

```bash
git add ipsec_sentinel/dataset/runner.py ipsec_sentinel/dataset/summary.py tests/test_dataset_runner.py tests/test_dataset_summary.py
git commit -m "feat: add resumable dataset generation"
```

### Task 11: CLI and Offline Dataset Validation

**Files:**
- Create: `ipsec_sentinel/dataset/validation.py`
- Create: `ipsec_sentinel/dataset/cli.py`
- Create: `ipsec_sentinel/dataset/__main__.py`
- Test: `tests/test_dataset_cli.py`
- Test: `tests/test_dataset_validation.py`

**Interfaces:**
- Consumes: traffic registry, `generate_dataset()`, `run_dataset_attempt()`, manifest, summary, JSON models, and PCAP inspection.
- Produces: `validate_dataset(dataset_root) -> DatasetValidationReport`, `build_parser()`, and `main(argv=None) -> int`.

- [ ] **Step 1: Write failing CLI parser tests**

```python
# tests/test_dataset_cli.py
from contextlib import redirect_stdout
from io import StringIO
import unittest

from ipsec_sentinel.dataset.cli import main


class DatasetCliTest(unittest.TestCase):
    def test_list_traffic_prints_exact_supported_classes(self) -> None:
        output = StringIO()
        with redirect_stdout(output):
            code = main(["list-traffic"])
        self.assertEqual(code, 0)
        self.assertEqual(output.getvalue().splitlines(), ["icmp", "video", "web"])

    def test_generate_passes_resume_to_orchestrator(self) -> None:
        observed: list[tuple[str, bool]] = []
        code = main(["generate", "configs/smoke-v1.yaml", "--resume"],
                    generate=lambda path, resume: observed.append((str(path), resume)) or passing_summary())
        self.assertEqual(code, 0)
        self.assertEqual(observed, [("configs/smoke-v1.yaml", True)])
```

Add parser tests for `run --traffic video --scenario secure-baseline`, validation return code, invalid traffic choices, and interrupted return code 130.

- [ ] **Step 2: Write failing offline validation tests**

```python
# tests/test_dataset_validation.py
class OfflineValidationTest(unittest.TestCase):
    def test_validates_every_manifest_pass_without_scanning_labels_from_packets(self) -> None:
        root = build_dataset_fixture(training_ready=("run_000001", "run_000002"))
        report = validate_dataset(root)
        self.assertTrue(report.passed)
        self.assertEqual(report.valid_runs, 2)

    def test_rejects_missing_ml_pcap_and_ground_truth_manifest_disagreement(self) -> None:
        root = build_dataset_fixture(training_ready=("run_000001",))
        (root / "runs/run_000001/encrypted.pcap").unlink()
        report = validate_dataset(root)
        self.assertFalse(report.passed)
        self.assertIn("encrypted.pcap", " ".join(report.errors))

    def test_failed_attempt_is_retained_but_not_training_ready(self) -> None:
        root = build_dataset_fixture(training_ready=(), failed=("run_000001",))
        report = validate_dataset(root)
        self.assertTrue(report.manifest_readable)
        self.assertEqual(report.valid_runs, 0)
        self.assertEqual(report.failed_runs, 1)
```

- [ ] **Step 3: Run tests and verify missing CLI/validation APIs fail**

```bash
python3 -m unittest tests.test_dataset_cli tests.test_dataset_validation -v
```

Expected: import errors for the CLI and validation modules.

- [ ] **Step 4: Implement offline validation from manifest truth**

```python
# ipsec_sentinel/dataset/validation.py
@dataclass(frozen=True)
class DatasetValidationReport:
    passed: bool
    manifest_readable: bool
    valid_runs: int
    failed_runs: int
    incomplete_runs: int
    errors: tuple[str, ...]


def validate_dataset(dataset_root: Path) -> DatasetValidationReport:
    manifest = Manifest.open_existing(dataset_root / "manifest.sqlite3")
    errors: list[str] = []
    valid_runs = 0
    for attempt in manifest.training_ready_attempts():
        run_dir = dataset_root / attempt.artifact_path
        try:
            truth = json.loads((run_dir / "ground_truth.json").read_text(encoding="utf-8"))
            verification = json.loads((run_dir / "verification.json").read_text(encoding="utf-8"))
            traffic = json.loads((run_dir / "traffic.json").read_text(encoding="utf-8"))
            environment = json.loads((run_dir / "environment.json").read_text(encoding="utf-8"))
            _validate_json_agreement(attempt, truth, verification, traffic, environment)
            window = WorkloadWindow(truth["capture"]["workload_started_unix_ns"],
                                    truth["capture"]["workload_finished_unix_ns"])
            summary = inspect_ml_pcap(run_dir / "encrypted.pcap", window,
                                      ("192.0.2.1", "192.0.2.2"))
            if summary.packet_count != truth["capture"]["ml_esp_packets"]:
                raise ValueError("manifest/ground-truth PCAP count mismatch")
            valid_runs += 1
        except (OSError, KeyError, ValueError, json.JSONDecodeError) as error:
            errors.append(f"{attempt.attempt_id}: {error}")
    return DatasetValidationReport(
        passed=not errors, manifest_readable=True, valid_runs=valid_runs,
        failed_runs=manifest.count_attempts(RunState.FAILED),
        incomplete_runs=manifest.count_attempts(RunState.INCOMPLETE),
        errors=tuple(errors),
    )
```

Validation treats manifest labels and generator metadata as ground truth; it never infers a class from PCAP content.

- [ ] **Step 5: Implement the four CLI commands**

```python
# ipsec_sentinel/dataset/cli.py
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python3 -m ipsec_sentinel.dataset")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("list-traffic")
    run = subparsers.add_parser("run")
    run.add_argument("--traffic", required=True, choices=("icmp", "web", "video"))
    run.add_argument("--scenario", default="secure-baseline", choices=("secure-baseline",))
    run.add_argument("--seed", type=int)
    run.add_argument("--output", type=Path, default=Path("dataset/ad-hoc"))
    generate = subparsers.add_parser("generate")
    generate.add_argument("config", type=Path)
    generate.add_argument("--resume", action="store_true")
    validate = subparsers.add_parser("validate")
    validate.add_argument("dataset_root", type=Path)
    return parser
```

`run` creates a one-slot config and uses the same manifest/attempt path as matrix generation. If `--seed` is absent, generate one with `secrets.randbits(63)` and record it. `generate` returns zero only when every logical slot has a training-ready pass. `validate` returns zero only for a passing report. Catch `KeyboardInterrupt` and return 130.

- [ ] **Step 6: Run focused, help-smoke, and full tests**

```bash
python3 -m unittest tests.test_dataset_cli tests.test_dataset_validation -v
python3 -m ipsec_sentinel.dataset --help
python3 -m ipsec_sentinel.dataset list-traffic
python3 -m unittest discover -s tests -v
```

Expected: help exits zero, list prints `icmp`, `video`, `web`, and all tests pass.

- [ ] **Step 7: Commit CLI and offline validation**

```bash
git add ipsec_sentinel/dataset/cli.py ipsec_sentinel/dataset/__main__.py ipsec_sentinel/dataset/validation.py tests/test_dataset_cli.py tests/test_dataset_validation.py
git commit -m "feat: add dataset CLI and validation"
```

### Task 12: Privileged ICMP, Web, Video, Retry, and Cleanup Integration

**Files:**
- Create: `tests/test_dataset_integration.py`
- Modify if required by proven failures: dataset/session/traffic modules owned by Tasks 4–11

**Interfaces:**
- Consumes: public dataset CLI/orchestrator and real WSL/Linux Phase 1 infrastructure.
- Produces: root-gated proof for all three traffic classes, independent sessions, resume, retry, artifacts, PCAP roles, and cleanup.

- [ ] **Step 1: Add root-gated one-run integration tests before changing production code**

```python
# tests/test_dataset_integration.py
@unittest.skipUnless(
    os.environ.get("IPSEC_SENTINEL_DATASET_INTEGRATION") == "1",
    "set IPSEC_SENTINEL_DATASET_INTEGRATION=1 and run as root",
)
class DatasetIntegrationTest(unittest.TestCase):
    def run_class(self, traffic_class: str, seed: int) -> tuple[Path, dict[str, object]]:
        dataset_name = f"integration-{traffic_class}-{seed}"
        config = write_one_slot_config(self.root, dataset_name, traffic_class, seed)
        summary = generate_dataset(config, self.root / "dataset")
        self.assertEqual(summary.successful_runs, 1)
        run_dir = next((self.root / "dataset" / dataset_name / "runs").iterdir())
        truth = json.loads((run_dir / "ground_truth.json").read_text())
        self.assertEqual(truth["traffic"]["class"], traffic_class)
        self.assertTrue(truth["training_ready"])
        self.assertTrue((run_dir / "full-evidence.pcap").is_file())
        self.assertTrue((run_dir / "encrypted.pcap").is_file())
        self.assertGreater(truth["capture"]["ml_esp_packets"], 0)
        assert_no_lab_resources(run_dir.name)
        return run_dir, truth

    def test_real_icmp_dataset_run(self) -> None:
        self.run_class("icmp", 1001)

    def test_real_web_dataset_run(self) -> None:
        self.run_class("web", 2001)

    def test_real_video_dataset_run(self) -> None:
        self.run_class("video", 3001)
```

Use this real config helper and cleanup assertion:

```python
def write_one_slot_config(
    root: Path, dataset_name: str, traffic_class: str, seed: int,
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
""", encoding="utf-8")
    return path


def assert_no_lab_resources(run_id: str) -> None:
    namespaces = subprocess.run(
        ["ip", "netns", "list"], text=True, capture_output=True,
        check=True, timeout=5,
    ).stdout
    for name in ("ips-client", "ips-gwa", "ips-gwb", "ips-server"):
        if name in namespaces:
            raise AssertionError(f"namespace leaked: {name}")
    for interface in ("veth-c", "veth-a-lan", "veth-a-wan",
                      "veth-b-wan", "veth-b-lan", "veth-s"):
        result = subprocess.run(["ip", "link", "show", interface],
                                text=True, capture_output=True, timeout=5)
        if result.returncode == 0:
            raise AssertionError(f"root veth leaked: {interface}")
    if (Path("/run/ipsec-sentinel") / run_id).exists():
        raise AssertionError(f"runtime directory leaked: {run_id}")
```

- [ ] **Step 2: Run each integration test separately and stop at its failing layer**

```bash
sudo env IPSEC_SENTINEL_DATASET_INTEGRATION=1 \
  python3 -m unittest tests.test_dataset_integration.DatasetIntegrationTest.test_real_icmp_dataset_run -v
sudo env IPSEC_SENTINEL_DATASET_INTEGRATION=1 \
  python3 -m unittest tests.test_dataset_integration.DatasetIntegrationTest.test_real_web_dataset_run -v
sudo env IPSEC_SENTINEL_DATASET_INTEGRATION=1 \
  python3 -m unittest tests.test_dataset_integration.DatasetIntegrationTest.test_real_video_dataset_run -v
```

Expected before fixes: each first run may reveal a concrete integration mismatch. For every mismatch, add or tighten the smallest unit regression test before changing production code, rerun that unit test red/green, then rerun only the failing integration.

- [ ] **Step 3: Add integration assertions for capture separation**

```python
def assert_capture_roles(self, run_dir: Path, truth: dict[str, object]) -> None:
    full = subprocess.run(["tcpdump", "-nn", "-r", str(run_dir / "full-evidence.pcap")],
                          text=True, capture_output=True, check=True).stdout
    ml = subprocess.run(["tcpdump", "-nn", "-r", str(run_dir / "encrypted.pcap")],
                        text=True, capture_output=True, check=True).stdout
    self.assertIn("isakmp", full)
    self.assertIn("ESP", full)
    self.assertIn("ESP", ml)
    self.assertNotIn("isakmp", ml)
    self.assertNotIn(".4500", ml)
    self.assertEqual(truth["capture"]["ml_input_file"], "encrypted.pcap")
```

Call it from every traffic-class test. Independently inspect `pfs-rekey.log` and before/after SA files to ensure rekey evidence remains in the run but outside the ML PCAP window.

- [ ] **Step 4: Add retry/resume and independent-session integration**

```python
def test_retry_creates_a_new_tunnel_session_and_resume_skips_passes(self) -> None:
    dataset_name = "integration-retry-4001"
    config = write_one_slot_config(self.root, dataset_name, "icmp", 4001, retry_failed=1)
    calls = 0

    def runner(plan: AttemptPlan, root: Path, fingerprint: str) -> AttemptOutcome:
        nonlocal calls
        calls += 1
        def stage_hook(stage: str) -> None:
            if calls == 1 and stage == "traffic_run":
                raise RuntimeError("injected failure after tunnel establishment")
        return run_dataset_attempt(plan, root, fingerprint, stage_hook=stage_hook)

    first = generate_dataset(config, self.root / "dataset", attempt_runner=runner)
    self.assertEqual(first.successful_runs, 1)
    dataset_root = self.root / "dataset" / dataset_name
    attempts = Manifest(dataset_root / "manifest.sqlite3").attempts()
    self.assertEqual([item.state for item in attempts], [RunState.FAILED, RunState.PASS])
    self.assertNotEqual(attempts[0].seed, attempts[1].seed)
    before = tuple(path.name for path in (dataset_root / "runs").iterdir())
    resumed = generate_dataset(config, self.root / "dataset", resume=True)
    self.assertEqual(tuple(path.name for path in (dataset_root / "runs").iterdir()), before)
```

The injected failure must occur after an actual tunnel establishment and must still execute cleanup. Compare retained `swanctl` SPIs or IKE evidence across attempt directories to show independent sessions rather than copied PCAPs.

- [ ] **Step 5: Run the complete privileged regression set**

```bash
sudo env IPSEC_SENTINEL_INTEGRATION=1 \
  python3 -m unittest tests.test_secure_baseline_integration -v
sudo env IPSEC_SENTINEL_DATASET_INTEGRATION=1 \
  python3 -m unittest tests.test_dataset_integration -v
```

Expected: Phase 1 and all dataset integrations pass with clean teardown.

- [ ] **Step 6: Commit integration-proven fixes and tests**

```bash
git add tests/test_dataset_integration.py ipsec_sentinel
git commit -m "test: prove dataset traffic integrations"
```

Before committing, verify `git diff --name-only` contains only files changed to resolve an observed integration failure plus the integration test. Do not fold unrelated refactors into this commit.

### Task 13: Smoke Dataset, Documentation, and Final Verification

**Files:**
- Modify: `.gitignore`
- Modify: `ipsec_sentinel/__init__.py`
- Modify: `README.md`
- Retain locally, ignored: `dataset/cipherlens-smoke-v1/`
- Test: all test modules

**Interfaces:**
- Consumes: complete public dataset CLI.
- Produces: documented operator workflow, nine-run smoke evidence, validated summary, and final Phase 1/Phase 2 regression evidence.

- [ ] **Step 1: Ignore generated dataset output and update package description**

```gitignore
dataset/
```

Update `ipsec_sentinel/__init__.py` to:

```python
"""IPsec Sentinel testbed, evidence verifier, and dataset factory."""
```

- [ ] **Step 2: Write the README Dataset Factory section**

Document these exact commands:

```bash
python3 -m ipsec_sentinel.dataset list-traffic
sudo python3 -m ipsec_sentinel.dataset run \
  --traffic video --scenario secure-baseline
sudo python3 -m ipsec_sentinel.dataset generate configs/smoke-v1.yaml
sudo python3 -m ipsec_sentinel.dataset generate configs/smoke-v1.yaml --resume
python3 -m ipsec_sentinel.dataset validate dataset/cipherlens-smoke-v1
```

Explain the topology, three generators, seeded variability, `full-evidence.pcap` versus ML-input `encrypted.pcap`, exact workload-window derivation, configured versus observed evidence, SQLite states, cleanup status, retry/resume, artifact tree, validation criteria, unattended execution, current limitations, and the five-method generator extension contract. State explicitly that Phase 2 performs no feature extraction or ML training.

Include this resumable unattended pattern, with the operator replacing the matrix path only after creating a reviewed larger matrix:

```bash
sudo nohup python3 -m ipsec_sentinel.dataset generate configs/smoke-v1.yaml --resume \
  > dataset-generation.log 2>&1 &
```

Document that process supervision by systemd or another host-native supervisor is preferred for long collections, and that a force-kill may leave a `RUNNING` attempt which `--resume` will convert to `INCOMPLETE` before retrying.

- [ ] **Step 3: Run all ordinary tests before generating data**

```bash
python3 -m unittest discover -s tests -v
git diff --check
```

Expected: every ordinary test passes; only privileged tests are skipped by guards; no whitespace errors.

- [ ] **Step 4: Run the nine-slot smoke matrix once**

```bash
sudo python3 -m ipsec_sentinel.dataset generate configs/smoke-v1.yaml
```

Expected CLI summary:

```text
Dataset: cipherlens-smoke-v1
Planned runs: 9
Successful runs: 9
Failed runs: 0
Training-ready runs: 9
Class distribution:
  icmp: 3
  video: 3
  web: 3
```

If a run fails, preserve it, diagnose the precise layer, add a failing regression test, fix it, and use `--resume`; do not delete or relabel the failed attempt.

- [ ] **Step 5: Prove resume is a no-op and validate offline**

```bash
sudo python3 -m ipsec_sentinel.dataset generate configs/smoke-v1.yaml --resume
python3 -m ipsec_sentinel.dataset validate dataset/cipherlens-smoke-v1
```

Expected: resume creates no new attempt directories; validation reports nine training-ready runs and zero artifact errors.

- [ ] **Step 6: Inspect smoke evidence independently**

```bash
python3 - <<'PY'
from pathlib import Path
import json
import sqlite3

root = Path("dataset/cipherlens-smoke-v1")
summary = json.loads((root / "dataset_summary.json").read_text())
assert summary["training_ready_runs"] == 9, summary
assert summary["class_distribution"] == {"icmp": 3, "video": 3, "web": 3}, summary
with sqlite3.connect(root / "manifest.sqlite3") as db:
    passing_paths = [row[0] for row in db.execute(
        "SELECT artifact_path FROM attempts "
        "WHERE state='PASS' AND cleanup_status='PASS' AND training_ready=1"
        " ORDER BY attempt_id"
    ).fetchall()]
    retained_failures = db.execute(
        "SELECT attempt_id, state, failure_class FROM attempts "
        "WHERE state IN ('FAILED','INCOMPLETE') ORDER BY attempt_id"
    ).fetchall()
assert len(passing_paths) == 9, passing_paths
for relative in passing_paths:
    run_dir = root / relative
    truth = json.loads((run_dir / "ground_truth.json").read_text())
    assert truth["status"] == "PASS" and truth["training_ready"] is True
    assert (run_dir / "full-evidence.pcap").stat().st_size > 24
    assert (run_dir / "encrypted.pcap").stat().st_size > 24
print(json.dumps(summary, indent=2, sort_keys=True))
print("retained failed/incomplete attempts:", retained_failures)
PY
```

Also run `tcpdump -nn -r` on one attempt per class and confirm IKE appears in `full-evidence.pcap`, only ESP appears in `encrypted.pcap`, and every tcpdump log reports zero kernel drops.

- [ ] **Step 7: Run final Phase 1 and Phase 2 verification from a clean tree**

```bash
python3 -m unittest discover -s tests -v
sudo env IPSEC_SENTINEL_INTEGRATION=1 \
  python3 -m unittest tests.test_secure_baseline_integration -v
sudo env IPSEC_SENTINEL_DATASET_INTEGRATION=1 \
  python3 -m unittest tests.test_dataset_integration -v
python3 -m ipsec_sentinel.dataset validate dataset/cipherlens-smoke-v1
git diff --check
git status --short --branch
```

Expected: all unit and privileged tests pass, smoke validation passes, no whitespace errors, and only intended documentation/code/test changes remain before commit.

- [ ] **Step 8: Commit documentation and smoke configuration changes**

```bash
git add .gitignore README.md ipsec_sentinel/__init__.py
git commit -m "docs: document phase two dataset factory"
```

Do not add `dataset/` or PCAP files to Git. Retain the smoke directory locally for the final report.

- [ ] **Step 9: Request whole-branch review before integration choices**

Review the range:

```bash
git diff --check
git log --oneline a251bb2..HEAD
git diff --stat a251bb2..HEAD
```

The reviewer must specifically assess Phase 1 compatibility, PCAP leakage boundaries, manifest crash/retry semantics, cleanup fail-closed behavior, reproducibility completeness, traffic-label ground truth, and whether any Phase 3 feature/ML work leaked into scope.

- [ ] **Step 10: Prepare the Phase 2 completion report and stop**

Report the implemented modules and branch, exact one-run/smoke/resume/validate commands, all test commands/results, logical and attempt counts, class distribution, total ESP packets and capture bytes, retained smoke path, one redacted `ground_truth.json` example, one manifest-row example, observed retry/failure behavior, known limitations, the unattended generation command, and a recommended Phase 3 plan covering cleaning, encrypted-flow features, leakage-safe session splits, baseline classifiers, evaluation, and model export.

Do not execute any Phase 3 data preparation, feature extraction, split construction, model training, API, or UI work. Do not merge or rebase either stacked branch automatically.
