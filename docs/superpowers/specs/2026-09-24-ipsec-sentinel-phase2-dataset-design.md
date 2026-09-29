# IPsec Sentinel Phase 2: Reproducible Dataset Factory

**Date:** 2026-09-24  
**Status:** Approved design; implementation not started  
**Branch:** `feat/ipsec-sentinel-phase2-dataset`  
**Stacked base:** `feat/ipsec-sentinel-phase1` at `a251bb21693b6876844a4f2d002d045e9f0a29c0`

## 1. Purpose

Phase 2 adds an automated, reproducible factory for correctly labeled encrypted IPsec traffic. It establishes a fresh real tunnel for every independent session, intentionally generates one known workload, captures observable encrypted traffic on the gateway transit link, records configured and observed ground truth, rejects invalid runs, and supports bounded retries and crash-safe resume.

The smoke milestone proves this machinery with three traffic classes—`icmp`, `web`, and `video`—and three independent sessions per class under the Phase 1 `secure-baseline` IPsec scenario and a `clean` network profile. It produces nine planned runs, plus retry attempts only when required.

The generator determines the label. No label is inferred from packet contents or behavior.

## 2. Branch and Phase 1 Compatibility

Phase 1 PR #1 is open and has not been merged into `main`. Phase 2 therefore starts from the validated Phase 1 tip, not from stale `main`. The Phase 2 branch is intentionally stacked on `feat/ipsec-sentinel-phase1`.

The implementation must:

- preserve all Phase 1 commits unchanged;
- preserve the public `run_secure_baseline()` entry point and its observable behavior;
- preserve the existing `run_scenario.py secure-baseline` command;
- keep the Phase 1 topology, strongSwan isolation, XFRM checks, PFS rekey proof, capture checks, and cleanup guarantees;
- keep the existing Phase 1 artifact meaning, including its current `encrypted.pcap` name;
- run all Phase 1 unit and privileged integration tests as regression gates;
- avoid automatic merges.

Until PR #1 merges, an eventual Phase 2 PR must target `feat/ipsec-sentinel-phase1` as a stacked PR. After PR #1 merges, Phase 2 may be rebased or otherwise updated onto current `main`, and its PR base may be changed to `main`, but only as an explicit integration action. The implementation must never infer that stale `main` is a valid Phase 2 base.

## 3. Goals

Phase 2 must provide:

1. A common traffic-generator contract.
2. Seeded ICMP, web, and video generators.
3. A reusable secure-session lifecycle built from the Phase 1 components.
4. A full evidence capture and a separate ESP-only workload capture for future ML.
5. Class-specific workload validation.
6. Extended configured-versus-observed ground truth.
7. Reproducibility and environment metadata for every attempt.
8. Deterministic matrix expansion and stable logical run IDs.
9. A transactional SQLite manifest with explicit lifecycle states.
10. Bounded retry and resumable serial generation.
11. Machine-readable and human-readable dataset summaries.
12. A nine-run smoke dataset proving the complete path.

## 4. Non-goals

Phase 2 does not include:

- feature engineering or extraction;
- dataset cleaning or leakage-safe train/test splitting;
- ML training, model selection, or model export;
- XGBoost, Random Forest, neural networks, or PyTorch;
- classifier APIs, dashboards, frontends, Electron, React, or FastAPI;
- LLM behavior, security scoring, exploitation, cloud deployment, or report generation;
- NAT, NAT-T, IKEv1, IPv6, transport mode, or additional IPsec algorithms;
- VoIP, email, messaging, file-transfer, mixed, or unknown generators;
- parallel workers;
- network impairment beyond the `clean` profile;
- hundreds of development-session captures.

The design reserves clean extension points for these later phases without implementing them now.

## 5. Architecture

### 5.1 Reusable secure-session lifecycle

The current Phase 1 runner contains a validated but ICMP-specific lifecycle. Phase 2 will extract the smallest practical reusable lifecycle abstraction while retaining `run_secure_baseline()` as a compatibility wrapper.

The reusable lifecycle owns and coordinates existing components:

- `Topology` for namespaces, veths, routes, forwarding, `rp_filter`, and reset;
- `StrongSwanPair` for isolated daemons, VICI, configuration, SA inspection, and rekey;
- `CaptureSession` for tracked tcpdump processes and drop validation;
- the existing SA, XFRM, PFS, and cleartext evidence evaluators;
- atomic artifact writers and cleanup aggregation.

The lifecycle exposes explicit hook points for traffic preparation, workload execution, workload validation, traffic metadata, and traffic cleanup. Dataset orchestration uses those hooks. Phase 1 uses the same lifecycle through its current ICMP behavior and produces the same Phase 1 schema and artifact names.

The implementation must not create a second copy of tunnel setup or cleanup logic. It may preserve a small Phase 1-specific adapter where the Phase 1 stage names or output schema differ from dataset stages.

### 5.2 Proposed modules

```text
ipsec_sentinel/
  session.py                   reusable secure-session lifecycle
  dataset/
    __init__.py
    __main__.py
    cli.py
    config.py
    manifest.py
    matrix.py
    models.py
    runner.py
    summary.py
    validation.py
  traffic/
    __init__.py
    base.py
    icmp.py
    web.py
    video.py
    http_service.py

configs/
  smoke-v1.yaml
```

Exact file boundaries may be adjusted during planning to keep units focused, but responsibilities must remain separate: traffic generation must not own IPsec orchestration, manifest code must not inspect packets, and validation must not guess traffic labels.

### 5.3 CLI

The supported commands will be:

```bash
python3 -m ipsec_sentinel.dataset list-traffic
python3 -m ipsec_sentinel.dataset run --traffic video --scenario secure-baseline
python3 -m ipsec_sentinel.dataset generate configs/smoke-v1.yaml
python3 -m ipsec_sentinel.dataset generate configs/smoke-v1.yaml --resume
python3 -m ipsec_sentinel.dataset validate dataset/cipherlens-smoke-v1
```

Commands that create real network sessions require Linux root privileges. Listing, configuration parsing, matrix expansion, summary reading, and ordinary unit tests do not require root.

## 6. Traffic Generator Contract

Each generator implements an intentionally small shared interface equivalent to:

```python
class TrafficGenerator(Protocol):
    name: str
    version: str

    def prepare(self, context: TrafficContext) -> None: ...
    def run(self, context: TrafficContext) -> TrafficRunResult: ...
    def validate(
        self,
        context: TrafficContext,
        result: TrafficRunResult,
    ) -> TrafficValidation: ...
    def cleanup(self, context: TrafficContext) -> None: ...
    def metadata(self) -> dict[str, object]: ...
```

`TrafficContext` supplies the run directory, client and server namespaces and addresses, the run log, the deterministic random seed, and the selected network and IPsec scenario identifiers. The generator does not create or destroy the IPsec topology.

`prepare()` may start a tracked service but must not generate the measured client workload. `run()` performs exactly one measured workload session. `validate()` uses generator-owned facts such as ping results, client responses, server request receipts, byte counts, and timing. `cleanup()` must be idempotent and attempt to terminate all tracked processes. `metadata()` returns the fully resolved plan and realized results written to `traffic.json`.

Every service and client process is started by argument vector, not an interpolated shell command. Every process has a timeout, PID tracking, captured output, and bounded termination.

## 7. Seeded Workloads

### 7.1 Reproducibility rule

Every attempt receives an integer random seed derived deterministically from:

- the dataset-level base seed;
- the stable matrix slot ordinal;
- the attempt number.

The derivation algorithm and its version are recorded. Given the same generator implementation/version, seed, scenario, and supported environment, the resolved workload plan should be reproducible where practical. Network scheduling, kernel packetization, SA identifiers, timestamps, and cryptographic nonces are not expected to be byte-for-byte reproducible.

Retries receive a distinct deterministic seed because they are independent attempts. The original failed attempt and its seed remain in the manifest.

All selected parameters, planned requests, realized counts, realized bytes, and relevant timings are stored in `traffic.json`. Independent sessions must not copy or split existing PCAPs.

### 7.2 ICMP

The ICMP generator invokes `ping` from `ips-client` to `10.20.0.2` with seeded selections from small bounded sets:

- packet count;
- interval;
- payload size.

Validation requires the command to finish successfully and the parsed transmitted and received counts to equal the planned count. Partial replies fail traffic validation.

### 7.3 Web

The web generator starts a local standard-library HTTP service bound to `10.20.0.2` inside `ips-server`. It does not depend on Flask, FastAPI, a headless browser, public DNS, or an external website.

The seed resolves:

- page order;
- selected resources;
- deterministic resource content and sizes;
- request count;
- bounded think times.

The client runs inside `ips-client` and performs multiple sequential page and asset requests, preferably over a reused HTTP connection where practical. The service records method, path, status, response bytes, and receipt timestamp to a run-local log.

Validation requires every planned request to appear in the server receipt log with the expected successful status and byte count, and requires the client to report the same completed request set. A client-only success without matching server receipts fails.

### 7.4 Video

The video generator uses the same local protected HTTP path but models segmented media delivery. It issues multiple ordered segment requests rather than transferring one monolithic file.

The seed resolves:

- a bounded bitrate/profile;
- segment duration;
- segment sequence and count;
- deterministic per-segment size/content;
- total target duration;
- bounded pacing or buffer cadence.

The initial smoke profiles remain short enough for development tests while producing sustained downstream transfer across multiple segment requests. The client records request timing and received bytes; the server records matching segment receipts.

Validation requires the planned segment count, matching server receipts, minimum total bytes, and a realized transfer/pacing duration within documented tolerance. A single successful large response cannot satisfy video validation.

## 8. Capture Separation and Workload Window

### 8.1 Capture roles

Dataset attempts use distinct artifacts with explicit roles:

- `full-evidence.pcap`: the complete encrypted transit session, beginning before IKE initiation and ending after CHILD_SA rekey evidence is collected. It exists for tunnel, IKE, ESP, rekey, and PFS validation.
- `encrypted.pcap`: a deterministic derivative containing only outer protocol-50 ESP packets whose capture timestamps fall within the measured workload window. It is the only PCAP designated as future ML input.
- `cleartext-audit-gateway-a.pcap` and `cleartext-audit-gateway-b.pcap`: Phase 1-compatible broad audit captures used only for validation and debugging. They are never ML input.

The dataset metadata labels every PCAP as `evidence`, `ml_input`, or `validation_only`. Phase 3 must consume only files marked `ml_input`.

The existing Phase 1 command retains its current `encrypted.pcap` behavior and naming. The new two-file semantics apply only to dataset attempts.

### 8.2 Single-capture derivation

Two simultaneous outer captures are unnecessary. The dataset runner captures the complete outer session once as legacy libpcap in `full-evidence.pcap`, then derives `encrypted.pcap` after capture shutdown.

The measured workload window is defined exactly as follows:

1. The traffic service is prepared before the tunnel workload window.
2. `workload_started_unix_ns` is sampled from `time.time_ns()` immediately before the client workload process is launched.
3. The generator runs only its planned client workload.
4. `workload_finished_unix_ns` is sampled immediately after the client process has exited and its final response bytes have been collected.
5. Generator validation performs no additional protected-network requests.
6. CHILD_SA rekey starts only after `workload_finished_unix_ns` is recorded.

The derivation reader preserves the source PCAP global header and copies a packet record only when both conditions hold:

- its capture timestamp is inclusively within `[workload_started_unix_ns, workload_finished_unix_ns]`; and
- it is an outer IPv4 ESP packet between `192.0.2.1` and `192.0.2.2`.

The reader supports the endianness and microsecond/nanosecond timestamp magic values emitted by tcpdump legacy PCAP and validates the link type it parses. Ethernet with optional 802.1Q/802.1ad tags is supported. An unsupported or malformed capture fails closed rather than producing an ML file.

`encrypted.pcap` validation requires:

- a readable PCAP header and records;
- at least the class-specific minimum ESP packet count;
- zero UDP/500 IKE packets;
- zero UDP/4500 packets;
- zero non-ESP packets;
- all packet timestamps inside the recorded workload window;
- the expected transit peer pair;
- nonzero capture duration, except that a narrowly bounded ICMP workload may use a documented minimum based on its configured interval.

`full-evidence.pcap` remains the source for IKE establishment, native ESP, NAT-T exclusion, and capture-drop checks. The rekey command, before/after `swanctl` snapshots, strongSwan log segment, and reciprocal SPI transition remain the source for PFS verification. These evidence sources are retained but excluded from future ML input.

## 9. Dataset Run Lifecycle

Each attempt follows this order:

1. Parse and validate dataset and scenario configuration.
2. Create or load the manifest and verify the matrix fingerprint.
3. Materialize a deterministic `PENDING` attempt and run directory.
4. Record start time and transition the attempt to `RUNNING` transactionally.
5. Run the Phase 1 kernel/XFRM/tool preflight.
6. Perform the scoped Phase 1 reset.
7. Create and read back the topology.
8. Start the two isolated strongSwan daemons.
9. Prepare the selected traffic generator and any local server.
10. Start `full-evidence.pcap` and both audit captures before IKE initiation.
11. Load configuration, initiate the tunnel, and wait for IKE and CHILD SAs.
12. Collect and validate `swanctl` and XFRM state/policy evidence.
13. Record the workload start boundary and run the planned traffic.
14. Record the workload end boundary and validate class-specific traffic evidence.
15. Explicitly rekey the CHILD_SA and verify fresh DH plus reciprocal SPI changes.
16. Stop all captures and reject any reported kernel drops.
17. Validate `full-evidence.pcap` and the two cleartext audit captures.
18. Derive and validate workload-only `encrypted.pcap`.
19. Write raw evidence and stage the terminal JSON artifacts without marking the attempt `PASS`.
20. Attempt all cleanup actions independently.
21. Record cleanup outcome separately.
22. Compute the final attempt state, atomically publish the terminal JSON files, then commit the manifest state and `training_ready` value transactionally.
23. Regenerate `dataset_summary.json` atomically.

Capture starts before IKE initiation. Traffic never starts before the tunnel, CHILD SA, XFRM state, and XFRM policy have independently passed. A failure stops progression at that layer and proceeds to cleanup.

The manifest is authoritative. A `PASS` transaction is committed only after every required artifact is durable and cleanup has passed. If the process dies after files are written but before the manifest transaction, resume treats the stale attempt as `INCOMPLETE`; it does not infer success from files alone.

## 10. Run States, Cleanup, and Failure Classification

### 10.1 States

Every logical slot and attempt uses explicit uppercase states:

- `PENDING`: planned but not started;
- `RUNNING`: execution began and has no terminal result;
- `PASS`: every required data-quality and lifecycle check passed;
- `FAILED`: execution reached a handled terminal failure;
- `INCOMPLETE`: execution was interrupted or a previously `RUNNING` attempt was found after process loss.

Allowed normal transitions are:

```text
PENDING -> RUNNING
RUNNING -> PASS
RUNNING -> FAILED
RUNNING -> INCOMPLETE
```

On resume, stale `RUNNING` attempts are transactionally changed to `INCOMPLETE` before scheduling decisions. A failed or incomplete attempt never changes to `PASS`; a retry creates a new attempt row and directory.

### 10.2 Cleanup outcome

Cleanup is recorded independently with:

- `cleanup_status`: `NOT_STARTED`, `PASS`, or `FAILED`;
- `cleanup_started_at` and `cleanup_finished_at`;
- a structured list of each cleanup action and result;
- `cleanup_error` when any action fails.

Cleanup independently attempts traffic client termination, local service termination, capture shutdown, strongSwan log preservation, both daemon stops, namespace deletion, exact root-veth deletion, XFRM removal through namespace teardown, and future network-profile cleanup.

An otherwise valid attempt with failed cleanup is `FAILED`, has `training_ready=false`, and records `failure_class=cleanup_failed`. The data remains available for diagnosis but is excluded from the successful dataset.

### 10.3 Failure classes

Handled failures use stable machine-readable classes, including:

- `configuration_failed`;
- `preflight_failed`;
- `topology_failed`;
- `tunnel_establishment_failed`;
- `ipsec_evidence_failed`;
- `traffic_prepare_failed`;
- `traffic_generator_failed`;
- `traffic_validation_failed`;
- `capture_failed`;
- `zero_or_insufficient_esp`;
- `pcap_derivation_failed`;
- `artifact_publication_failed`;
- `cleanup_failed`;
- `interrupted`;
- `unexpected_error`.

Configuration and preflight failures are non-retriable until the environment or input changes. Runtime tunnel, traffic, capture, derivation, artifact, cleanup, and interruption failures are eligible for the configured bounded retry. `retry_failed: 1` means at most two attempts for a logical slot. There are no infinite retries.

After retries are exhausted, serial matrix generation continues to later slots but exits nonzero at the end if any slot lacks a passing attempt.

## 11. Manifest and Resume

### 11.1 SQLite choice

The dataset manifest is `dataset/<dataset-name>/manifest.sqlite3`. SQLite is used because it is in the Python standard library and provides transactions, constraints, durable state changes, indexed lookup, and safe recovery without parsing or repairing a partially appended JSONL record.

The database uses explicit transactions, foreign keys, a busy timeout, and WAL mode where supported by the filesystem. Each attempt state transition is committed before the next external lifecycle step. The database never stores PCAP blobs.

### 11.2 Logical schema

The manifest contains the logical equivalent of:

- `datasets`: name, schema version, matrix fingerprint, source config path, base seed, creation/update timestamps;
- `slots`: stable slot ID, ordinal, scenario, traffic class, network profile, repetition index, current state, successful attempt ID;
- `attempts`: attempt ID, slot ID, attempt number, seed, state, timestamps, artifact path, failure class/message, cleanup fields, validation flags, ESP count, capture bytes, and `training_ready`;
- `events`: timestamped state transitions and retry/resume reasons.

All paths stored in the manifest are relative to the dataset root.

### 11.3 Matrix fingerprint

The fingerprint is SHA-256 over a canonical representation of all fields that determine matrix identity: dataset schema version, dataset name, ordered traffic classes, ordered IPsec scenarios, ordered network profiles, runs per combination, base seed, and generator names/versions.

`--resume` requires an exact fingerprint match. A changed matrix cannot silently reuse prior slot IDs or artifacts. A user must choose a new dataset name or explicitly perform a future migration outside this phase.

### 11.4 Deterministic IDs

Matrix expansion is serial and deterministic. It preserves the declared configuration order and assigns zero-padded logical IDs:

```text
run_000001
run_000002
...
```

The first attempt uses the logical ID as its attempt ID and directory. Later attempts use `run_000001-attempt02`, `run_000001-attempt03`, and so on. Existing IDs are never renumbered.

### 11.5 Resume behavior

With `--resume`, the runner:

1. validates the stored schema and matrix fingerprint;
2. converts stale `RUNNING` attempts to `INCOMPLETE`;
3. skips slots with a `PASS` attempt;
4. creates a new deterministic attempt for eligible failed or incomplete slots when retry budget remains;
5. schedules untouched `PENDING` slots;
6. leaves exhausted failures intact;
7. regenerates the summary and returns nonzero if the dataset remains incomplete.

Without `--resume`, generation refuses to overwrite or append to an existing initialized dataset directory.

## 12. Artifact Layout

The dataset root is:

```text
dataset/cipherlens-smoke-v1/
  manifest.sqlite3
  matrix.yaml
  dataset_summary.json
  runs/
    run_000001/
      full-evidence.pcap
      encrypted.pcap
      cleartext-audit-gateway-a.pcap
      cleartext-audit-gateway-b.pcap
      ground_truth.json
      verification.json
      traffic.json
      environment.json
      scenario.yaml
      run.log
      strongswan-gateway-a.log
      strongswan-gateway-b.log
      swanctl-gateway-a.txt
      swanctl-gateway-b.txt
      swanctl-before-rekey-gateway-a.txt
      swanctl-before-rekey-gateway-b.txt
      swanctl-after-rekey-gateway-a.txt
      swanctl-after-rekey-gateway-b.txt
      xfrm-gateway-a.txt
      xfrm-gateway-b.txt
      pfs-rekey.log
      tcpdump.log
      tcpdump-audit-gateway-a.log
      tcpdump-audit-gateway-b.log
```

Failed and incomplete attempts use the same self-contained layout and retain every artifact available at the failure point. They are not silently deleted.

Runtime sockets, PIDs, and temporary captures remain under a private mode-0700 `/run/ipsec-sentinel/<attempt-id>/` directory and are not durable dataset artifacts.

## 13. Ground Truth and Schemas

### 13.1 Schema versioning

The initial constants are:

- dataset ground-truth schema: `ipsec-sentinel.dataset-ground-truth/v1`;
- verification schema: `ipsec-sentinel.dataset-verification/v1`;
- traffic schema: `ipsec-sentinel.traffic/v1`;
- scenario schema: `ipsec-sentinel.scenario/v1`;
- manifest schema version: integer `1` managed through SQLite `PRAGMA user_version`.

Unknown schema versions fail closed. Future schema changes require an explicit migration or new dataset.

### 13.2 Ground-truth model

The dataset model composes the existing Phase 1 `ConfiguredPolicy`, `ObservedState`, PFS observation, capture evidence, and verification checks rather than replacing them. Phase 1 serialization remains compatible.

Logical shape:

```json
{
  "schema_version": "ipsec-sentinel.dataset-ground-truth/v1",
  "run_id": "run_000001",
  "slot_id": "run_000001",
  "attempt_number": 1,
  "status": "PASS",
  "training_ready": true,
  "traffic": {
    "class": "video",
    "known_training_class": true,
    "generator": "local-segmented-video",
    "generator_version": "1",
    "seed": 123456789,
    "parameters": {},
    "result": {}
  },
  "ipsec": {
    "scenario_id": "secure-baseline",
    "scenario_schema_version": "ipsec-sentinel.scenario/v1",
    "configured": {},
    "observed": {}
  },
  "network": {
    "profile": "clean",
    "latency_ms": 0,
    "jitter_ms": 0,
    "packet_loss_percent": 0,
    "bandwidth_limit_bps": null
  },
  "capture": {
    "full_evidence_file": "full-evidence.pcap",
    "ml_input_file": "encrypted.pcap",
    "workload_started_unix_ns": 0,
    "workload_finished_unix_ns": 0,
    "esp_packets": 0,
    "capture_bytes": 0,
    "duration_seconds": 0.0,
    "derivation": "pcap-workload-window-esp/v1"
  },
  "validation": {
    "traffic_verified": true,
    "ipsec_verified": true,
    "capture_verified": true,
    "cleanup_verified": true
  },
  "reproducibility": {}
}
```

Configured policy and observed negotiation remain distinct objects. Requested proposals must never be copied into observed fields as a substitute for `swanctl`, XFRM, rekey, or PCAP evidence.

### 13.3 Reproducibility metadata

Every attempt writes `environment.json` and embeds the same logical information under `ground_truth.json.reproducibility`:

- exact Git commit SHA;
- Git dirty flag and, when dirty, a deterministic diff hash;
- dataset schema version;
- scenario schema version;
- manifest schema version;
- strongSwan version;
- kernel release/version;
- Python implementation and version;
- traffic generator name and implementation version;
- seed derivation version and attempt seed;
- dataset matrix fingerprint;
- UTC run start and end timestamps in RFC 3339 form;
- workload start and end Unix nanoseconds;
- platform identifier and architecture.

Metadata collection failure is an attempt failure because an unversioned session is not reproducible enough for the dataset.

## 14. Network Profiles

Phase 2 implements only:

```yaml
network_profiles:
  - clean
```

The `clean` profile records zero configured latency, jitter, loss, and bandwidth limit and verifies that the dataset runner did not install netem state. A small network-profile interface reserves `apply()`, `verify()`, `cleanup()`, and `metadata()` for later `tc/netem` support. No impairment profile is added to the smoke milestone.

## 15. Smoke Matrix

`configs/smoke-v1.yaml` has the logical content:

```yaml
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

Only `workers: 1` is accepted in Phase 2. Unknown fields and unsupported values fail configuration validation. The smoke command creates nine logical slots.

## 16. Validation and Training-readiness

An attempt is `PASS` and `training_ready=true` only if all of the following are true:

1. Preflight passed.
2. Topology readback passed.
3. IKE SA is established on both gateways.
4. CHILD SA is installed on both gateways.
5. XFRM states and policies match selectors, peers, algorithms, and reciprocal CHILD SPIs.
6. The selected generator completed.
7. Class-specific traffic validation passed.
8. `full-evidence.pcap` exists, is readable, contains peer-matched IKE and native ESP, contains no NAT-T, and has no capture drops.
9. The two audit captures pass Phase 1 cleartext correlation checks and have no capture drops.
10. Explicit CHILD_SA rekey proves fresh DH and reciprocal inbound/outbound SPI changes.
11. `encrypted.pcap` exists, is readable, contains only workload-window peer-matched ESP, and exceeds the class-specific minimum.
12. Required metadata and configured/observed ground truth exist and pass schema validation.
13. Artifact publication completed atomically.
14. Cleanup passed.

No failed, incomplete, or cleanup-failed attempt is included in the training-ready count, even if it produced a readable PCAP.

Class-specific minimum ESP thresholds are derived conservatively from the planned workload and documented in verification evidence. The initial rule must be strong enough to reject an empty or tunnel-control-only capture without pretending that packet count alone validates the label.

## 17. Dataset Summary

After every terminal attempt, the runner atomically rewrites `dataset_summary.json` from SQLite. It contains:

- dataset name, schema version, and matrix fingerprint;
- logical slots planned, passed, failed, pending, and incomplete;
- attempt counts by state;
- training-ready run count;
- class distribution of training-ready runs;
- failures by failure class;
- total ML ESP packets;
- total `encrypted.pcap` bytes;
- total measured workload duration;
- generation start/update timestamps.

The CLI prints the same core information in a compact human-readable form. Summary values come from successful manifest records, not by guessing labels from directories or packet contents.

## 18. Test Strategy

### 18.1 Ordinary tests

Non-root unit tests cover:

- generator interface conformance;
- deterministic seeded parameter selection and variation across seeds;
- ICMP, web, and video validation success and failure;
- exact workload-window boundary behavior;
- PCAP derivation, malformed input rejection, link-type rejection, and IKE/rekey exclusion;
- dataset and traffic schema serialization;
- reproducibility metadata requirements;
- strict matrix configuration parsing;
- deterministic expansion, IDs, seeds, and fingerprints;
- SQLite schema, constraints, transactions, and state transitions;
- stale `RUNNING` to `INCOMPLETE` recovery;
- resume skipping successful slots;
- retry limits and independent attempt IDs/seeds;
- failure classification and cleanup outcome separation;
- training-ready exclusion for every invalid state;
- summary counts and class distribution;
- Phase 1 compatibility adapters.

Tests use temporary directories and synthetic PCAP fixtures. They do not require root or live network namespaces.

### 18.2 Privileged integration tests

Root-gated WSL/Linux integration tests cover:

- the unchanged Phase 1 secure baseline;
- one ICMP dataset attempt;
- one web dataset attempt;
- one video dataset attempt;
- a small matrix execution and `--resume` no-op for already passing slots;
- injected retriable failure followed by a successful independent retry;
- cleanup verification after success and failure.

Every integration test verifies that no tracked tcpdump, traffic service, traffic client, strongSwan process, namespace, root veth, runtime directory, or stale XFRM state remains.

The development session generates only the nine-run smoke dataset after individual class integrations pass. It does not generate a large training corpus.

## 19. Documentation

The README will gain a Dataset Factory section explaining:

- the purpose and ground-truth principle;
- the four-node topology and capture point;
- supported traffic classes;
- the distinction between `full-evidence.pcap`, validation-only captures, and ML-input `encrypted.pcap`;
- the exact workload-window rule;
- configured versus observed IPsec evidence;
- single-run, matrix, resume, and validate commands;
- manifest and run states;
- retry behavior;
- artifact structure and schemas;
- unattended execution guidance;
- current limitations;
- how to add a future traffic generator.

## 20. Security and Operational Constraints

- All network traffic is local to the namespace lab.
- No public website or cloud service is contacted by a generator.
- The HTTP service binds only to the protected server address inside `ips-server`.
- Test PSKs remain lab-only and are never presented as production secrets.
- Runtime paths are private and attempt-scoped.
- Cleanup names only tracked PIDs and exact lab resources; it does not use wildcard process killing.
- Validation fails closed on missing evidence, malformed PCAPs, capture drops, unknown schemas, missing metadata, or disagreement between configured and observed state.
- A host lacking required XFRM/IPsec support stops at preflight; the architecture is not redesigned automatically.

## 21. Definition of Done

Phase 2 is complete when:

- Phase 1 commands, schemas, and tests remain compatible;
- ICMP, controlled web, and segmented-video generators pass end to end;
- seeded sessions vary while recording reproducible resolved plans;
- every attempt establishes a fresh independent tunnel and capture;
- full evidence and workload-only ESP captures are separated and validated;
- IKE and PFS rekey evidence is retained but excluded from the ML input PCAP;
- configured and observed IPsec parameters remain distinct;
- all required reproducibility fields are recorded;
- explicit states and separate cleanup outcomes are persisted transactionally;
- failure history, bounded retry, interruption recovery, and resume work;
- the manifest and summary accurately index training-ready runs;
- the nine-run smoke matrix completes or reports precise retained failures;
- relevant unit and privileged integration tests pass;
- cleanup leaves no lab resources or processes;
- no Phase 3 feature extraction or ML work has begun.
