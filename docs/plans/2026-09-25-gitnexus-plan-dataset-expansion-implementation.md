# IPsec Sentinel Dataset Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> Task: Expand the Phase 2 dataset factory with four supervised generators, two evaluation-only OOD workloads, four allowlisted IPsec configurations, three network profiles, an exact 11-session smoke, and leakage review tooling.
>
> Evidence verified at commit `d45c4ac6c2255e83a5f54c6902d4496f72914896`; GitNexus index not used because the target repository is not indexed (the only available index is for unrelated repository `Aura`). All findings below are source-derived fallback evidence.
>
> Evidence provenance schema 2; global dirty digest `0a9c85780067d9afcd0764f307b60891e3cee927ee11eaeb5ec7826d10fd82cd`; cited-path manifest contains 39 sorted entries; the exact generated plan path is excluded.

**Goal:** Build a resumable, serial dataset factory for seven supervised encrypted-traffic classes and two evaluation-only OOD workloads across four verified IPsec scenarios and three deterministic network profiles, while preserving Phase 1/2 compatibility and strict capture separation.

**Architecture:** Keep `run_dataset_attempt()` as the single lifecycle owner and extend its existing registries for traffic roles, scenarios, and network profiles. New generators use a small shared namespace-process, seeded-port, framing, and deterministic-payload foundation; scenario and profile definitions are allowlisted and persisted with configured-versus-observed evidence. SQLite remains the source of resume/retry truth through an additive v1-to-v2 migration.

**Tech Stack:** Python 3 standard library, `unittest`, PyYAML, SQLite, Linux network namespaces, strongSwan/swanctl/VICI, XFRM, tcpdump/PCAP parsing, and `tc netem`.

**Spec:** `docs/superpowers/specs/2026-09-25-ipsec-sentinel-dataset-expansion-design.md`

## Global Constraints

- Work only on `feat/ipsec-sentinel-dataset-expansion`, stacked on Phase 2 commit `6460d234deabdf9e295f7e48fb57fe5039f0cc0f`; do not merge, rebase, push, or open a PR automatically.
- Preserve `run_secure_baseline()`, Phase 1 topology, Phase 2 retry/resume/recovery, immutable attempt directories, serial execution, and cleanup/status separation.
- Supervised allowlist is exactly `icmp, web, video, voip, email, messaging, file_transfer`.
- Evaluation-only OOD allowlist is exactly `remote_desktop_like, database_query_like`; supervised eligibility requires both `known_training_class is True` and membership in the supervised allowlist.
- Shared seeded ports come from `20000-29999`; selected ports and deterministic collision fallbacks are recorded.
- IPsec allowlist is exactly `secure-baseline`, `aes128-gcm`, `aes256-cbc`, and `no-pfs`; ECP-384 remains constant for every PFS-enabled CHILD SA.
- Network-profile allowlist is exactly `clean`, `moderate_latency`, and `jitter_loss`; profiles apply symmetrically to gateway `wan0` egress, are verified by readback, and are removed before rekey and again during idempotent cleanup.
- `full-evidence.pcap` preserves IKE, ESP workload, and rekey evidence; derived `encrypted.pcap` remains expected-peer protocol-50 ESP only and excludes establishment/rekey traffic.
- Generate only the exact 11-session extension smoke during implementation. Do not generate the 492-session bulk dataset.
- Do not add feature extraction, ML tables/splits/models, calibration, OOD detectors, APIs, frontends, assessment engines, or reports.

## Review Focus

1. A manifest whose role column, `traffic.json`, or edited matrix disagrees with the authoritative registry must fail validation and never become supervised-eligible; pinned in Tasks 1-2.
2. A service collision, timeout, partial startup, or repeated cleanup must leave no child process/socket and must record the chosen fallback port; pinned in Task 3.
3. CBC/XFRM normalization and PFS-disabled rekey evidence must not be judged with AES-GCM/fresh-DH assumptions; pinned in Tasks 10-13.
4. A failed netem apply/readback or interrupted workload must remove both gateway qdiscs, and the following clean run must prove no residue; pinned in Tasks 14-15.
5. A classifier shortcut caused by fixed ports, addresses, durations, startup/rekey timing, payloads, directionality, packet counts, or matrix imbalance must be reported before bulk generation; pinned in Task 17.

---

## 1. Objective

Implement the approved dataset expansion in dependency order with a real privileged integration gate after every new generator, every new IPsec scenario, and every network-profile layer. Each failed checkpoint stops later dependent work.

## 2. Current Behaviour

- [verified] `TrafficGenerator` already defines `prepare/run/validate/cleanup/metadata`, but the registry stores only factories; class role is supplied ad hoc by each generator (`ipsec_sentinel/traffic/base.py`, `ipsec_sentinel/traffic/__init__.py`).
- [verified] artifact construction currently hardcodes `known_training_class=True`, so it cannot safely persist OOD runs (`ipsec_sentinel/dataset/artifacts.py`).
- [verified] matrix expansion is supervised-only Cartesian expansion and fingerprints only class/scenario/profile names, run count, and generator versions (`ipsec_sentinel/dataset/config.py`, `ipsec_sentinel/dataset/matrix.py`).
- [verified] the manifest is schema version 1 and already correctly preserves attempts, state transitions, independent retry seeds, successful-slot skipping, and recovery of stale `RUNNING` attempts (`ipsec_sentinel/dataset/manifest.py`, `tests/test_dataset_manifest.py`, `tests/test_dataset_runner.py`).
- [verified] Web and Video use fixed ports 8080/8081 and a bespoke HTTP process wrapper; ICMP has no service process (`ipsec_sentinel/traffic/web.py`, `ipsec_sentinel/traffic/video.py`, `ipsec_sentinel/traffic/http_service.py`).
- [verified] `run_dataset_attempt()` owns capture boundaries and cleanup, but applies the network profile before daemon startup and leaves profile removal until final cleanup (`ipsec_sentinel/dataset/runner.py`).
- [verified] `Scenario.load()`, strongSwan rendering, SA/XFRM evaluation, and PFS evaluation are hardcoded to the AES-256-GCM/ECP-384 baseline (`ipsec_sentinel/scenario.py`, `ipsec_sentinel/strongswan.py`, `ipsec_sentinel/evidence.py`).
- [verified] `derive_workload_esp()` and `inspect_ml_pcap()` already enforce the workload timestamp window, protocol 50, expected transit peers, and non-empty ESP capture; these checks remain strict (`ipsec_sentinel/pcap.py`, `tests/test_pcap_workload.py`).
- [verified] `run_secure_baseline()` constructs `SecureSession` directly and relies on existing stage ordering and output models, so shared model/session changes require an immediate Phase 1 regression gate (`ipsec_sentinel/runner.py`, `tests/test_secure_baseline_integration.py`).

## 3. Relevant Architecture

The dataset command loads a strict YAML configuration, expands deterministic slots, initializes or resumes SQLite state, and calls `run_dataset_attempt()` serially. The attempt runner creates the generator, session, and network profile; establishes the real tunnel; records a workload window around only `generator.run()`; rekeys after that window; derives ESP-only ML input; writes immutable artifacts; and then records the terminal manifest state.

The implementation will retain this flow but make three registries authoritative:

- `TrafficClassSpec` owns factory, version, and supervised/OOD role.
- `ScenarioDefinition` owns the allowlisted YAML path, expected normalized algorithms, PFS policy, version, and digest.
- `NetworkProfileSpec` owns the factory, version, and normalized netem parameters.

The lifecycle consumes registry entries and persists their identities. Generators and profiles do not establish tunnels or choose capture boundaries.

## 4. GitNexus Findings

GitNexus fallback mode is active: `mcp__gitnexus__list_repos(limit=200)` returned only unrelated repository `Aura`; no graph, impact, or process claim is used for this repository.

Source-derived dependency findings:

- [verified] `run_dataset_attempt()` directly couples generator creation, scenario loading, network-profile lifecycle, evidence evaluation, capture derivation, artifact publication, and cleanup. It is the highest-risk integration symbol.
- [verified] `MatrixSlot -> AttemptPlan -> DatasetGroundTruth` is the data path that must carry class role, scenario definition, profile version, and seed without recomputing mutable labels.
- [verified] `StrongSwanPair.render_configs/start`, `SecureSession.load_scenario/start_daemons/rekey`, and `evaluate_tunnel/evaluate_ipsec/evaluate_pfs` form the configured-to-observed IPsec proof path.
- [verified] `Manifest.initialize/next_attempt/recover_running/finish_attempt` and `generate_dataset()` form the transactional retry/resume path; migration must preserve their state-machine checks.
- [verified] `build_terminal_payloads()`, `validate_dataset()`, and `build_summary()` are independent consumers of role and evidence data, so all three must reject disagreement rather than trusting one field.

## 5. Statement-Level PDG Findings

No target-repository PDG layer is available. Source inspection establishes these ordering constraints:

- [verified] workload timestamps are set immediately around `generator.run()`; service readiness must complete before that call and rekey must remain after it.
- [verified] `finalize_attempt_state()` requires traffic, IPsec, capture, and cleanup success before PASS; OOD quality success must keep this rule while supervised eligibility remains a separate selection property.
- [verified] manifest state transitions occur under `BEGIN IMMEDIATE`; migrations and new columns must not weaken PENDING → RUNNING → terminal checks.
- [verified] `finally`-style cleanup currently attempts generator, profile, and session cleanup independently; early profile removal must be idempotent because final cleanup invokes it again.
- [verified] current PFS validation searches one fixed GCM/ECP-384 log line; scenario-aware evaluation must compare SPI replacement plus expected DH presence/absence instead.

## 6. Proposed Changes

1. Promote traffic class role into the generator registry and enforce the dual supervised-selection invariant in config, matrix, manifest, artifacts, summaries, and offline validation.
2. Add an additive manifest schema-v2 migration and persist class role, generator version, scenario digest, and profile version without redesigning retry/resume.
3. Add narrowly scoped seeded-port, namespace-process, deterministic-payload, and framed-I/O helpers; migrate Web/Video off fixed ports while preserving their workload semantics.
4. Add VoIP, Email, Messaging, File Transfer, `remote_desktop_like`, and `database_query_like` generators through the existing five-method contract.
5. Replace hardcoded scenario expectations with an allowlisted scenario registry and scenario-aware strongSwan rendering/evidence normalization.
6. Split rekey proof into SPI replacement and CHILD-DH observation so both PFS-enabled and no-PFS policy can be positively verified.
7. Replace the clean-only profile with an allowlisted network-profile registry and deterministic netem implementation, moving apply/verify after initial tunnel proof and removal before rekey.
8. Add Cartesian supervised/OOD expansion, exact explicit cases, complete fingerprint inputs, extension/bulk configs, leakage audit tooling, and operator documentation.

## 7. Implementation Sequence

### Task 1: Make traffic role authoritative and enforce dual selection

**Goal:** Establish supervised/OOD semantics before any OOD generator exists.

**Files:**
- Modify: `ipsec_sentinel/traffic/base.py`
- Modify: `ipsec_sentinel/traffic/__init__.py`
- Modify: `ipsec_sentinel/dataset/config.py`
- Modify: `ipsec_sentinel/dataset/matrix.py`
- Modify: `tests/test_traffic_contract.py`
- Modify: `tests/test_dataset_config.py`
- Modify: `tests/test_dataset_matrix.py`

**Interfaces:**
- Produces: `TrafficClassSpec(name: str, factory: GeneratorFactory, version: str, known_training_class: bool)`
- Produces: `traffic_spec(name) -> TrafficClassSpec`, `traffic_specs() -> tuple[TrafficClassSpec, ...]`
- Produces: `is_supervised_eligible(name: str, known_training_class: bool) -> bool`
- Extends: `DatasetConfig.evaluation_ood_classes` and `DatasetConfig.evaluation_runs_per_combination`

- [ ] **Step 1: Write failing registry and eligibility tests.**

  ```python
  self.assertTrue(is_supervised_eligible("icmp", True))
  self.assertFalse(is_supervised_eligible("icmp", False))
  self.assertFalse(is_supervised_eligible("remote_desktop_like", True))
  self.assertFalse(traffic_spec("remote_desktop_like").known_training_class)
  ```

  Register test-only supervised and OOD specs and assert duplicate names, OOD-in-`traffic.classes`, supervised-in-`evaluation.ood_classes`, and unknown labels fail closed.

- [ ] **Step 2: Run the focused tests and confirm failure.**

  Run: `python3 -m unittest tests.test_traffic_contract tests.test_dataset_config tests.test_dataset_matrix -v`  
  Expected: FAIL because role-bearing registry/config APIs do not exist.

- [ ] **Step 3: Implement the registry metadata and hard allowlists.**

  ```python
  SUPERVISED_CLASS_ALLOWLIST = frozenset(
      {"icmp", "web", "video", "voip", "email", "messaging", "file_transfer"}
  )
  OOD_CLASS_ALLOWLIST = frozenset({"remote_desktop_like", "database_query_like"})

  @dataclass(frozen=True)
  class TrafficClassSpec:
      name: str
      factory: GeneratorFactory
      version: str
      known_training_class: bool
  ```

  Keep `register_generator()` backward-compatible for existing tests by defaulting `known_training_class=True`, but require built-ins to register explicitly. Make the registry—not YAML—the role authority.

- [ ] **Step 4: Extend strict config parsing for a separate optional `evaluation` block.**

  Accept exactly `evaluation: {ood_classes, runs_per_combination}`; default it to empty for existing Phase 2 configs. Reject mixed roles through registry lookup during matrix validation.

- [ ] **Step 5: Run focused tests and the complete ordinary suite.**

  Run: `python3 -m unittest tests.test_traffic_contract tests.test_dataset_config tests.test_dataset_matrix -v`  
  Run: `python3 -m unittest discover -s tests -v`  
  Expected: role tests PASS; existing guarded privileged tests remain skipped unless enabled.

- [ ] **Step 6: Review the invariant and commit.**

  Confirm no selection API treats `known_training_class` or class-name membership alone as sufficient.  
  Commit: `git commit -am "feat: enforce dataset class roles"`

**Failure gate / rollback:** Stop if any existing `configs/smoke-v1.yaml` load changes or existing ICMP/Web/Video registration fails. Revert only this task commit; no schema mutation has occurred.

**Expected result:** OOD role is structurally representable and impossible to select through the supervised list.

### Task 2: Persist roles with an additive manifest migration and split summaries

**Goal:** Make SQLite, terminal artifacts, summaries, and offline validation agree on quality readiness versus supervised eligibility.

**Files:**
- Modify: `ipsec_sentinel/dataset/models.py`
- Modify: `ipsec_sentinel/dataset/manifest.py`
- Modify: `ipsec_sentinel/dataset/artifacts.py`
- Modify: `ipsec_sentinel/dataset/summary.py`
- Modify: `ipsec_sentinel/dataset/validation.py`
- Modify: `tests/test_dataset_models.py`
- Modify: `tests/test_dataset_manifest.py`
- Modify: `tests/test_dataset_summary.py`
- Modify: `tests/test_dataset_validation.py`

**Interfaces:**
- Produces: manifest schema version 2 with `slots.known_training_class`, `slots.class_role`, `slots.generator_version`, `slots.scenario_definition_digest`, and `slots.network_profile_version`; Task 2 fills role/generator fields and compatibility sentinels, while Tasks 10 and 14 replace the scenario/profile sentinels from their authoritative registries
- Produces: `Manifest.quality_ready_attempts()` and `Manifest.supervised_ready_attempts()`
- Extends: `DatasetSummary.supervised_class_distribution` and `DatasetSummary.ood_class_distribution`

- [ ] **Step 1: Write failing v1 migration, role disagreement, and summary tests.**

  Build a real schema-v1 fixture, open it twice, and assert both opens produce schema 2 without losing attempts/events. Add assertions that an OOD PASS is quality-ready but absent from `supervised_ready_attempts()`.

- [ ] **Step 2: Run focused persistence tests and confirm failure.**

  Run: `python3 -m unittest tests.test_dataset_models tests.test_dataset_manifest tests.test_dataset_summary tests.test_dataset_validation -v`  
  Expected: FAIL on missing migration/role fields.

- [ ] **Step 3: Implement an idempotent transactional v1-to-v2 migration.**

  ```python
  def _migrate_v1_to_v2(connection: sqlite3.Connection) -> None:
      connection.execute("BEGIN IMMEDIATE")
      # Add non-destructive columns with supervised-compatible defaults.
      # Set PRAGMA user_version = 2 only after all ALTER/UPDATE statements succeed.
  ```

  Existing manifests default to supervised role because Phase 2 contained only allowlisted supervised classes. Preserve every slot, attempt, event, artifact path, retry seed, and successful-attempt pointer. Use explicit `legacy-secure-baseline/v1` and `clean/v1` compatibility values until Tasks 10 and 14 provide authoritative definition digests/versions; never invent a cryptographic digest.

- [ ] **Step 4: Remove hardcoded role construction and add three-way agreement checks.**

  `build_terminal_payloads()` obtains role from `AttemptPlan`; `validate_dataset()` compares registry, manifest, `traffic.json`, and `ground_truth.json`. Any mismatch yields a validation error and cannot be supervised-eligible.

- [ ] **Step 5: Split summary counts and retain quality totals.**

  Report supervised and OOD session/class/scenario/profile counts separately, plus ESP packets, bytes, and duration per class. Keep `training_ready_runs` as quality-ready count for compatibility and add `supervised_ready_runs`/`ood_ready_runs`.

- [ ] **Step 6: Re-run retry/resume correctness tests.**

  Run: `python3 -m unittest tests.test_dataset_manifest tests.test_dataset_runner tests.test_dataset_summary tests.test_dataset_validation -v`  
  Expected: v1 migration is lossless/idempotent; RUNNING recovery, retry history, successful skip, exhausted retries, and fingerprint rejection still PASS.

- [ ] **Step 7: Commit the persistence layer.**

  Commit: `git commit -am "feat: persist supervised and OOD roles"`

**Failure gate / rollback:** A migration failure must roll back with `user_version=1`; never partially upgrade. Stop if a v1 manifest loses or rewrites any attempt.

**Expected result:** Quality readiness and supervised eligibility are separate, independently verifiable properties.

### Task 3: Add the shared seeded socket/process foundation

**Goal:** Provide only the reusable runtime pieces needed by socket-based generators and remove fixed Web/Video ports without altering workload semantics.

**Files:**
- Create: `ipsec_sentinel/traffic/ports.py`
- Create: `ipsec_sentinel/traffic/process.py`
- Create: `ipsec_sentinel/traffic/framing.py`
- Create: `ipsec_sentinel/traffic/payload.py`
- Create: `ipsec_sentinel/traffic/port_probe.py`
- Modify: `ipsec_sentinel/traffic/http_service.py`
- Modify: `ipsec_sentinel/traffic/web.py`
- Modify: `ipsec_sentinel/traffic/video.py`
- Create: `tests/test_traffic_foundation.py`
- Modify: `tests/test_traffic_web.py`
- Modify: `tests/test_traffic_video.py`
- Modify: `tests/test_dataset_integration.py`

**Interfaces:**
- Produces: `PortSelection(port: int, candidate_index: int, purpose: str, protocol: str)`
- Produces: `select_port_candidates(seed, purpose, protocol, count=32) -> tuple[int, ...]`
- Produces: `choose_available_port(context, seed, purpose, protocol) -> PortSelection`
- Produces: `NamespaceServiceProcess.start()/stop()` with ready-file, exit, timeout, log, and idempotent termination handling
- Produces: length-prefixed frame and deterministic-byte helpers

- [ ] **Step 1: Write failing deterministic-port, timeout, cleanup, framing, and payload tests.**

  ```python
  self.assertEqual(select_port_candidates(7, "web", "tcp"),
                   select_port_candidates(7, "web", "tcp"))
  self.assertNotEqual(select_port_candidates(7, "web", "tcp")[0],
                      select_port_candidates(8, "web", "tcp")[0])
  self.assertTrue(all(20_000 <= p <= 29_999 for p in candidates))
  ```

  Simulate first-candidate collision, early server exit, readiness timeout, repeated `stop()`, truncated frames, and deterministic payload digests.

- [ ] **Step 2: Run focused tests and confirm failure.**

  Run: `python3 -m unittest tests.test_traffic_foundation tests.test_traffic_web tests.test_traffic_video -v`  
  Expected: FAIL because the helpers do not exist and ports remain fixed.

- [ ] **Step 3: Implement stable port derivation and namespace availability probing.**

  Derive candidates with SHA-256 over `port-selection/v1:{seed}:{purpose}:{protocol}:{candidate_index}`. Probe bindability inside the target namespace through `python -m ipsec_sentinel.traffic.port_probe`; record the chosen candidate index and every rejected candidate.

- [ ] **Step 4: Implement `NamespaceServiceProcess` and small framing/payload helpers.**

  `start()` must remove stale readiness files, launch via `ip netns exec`, detect early exit, wait at most the configured timeout, and terminate on timeout. `stop()` performs TERM → bounded wait → KILL and closes logs even when called repeatedly.

- [ ] **Step 5: Refactor HTTP process ownership and migrate Web/Video ports.**

  Preserve request/segment generation and validation exactly; replace 8080/8081 with the shared selection. Add `preferred_port`, `selected_port`, `candidate_index`, and collision evidence to `traffic.json`.

- [ ] **Step 6: Run unit tests and existing real integrations.**

  Run: `python3 -m unittest discover -s tests -v`  
  Run: `sudo env IPSEC_SENTINEL_INTEGRATION=1 python3 -m unittest tests.test_secure_baseline_integration -v`  
  Run: `sudo env IPSEC_SENTINEL_DATASET_INTEGRATION=1 python3 -m unittest tests.test_dataset_integration.DatasetIntegrationTest.test_real_icmp_dataset_run tests.test_dataset_integration.DatasetIntegrationTest.test_real_web_dataset_run tests.test_dataset_integration.DatasetIntegrationTest.test_real_video_dataset_run -v`

- [ ] **Step 7: Execute Checkpoint A review.**

  Confirm Phase 1 passes, ICMP output is unchanged, Web/Video receipts remain exact, same-seed plans match, different seeds vary ports/behavior, and no service process/socket/runtime path remains.

- [ ] **Step 8: Commit the shared foundation.**

  Commit: `git add ipsec_sentinel/traffic tests && git commit -m "feat: add seeded traffic runtime foundation"`

**Failure gate / rollback:** Stop before VoIP if any existing generator, capture role, or cleanup assertion regresses. A failed service start must not enter the workload window.

**Expected artifacts:** Existing Web/Video `traffic.json` files now record seeded shared-range ports and collision evidence.

### Task 4: Implement and prove seeded bidirectional RTP-like VoIP

**Goal:** Add a valid RTP-v2-header UDP workload with realistic bidirectional voice cadence.

**Files:**
- Create: `ipsec_sentinel/traffic/voip.py`
- Create: `ipsec_sentinel/traffic/rtp_peer.py`
- Modify: `ipsec_sentinel/traffic/__init__.py`
- Create: `tests/test_traffic_voip.py`
- Modify: `tests/test_dataset_integration.py`

**Interfaces:**
- Produces: `VoipPlan`, `RtpDirectionPlan`, `resolve_voip_plan(seed)`, and `VoipGenerator`
- RTP packet layout: version 2, payload type from plan, seeded sequence/timestamp/SSRC, deterministic payload bytes

- [ ] **Step 1: Write failing plan, RTP codec, validation, and metadata tests.**

  Assert equal seeds reproduce every planned field; a seed set varies packetization interval, duration, payload distribution, talk spurts, and direction ratio. Decode generated packets and assert RTP version/sequence/timestamp/SSRC correctness.

- [ ] **Step 2: Run VoIP tests and confirm failure.**

  Run: `python3 -m unittest tests.test_traffic_voip -v`  
  Expected: FAIL on missing module.

- [ ] **Step 3: Implement the seeded plan and RTP peer protocol.**

  Use 10/20/30 ms intervals, approximately 3.5-7 second smoke duration, bounded payload-size profiles, alternating talk/suppression periods, and small direction start offsets. The server peer becomes ready before the workload window but transmits only after a client start frame.

- [ ] **Step 4: Implement independent validation and metadata.**

  Require both directions, duration tolerance, derived packet-count ranges, monotonic sequence/timestamp behavior, receipt-ledger agreement, and protected peer addresses. Emit `rtp_like_synthetic: true` and every selected parameter.

- [ ] **Step 5: Run unit tests and seed-variation assertions.**

  Run: `python3 -m unittest tests.test_traffic_voip tests.test_traffic_contract -v`

- [ ] **Step 6: Run the real privileged VoIP dataset integration.**

  Run: `sudo env IPSEC_SENTINEL_DATASET_INTEGRATION=1 python3 -m unittest tests.test_dataset_integration.DatasetIntegrationTest.test_real_voip_dataset_run -v`  
  Expected: PASS with bidirectional receipts, non-empty ESP-only `encrypted.pcap`, IKE/ESP/rekey in `full-evidence.pcap`, and clean resources.

- [ ] **Step 7: Stop-on-failure review and commit.**

  Inspect `traffic.json`, peer ledgers, PCAP summaries, and cleanup. Do not begin Email until real VoIP passes.  
  Commit: `git add ipsec_sentinel/traffic tests && git commit -m "feat: add seeded RTP-like VoIP traffic"`

**Failure gate / rollback:** Preserve the failed attempt directory and logs. Do not weaken packet-count or bidirectional validation to make the integration pass.

### Task 5: Implement and prove controlled SMTP Email

**Goal:** Add a real local SMTP/MIME workflow with seeded transaction and attachment variation.

**Files:**
- Create: `ipsec_sentinel/traffic/email.py`
- Create: `ipsec_sentinel/traffic/smtp_service.py`
- Create: `ipsec_sentinel/traffic/smtp_client.py`
- Modify: `ipsec_sentinel/traffic/__init__.py`
- Create: `tests/test_traffic_email.py`
- Modify: `tests/test_dataset_integration.py`

**Interfaces:**
- Produces: `EmailPlan`, `EmailMessagePlan`, `resolve_email_plan(seed)`, and `EmailGenerator`
- SMTP server supports EHLO/HELO, MAIL FROM, RCPT TO, DATA, RSET, NOOP, QUIT and persists a receipt ledger

- [ ] **Step 1: Write failing SMTP dialogue, MIME ledger, variation, and validation tests.**

  Assert 2-5 transactions, deterministic message IDs/content, varied body/attachment sizes, think times, recipient counts, order, and connection reuse/reconnect behavior.

- [ ] **Step 2: Run Email tests and confirm failure.**

  Run: `python3 -m unittest tests.test_traffic_email -v`

- [ ] **Step 3: Implement the bounded local SMTP receiver and client.**

  Use the standard library `smtplib` and `email.message.EmailMessage`; implement the server with a bounded local TCP state machine rather than an external provider or removed `smtpd` module.

- [ ] **Step 4: Implement server-side receipt validation.**

  Compare planned message ID, sender/recipients, body bytes, attachment filename/bytes/SHA-256, transaction order, and SMTP completion result. Record all selected parameters and receipt digest in `traffic.json`.

- [ ] **Step 5: Run unit tests.**

  Run: `python3 -m unittest tests.test_traffic_email tests.test_traffic_foundation -v`

- [ ] **Step 6: Run the real privileged Email integration.**

  Run: `sudo env IPSEC_SENTINEL_DATASET_INTEGRATION=1 python3 -m unittest tests.test_dataset_integration.DatasetIntegrationTest.test_real_email_dataset_run -v`

- [ ] **Step 7: Stop-on-failure review and commit.**

  Verify the server receipt ledger—not merely client exit code—proves delivery, then commit:  
  `git add ipsec_sentinel/traffic tests && git commit -m "feat: add seeded SMTP email traffic"`

**Failure gate / rollback:** A partial SMTP transaction is a failed workload and its ledger remains diagnostic evidence. Do not begin Messaging until the real Email run passes.

### Task 6: Implement and prove persistent bidirectional Messaging

**Goal:** Add an interactive length-framed TCP workload with seeded bursts, replies, idle gaps, sizes, and direction changes.

**Files:**
- Create: `ipsec_sentinel/traffic/messaging.py`
- Create: `ipsec_sentinel/traffic/messaging_peer.py`
- Modify: `ipsec_sentinel/traffic/__init__.py`
- Create: `tests/test_traffic_messaging.py`
- Modify: `tests/test_dataset_integration.py`

**Interfaces:**
- Produces: `MessagingPlan`, `MessagePlan`, `resolve_messaging_plan(seed)`, and `MessagingGenerator`
- Uses: shared length-prefixed framing and deterministic payload generation

- [ ] **Step 1: Write failing seed, burst, framing, direction, and receipt tests.**

  Assert equal plans for equal seeds and meaningful changes across seeds in burst sizes, idle intervals, sizes, direction sequences, and reply patterns.

- [ ] **Step 2: Run Messaging tests and confirm failure.**

  Run: `python3 -m unittest tests.test_traffic_messaging -v`

- [ ] **Step 3: Implement the persistent session.**

  Keep one bounded TCP connection, assign deterministic message IDs, allow both endpoints to originate frames according to the plan, and write endpoint receipt ledgers.

- [ ] **Step 4: Implement validation and complete metadata.**

  Require exact ID/direction/size/digest agreement, permitted ordering, both-side reception, realized idle/burst counts, and no unplanned reconnect.

- [ ] **Step 5: Run unit tests.**

  Run: `python3 -m unittest tests.test_traffic_messaging tests.test_traffic_foundation -v`

- [ ] **Step 6: Run the real privileged Messaging integration.**

  Run: `sudo env IPSEC_SENTINEL_DATASET_INTEGRATION=1 python3 -m unittest tests.test_dataset_integration.DatasetIntegrationTest.test_real_messaging_dataset_run -v`

- [ ] **Step 7: Stop-on-failure review and commit.**

  Inspect both ledgers and ESP capture, then commit:  
  `git add ipsec_sentinel/traffic tests && git commit -m "feat: add seeded messaging traffic"`

**Failure gate / rollback:** Do not accept a one-direction-only run. Stop before File Transfer if either endpoint ledger is incomplete.

### Task 7: Implement and prove sustained File Transfer

**Goal:** Add checksum-verified bulk TCP transfer behavior that is distinct from segmented Video.

**Files:**
- Create: `ipsec_sentinel/traffic/file_transfer.py`
- Create: `ipsec_sentinel/traffic/file_transfer_peer.py`
- Modify: `ipsec_sentinel/traffic/__init__.py`
- Create: `tests/test_traffic_file_transfer.py`
- Modify: `tests/test_dataset_integration.py`

**Interfaces:**
- Produces: `FileTransferPlan`, `resolve_file_transfer_plan(seed)`, and `FileTransferGenerator`
- Directions: `upload`, `download`, or bounded `bidirectional`; payload size approximately 1-8 MiB in smoke

- [ ] **Step 1: Write failing plan, deterministic content, checksum, direction, and distinction tests.**

  Assert variation in total size, direction, write/chunk sizes, grouping, and bounded gaps. Assert the plan has no Video segment sequence or playback pacing.

- [ ] **Step 2: Run File Transfer tests and confirm failure.**

  Run: `python3 -m unittest tests.test_traffic_file_transfer -v`

- [ ] **Step 3: Implement sustained transfer peers.**

  Generate content incrementally from the seed, stream according to write grouping, avoid materializing unnecessary duplicate files, and exchange expected length/SHA-256 control frames.

- [ ] **Step 4: Implement exact integrity validation and metadata.**

  Require expected bytes in every direction, sender/receiver SHA-256 equality, successful completion frames, and recorded realized duration/write counts.

- [ ] **Step 5: Run unit tests.**

  Run: `python3 -m unittest tests.test_traffic_file_transfer tests.test_traffic_foundation -v`

- [ ] **Step 6: Run the real privileged File Transfer integration.**

  Run: `sudo env IPSEC_SENTINEL_DATASET_INTEGRATION=1 python3 -m unittest tests.test_dataset_integration.DatasetIntegrationTest.test_real_file_transfer_dataset_run -v`

- [ ] **Step 7: Execute Checkpoint B and commit.**

  Confirm all four new supervised integrations independently pass, all parameters are recorded, and different seeds vary meaningful behavior.  
  Commit: `git add ipsec_sentinel/traffic tests && git commit -m "feat: add seeded file transfer traffic"`

**Failure gate / rollback:** A matching byte count without matching digest is failure. Do not proceed to OOD until Checkpoint B passes.

### Task 8: Implement and prove `remote_desktop_like` OOD

**Goal:** Add an accurately named evaluation-only interactive input/update behavioral workload.

**Files:**
- Create: `ipsec_sentinel/traffic/remote_desktop_like.py`
- Create: `ipsec_sentinel/traffic/remote_desktop_peer.py`
- Modify: `ipsec_sentinel/traffic/__init__.py`
- Create: `tests/test_traffic_remote_desktop_like.py`
- Modify: `tests/test_dataset_integration.py`

**Interfaces:**
- Produces: `RemoteDesktopLikePlan`, `resolve_remote_desktop_like_plan(seed)`, `RemoteDesktopLikeGenerator`
- Registry role: `known_training_class=False`

- [ ] **Step 1: Write failing behavioral, metadata, and OOD-role tests.**

  Assert seeded input clusters, irregular update bursts, idle gaps, direction ratios, and occasional large updates vary; metadata must state this is a controlled simulation, not RDP/VNC.

- [ ] **Step 2: Run focused tests and confirm failure.**

  Run: `python3 -m unittest tests.test_traffic_remote_desktop_like tests.test_traffic_contract -v`

- [ ] **Step 3: Implement the request/update workload through shared framing/process/port helpers.**

  Client input events trigger zero or more server update frames; both ledgers record IDs, relationship, direction, size, and digest.

- [ ] **Step 4: Implement validation and OOD metadata.**

  Require exact planned input/update relationships, both directional delivery, seeded timing evidence, `known_training_class=False`, and `behavioral_simulation=True`.

- [ ] **Step 5: Run the real privileged integration.**

  Run: `sudo env IPSEC_SENTINEL_DATASET_INTEGRATION=1 python3 -m unittest tests.test_dataset_integration.DatasetIntegrationTest.test_real_remote_desktop_like_dataset_run -v`

- [ ] **Step 6: Verify exclusion and commit.**

  Assert the run appears in OOD quality summaries, not supervised distributions or `supervised_ready_attempts()`.  
  Commit: `git add ipsec_sentinel/traffic tests && git commit -m "feat: add remote-desktop-like OOD traffic"`

**Failure gate / rollback:** A PASS OOD run found by the supervised selector blocks all later work.

### Task 9: Implement and prove `database_query_like` OOD

**Goal:** Add an evaluation-only persistent query/response behavioral workload and complete the OOD exclusion checkpoint.

**Files:**
- Create: `ipsec_sentinel/traffic/database_query_like.py`
- Create: `ipsec_sentinel/traffic/database_peer.py`
- Modify: `ipsec_sentinel/traffic/__init__.py`
- Create: `tests/test_traffic_database_query_like.py`
- Modify: `tests/test_dataset_integration.py`
- Modify: `tests/test_dataset_validation.py`

**Interfaces:**
- Produces: `DatabaseQueryLikePlan`, `resolve_database_query_like_plan(seed)`, `DatabaseQueryLikeGenerator`
- Registry role: `known_training_class=False`

- [ ] **Step 1: Write failing plan, request/result, ledger, and exclusion tests.**

  Vary query count, request size, response rows, row sizes, transaction groups, think time, and occasional large result sets.

- [ ] **Step 2: Run focused tests and confirm failure.**

  Run: `python3 -m unittest tests.test_traffic_database_query_like tests.test_dataset_validation -v`

- [ ] **Step 3: Implement the persistent framed query/response workload.**

  Each deterministic query ID produces the planned response frames and digests; metadata explicitly disclaims a specific database wire protocol.

- [ ] **Step 4: Implement strict relationship and role validation.**

  Require every query and response-row total, byte count, digest, transaction boundary, and `known_training_class=False` to agree across plan, peer ledger, artifacts, manifest, and registry.

- [ ] **Step 5: Run both OOD privileged integrations and selection checks.**

  Run: `sudo env IPSEC_SENTINEL_DATASET_INTEGRATION=1 python3 -m unittest tests.test_dataset_integration.DatasetIntegrationTest.test_real_remote_desktop_like_dataset_run tests.test_dataset_integration.DatasetIntegrationTest.test_real_database_query_like_dataset_run -v`

- [ ] **Step 6: Execute Checkpoint C.**

  Create a two-OOD test matrix, validate both runs as quality-ready, and prove supervised count is zero. Tamper each role source in turn and confirm offline validation fails.

- [ ] **Step 7: Commit the completed OOD layer.**

  Commit: `git add ipsec_sentinel/traffic tests && git commit -m "feat: add database-like OOD traffic"`

**Failure gate / rollback:** Do not start scenario work until both OOD integrations pass and structural exclusion is independently proven.

### Task 10: Generalize the allowlisted scenario and evidence foundation

**Goal:** Remove baseline-only proposal assumptions while immediately proving Phase 1 remains backward-compatible.

**Files:**
- Modify: `ipsec_sentinel/scenario.py`
- Modify: `ipsec_sentinel/strongswan.py`
- Modify: `ipsec_sentinel/evidence.py`
- Modify: `ipsec_sentinel/models.py`
- Modify: `ipsec_sentinel/session.py`
- Modify: `ipsec_sentinel/runner.py`
- Modify: `ipsec_sentinel/dataset/runner.py`
- Modify: `ipsec_sentinel/dataset/artifacts.py`
- Modify: `ipsec_sentinel/dataset/matrix.py`
- Modify: `ipsec_sentinel/dataset/manifest.py`
- Create: `scenarios/aes128-gcm.yaml`
- Create: `scenarios/aes256-cbc.yaml`
- Create: `scenarios/no-pfs.yaml`
- Modify: `tests/test_scenario.py`
- Modify: `tests/test_strongswan.py`
- Modify: `tests/test_evidence.py`
- Modify: `tests/test_session.py`
- Modify: `tests/test_runner.py`

**Interfaces:**
- Produces: `ScenarioDefinition(id, path, version, digest, expected_ike, expected_esp, child_dh_group, pfs_enabled)`
- Produces: `scenario_definition(id) -> ScenarioDefinition`, `scenario_ids() -> tuple[str, ...]`
- Changes: `StrongSwanPair.render_configs(run_dir, scenario)` and `start(run_dir, scenario)`
- Produces: scenario-aware `evaluate_tunnel(..., expectation)` and `evaluate_rekey_policy(..., expectation)`

- [ ] **Step 1: Write failing allowlist, rendering, normalization, and backward-compatibility tests.**

  Assert the exact four IDs/proposals, fixed networks/mode/IKEv2, ECP-384 for all PFS-enabled CHILD proposals, and no CHILD DH group for `no-pfs`. Reject arbitrary YAML paths/IDs/proposals.

- [ ] **Step 2: Run focused tests and confirm hardcoded failures.**

  Run: `python3 -m unittest tests.test_scenario tests.test_strongswan tests.test_evidence tests.test_session tests.test_runner -v`

- [ ] **Step 3: Implement scenario definitions and parameterized rendering.**

  ```python
  SCENARIOS = {
      "secure-baseline": ScenarioDefinition(..., "aes256gcm16-prfsha384-ecp384",
                                            "aes256gcm16-ecp384", "ECP_384", True),
      "aes128-gcm": ScenarioDefinition(..., "aes128gcm16-prfsha384-ecp384",
                                       "aes128gcm16-ecp384", "ECP_384", True),
      "aes256-cbc": ScenarioDefinition(..., "aes256-sha256-prfsha384-ecp384",
                                       "aes256-sha256-ecp384", "ECP_384", True),
      "no-pfs": ScenarioDefinition(..., "aes256gcm16-prfsha384-ecp384",
                                   "aes256gcm16", None, False),
  }
  ```

  Hash the checked-in scenario bytes for the definition digest, carry it through `MatrixSlot`/`AttemptPlan`, and replace the manifest compatibility sentinel for newly initialized matrices. Preserve separate VICI/runtime/config paths.

- [ ] **Step 4: Generalize SA/XFRM parsing without weakening identity/selectors/SPI checks.**

  Extend parsed evidence with encryption, key size, integrity, PRF, IKE DH, CHILD DH, and XFRM AEAD/auth details. Compare normalized observed values to the selected definition; do not special-case only GCM.

- [ ] **Step 5: Generalize rekey evidence semantics.**

  Add `fresh_dh_observed` to observed PFS evidence. Every scenario requires completed reciprocal SPI replacement and refreshed XFRM correlation; PFS-enabled expects its CHILD DH group, while no-PFS expects no CHILD DH selection.

- [ ] **Step 6: Preserve Phase 1 public behavior and run all ordinary tests.**

  `run_secure_baseline("secure-baseline", ...)` retains its signature, output filenames, and PASS semantics.  
  Run: `python3 -m unittest discover -s tests -v`

- [ ] **Step 7: Run the privileged secure-baseline regression immediately.**

  Run: `sudo env IPSEC_SENTINEL_INTEGRATION=1 python3 -m unittest tests.test_secure_baseline_integration -v`  
  Run: `sudo env IPSEC_SENTINEL_DATASET_INTEGRATION=1 python3 -m unittest tests.test_dataset_integration.DatasetIntegrationTest.test_real_icmp_dataset_run -v`

- [ ] **Step 8: Review configured-versus-observed artifacts and commit.**

  Confirm baseline IKE/CHILD/XFRM/ESP/PFS evidence is unchanged in meaning and new definition digest/version fields are present.  
  Commit: `git add ipsec_sentinel scenarios tests && git commit -m "refactor: make IPsec evidence scenario-aware"`

**Failure gate / rollback:** Stop before validating new ciphers if Phase 1 or secure-baseline dataset integration regresses. This task may not alter the topology or weaken the strict PCAP parser.

### Task 11: Validate `aes128-gcm` independently

**Goal:** Prove AES-128-GCM changes encryption strength only while retaining ECP-384 CHILD PFS.

**Files:**
- Modify: `tests/test_dataset_integration.py`
- Modify: `tests/test_evidence.py` only if the real normalized output exposes a documented parser defect

**Interfaces:** Uses the scenario registry and ICMP generator through the common lifecycle.

- [ ] **Step 1: Add the failing privileged scenario test.**

  ```python
  def test_real_aes128_gcm_icmp_dataset_run(self):
      run_dir, truth = self.run_case("icmp", "aes128-gcm", "clean", 5101)
      self.assertEqual(truth["ipsec"]["configured"]["esp_proposal"],
                       "aes128gcm16-ecp384")
      self.assertEqual(truth["ipsec"]["observed"]["pfs"]["fresh_dh_observed"], True)
  ```

- [ ] **Step 2: Run only this privileged test and preserve failure evidence.**

  Run: `sudo env IPSEC_SENTINEL_DATASET_INTEGRATION=1 python3 -m unittest tests.test_dataset_integration.DatasetIntegrationTest.test_real_aes128_gcm_icmp_dataset_run -v`

- [ ] **Step 3: If needed, fix only concrete normalization/rendering defects exposed by real evidence.**

  Do not change ECP-384 to ECP-256 unless the installed environment produces a reproducible compatibility failure; if that occurs, stop and document it for design review instead of silently changing policy.

- [ ] **Step 4: Re-run the focused privileged test and inspect artifacts.**

  Require accepted proposal, established IKE/CHILD SAs, normalized AES-128 observation, reciprocal XFRM/SPI state, protected ICMP, ESP capture, rekeyed SPIs, fresh ECP-384 selection, and strict capture separation.

- [ ] **Step 5: Re-run secure baseline and commit.**

  Run: `sudo env IPSEC_SENTINEL_DATASET_INTEGRATION=1 python3 -m unittest tests.test_dataset_integration.DatasetIntegrationTest.test_real_icmp_dataset_run tests.test_dataset_integration.DatasetIntegrationTest.test_real_aes128_gcm_icmp_dataset_run -v`  
  Commit: `git add tests ipsec_sentinel && git commit -m "test: validate AES-128-GCM IPsec scenario"`

**Failure gate / rollback:** Do not continue to CBC until the AES-128 scenario independently passes every evidence layer.

### Task 12: Validate `aes256-cbc` independently

**Goal:** Prove AES-256-CBC plus HMAC-SHA-256 and ECP-384 CHILD PFS through SA and XFRM evidence.

**Files:**
- Modify: `tests/test_dataset_integration.py`
- Modify: `tests/test_evidence.py` only for source-proven CBC/auth parsing corrections

**Interfaces:** Uses generic algorithm normalization introduced in Task 10.

- [ ] **Step 1: Add failing CBC unit fixtures and privileged integration assertion.**

  Fixture assertions must require `AES_CBC_256`, `HMAC_SHA2_256_128`, `PRF_HMAC_SHA2_384`, and `ECP_384`; XFRM must contain both encryption and authentication algorithms.

- [ ] **Step 2: Run focused unit tests.**

  Run: `python3 -m unittest tests.test_evidence tests.test_strongswan -v`

- [ ] **Step 3: Run the real CBC ICMP scenario.**

  Run: `sudo env IPSEC_SENTINEL_DATASET_INTEGRATION=1 python3 -m unittest tests.test_dataset_integration.DatasetIntegrationTest.test_real_aes256_cbc_icmp_dataset_run -v`

- [ ] **Step 4: Inspect and reconcile configured-versus-observed values.**

  Correct normalization only when raw swanctl/XFRM evidence proves the parser wrong. Require real protocol-50 ESP and fresh ECP-384 on CHILD rekey.

- [ ] **Step 5: Re-run AES-128, CBC, and baseline serially.**

  Run: `sudo env IPSEC_SENTINEL_DATASET_INTEGRATION=1 python3 -m unittest tests.test_dataset_integration.DatasetIntegrationTest.test_real_icmp_dataset_run tests.test_dataset_integration.DatasetIntegrationTest.test_real_aes128_gcm_icmp_dataset_run tests.test_dataset_integration.DatasetIntegrationTest.test_real_aes256_cbc_icmp_dataset_run -v`

- [ ] **Step 6: Commit the independently validated CBC scenario.**

  Commit: `git add tests ipsec_sentinel && git commit -m "test: validate AES-CBC IPsec scenario"`

**Failure gate / rollback:** Do not continue to no-PFS if integrity or XFRM authentication evidence is ambiguous.

### Task 13: Validate `no-pfs` and absence semantics independently

**Goal:** Positively prove successful CHILD rekey/SPI replacement with no CHILD-SA DH exchange.

**Files:**
- Modify: `tests/test_evidence.py`
- Modify: `tests/test_dataset_validation.py`
- Modify: `tests/test_dataset_integration.py`
- Modify: `ipsec_sentinel/dataset/validation.py`

**Interfaces:** `PfsObservation.status="VERIFIED"` means policy matched; `fresh_dh_observed` records the observed behavior separately.

- [ ] **Step 1: Write failing no-PFS policy tests.**

  ```python
  observed = evaluate_rekey_policy(no_pfs_definition, before, after, no_dh_log,
                                   before_xfrm, after_xfrm)
  self.assertEqual(observed.status, "VERIFIED")
  self.assertTrue(observed.rekey_observed)
  self.assertFalse(observed.fresh_dh_observed)
  ```

  Also assert unchanged SPIs, failed rekey, missing XFRM replacement, or an unexpected CHILD DH selection fails verification.

- [ ] **Step 2: Run focused unit/offline validation tests.**

  Run: `python3 -m unittest tests.test_evidence tests.test_dataset_validation -v`

- [ ] **Step 3: Remove the validator’s unconditional fresh-DH assumption.**

  Offline validation compares configured `pfs` policy to observed `status`, `rekey_observed`, and `fresh_dh_observed`; it requires fresh DH only for PFS-enabled definitions.

- [ ] **Step 4: Run the real no-PFS ICMP integration.**

  Run: `sudo env IPSEC_SENTINEL_DATASET_INTEGRATION=1 python3 -m unittest tests.test_dataset_integration.DatasetIntegrationTest.test_real_no_pfs_icmp_dataset_run -v`

- [ ] **Step 5: Inspect raw rekey artifacts.**

  Confirm before/after swanctl and XFRM SPIs changed reciprocally, CHILD proposal omitted DH, rekey log lacks CHILD DH selection, protected ICMP succeeded, and both PCAP roles remain correct.

- [ ] **Step 6: Execute Checkpoint D.**

  Run all four scenario ICMP integrations serially. Stop if configured/observed normalization, SPI/XFRM correlation, or PFS policy agreement fails for any scenario.

- [ ] **Step 7: Commit scenario completion.**

  Commit: `git add ipsec_sentinel tests && git commit -m "feat: verify disabled CHILD PFS policy"`

**Failure gate / rollback:** Never represent “no fresh DH” as success unless SPI replacement, XFRM replacement, and explicit no-PFS configuration all agree.

### Task 14: Add network-profile registry and prove `moderate_latency`

**Goal:** Introduce deterministic, verified, idempotent netem lifecycle and move impairment into the approved lifecycle position.

**Files:**
- Modify: `ipsec_sentinel/dataset/network.py`
- Modify: `ipsec_sentinel/dataset/runner.py`
- Modify: `ipsec_sentinel/dataset/models.py`
- Modify: `ipsec_sentinel/dataset/artifacts.py`
- Modify: `ipsec_sentinel/dataset/matrix.py`
- Modify: `ipsec_sentinel/dataset/manifest.py`
- Create: `tests/test_dataset_network.py`
- Modify: `tests/test_dataset_runner.py`
- Modify: `tests/test_dataset_integration.py`

**Interfaces:**
- Produces: `NetworkProfileContext(log, seed, targets=(("ips-gwa", "wan0"), ("ips-gwb", "wan0")))`
- Produces: `NetworkProfileSpec(name, version, parameters, factory)`
- Produces: `create_network_profile(name, seed)`
- Profile contract: `apply(context)`, `verify(context)`, `cleanup(context)`, `metadata()`

- [ ] **Step 1: Write failing command, readback, stage-order, and idempotent-cleanup tests.**

  Assert `moderate_latency` renders symmetric `delay 50ms`, applies only to both gateway `wan0` interfaces, rejects malformed readback, and tolerates repeated cleanup.

- [ ] **Step 2: Run focused tests and confirm failure.**

  Run: `python3 -m unittest tests.test_dataset_network tests.test_dataset_runner -v`

- [ ] **Step 3: Implement the allowlisted profile registry and clean verification.**

  `clean` actively reads both qdiscs and fails on netem. Before any non-clean apply, remove an exact `root` qdisc from each target, ignoring only the documented “not found” result. Carry the selected profile version through `MatrixSlot`/`AttemptPlan` into the manifest.

- [ ] **Step 4: Implement deterministic moderate latency with readback evidence.**

  Use `tc qdisc replace dev wan0 root netem delay 50ms seed <derived>` where supported by the installed netem syntax. Persist profile/version/normalized parameters, seed, targets, commands, apply/readback/removal timestamps, raw readback, and cleanup result.

- [ ] **Step 5: Reorder the attempt lifecycle.**

  Start full capture before IKE; establish and verify initial SA/XFRM; apply/verify profile; prepare service; run/validate workload; remove/verify profile; then perform rekey. Final cleanup calls profile cleanup again.

- [ ] **Step 6: Run unit and real moderate-latency integration.**

  Run: `python3 -m unittest tests.test_dataset_network tests.test_dataset_runner -v`  
  Run: `sudo env IPSEC_SENTINEL_DATASET_INTEGRATION=1 python3 -m unittest tests.test_dataset_integration.DatasetIntegrationTest.test_real_moderate_latency_icmp_dataset_run -v`

- [ ] **Step 7: Run a following clean integration and inspect qdisc state.**

  The clean run must begin and end with no netem on either gateway; no impairment may affect rekey or a later attempt.

- [ ] **Step 8: Commit the profile foundation.**

  Commit: `git add ipsec_sentinel tests && git commit -m "feat: add verified latency network profile"`

**Failure gate / rollback:** Any apply/readback disagreement is a failed attempt; cleanup still runs. Stop before jitter/loss if either gateway retains a qdisc.

### Task 15: Add deterministic `jitter_loss` and cross-run leakage coverage

**Goal:** Add the final realistic impairment profile and prove profile isolation across interrupted/failed runs.

**Files:**
- Modify: `ipsec_sentinel/dataset/network.py`
- Modify: `tests/test_dataset_network.py`
- Modify: `tests/test_dataset_integration.py`

**Interfaces:** `jitter_loss` parameters are `delay 25ms 5ms distribution normal loss random 0.5%` plus recorded netem seed.

- [ ] **Step 1: Write failing parameter, seed, readback, and interrupted-cleanup tests.**

  Assert same run seed produces the same netem seed/commands, different seeds vary netem seed, and a failure after apply still deletes qdiscs on both gateways.

- [ ] **Step 2: Run focused tests and confirm failure.**

  Run: `python3 -m unittest tests.test_dataset_network tests.test_dataset_runner -v`

- [ ] **Step 3: Implement `jitter_loss` through the existing profile contract.**

  Parse `tc qdisc show` semantically rather than comparing unstable formatting; require delay, jitter, distribution, loss model/rate, and seed agreement where the kernel reports it.

- [ ] **Step 4: Run the real jitter/loss integration.**

  Run: `sudo env IPSEC_SENTINEL_DATASET_INTEGRATION=1 python3 -m unittest tests.test_dataset_integration.DatasetIntegrationTest.test_real_jitter_loss_icmp_dataset_run -v`

- [ ] **Step 5: Run explicit leakage sequence.**

  Execute jitter/loss success → injected workload failure → clean success. After each attempt and before the clean run, query both gateway qdiscs and assert no stale netem.

- [ ] **Step 6: Execute Checkpoint E and commit.**

  Confirm clean, moderate latency, and jitter/loss independently pass, metadata records exact actual parameters, and clean state follows each.  
  Commit: `git add ipsec_sentinel tests && git commit -m "feat: add deterministic jitter-loss profile"`

**Failure gate / rollback:** If the installed kernel’s readback cannot prove the requested semantics, stop and document the concrete output; do not relax verification or substitute extreme values.

### Task 16: Complete matrix expansion, fingerprints, CLI choices, and checked-in configs

**Goal:** Support supervised Cartesian, separate OOD Cartesian, and mutually exclusive explicit-case matrices while retaining deterministic IDs/resume.

**Files:**
- Modify: `ipsec_sentinel/dataset/config.py`
- Modify: `ipsec_sentinel/dataset/matrix.py`
- Modify: `ipsec_sentinel/dataset/manifest.py`
- Modify: `ipsec_sentinel/dataset/runner.py`
- Modify: `ipsec_sentinel/dataset/cli.py`
- Create: `configs/datasets/extension-smoke-v1.yaml`
- Create: `configs/datasets/cipherlens-v1.yaml`
- Modify: `tests/test_dataset_config.py`
- Modify: `tests/test_dataset_matrix.py`
- Modify: `tests/test_dataset_cli.py`
- Modify: `tests/test_dataset_runner.py`

**Interfaces:**
- Produces: `ExplicitCase(traffic_class, scenario_id, network_profile, repetitions)`
- `expand_matrix()` returns deterministic slots carrying role and definition versions/digests
- Fingerprint covers normalized selectors, roles, generator versions, scenario definitions, profile definitions, seed policy, and exact slots

- [ ] **Step 1: Write failing 420+72, exact-11, and rejection tests.**

  Assert the bulk config expands to 492 slots: 420 supervised and 72 OOD. Assert the smoke expands to exactly the 11 specification rows in order. Reject mixed explicit/Cartesian configuration and all unknown/mis-role IDs.

- [ ] **Step 2: Run matrix/config tests and confirm failure.**

  Run: `python3 -m unittest tests.test_dataset_config tests.test_dataset_matrix tests.test_dataset_cli -v`

- [ ] **Step 3: Implement explicit-case expansion and complete Cartesian expansion.**

  Slot IDs remain `run_%06d`; ordinals follow declared order; attempt seeds remain derived from base seed + ordinal + attempt number. Role always comes from the registry.

- [ ] **Step 4: Strengthen fingerprint inputs.**

  Include scenario file digest/version, profile version/parameters, traffic roles/versions, both run counts, explicit cases, dataset/schema versions, and `SEED_DERIVATION_VERSION`. A changed input must make `--resume` fail before mutation.

- [ ] **Step 5: Update CLI dynamic choices and preserve existing commands.**

  Keep `generate <config> --resume`, `validate <root>`, and one-off `run`; populate traffic/scenario/profile choices from registries instead of literals.

- [ ] **Step 6: Re-run manifest/resume/fingerprint tests.**

  Run: `python3 -m unittest tests.test_dataset_config tests.test_dataset_matrix tests.test_dataset_manifest tests.test_dataset_runner tests.test_dataset_cli -v`

- [ ] **Step 7: Review both configs without generating bulk data and commit.**

  Run: `python3 -m ipsec_sentinel.dataset list-traffic`  
  Run a dry matrix-inspection test, not collection.  
  Commit: `git add ipsec_sentinel configs tests && git commit -m "feat: expand resumable dataset matrices"`

**Failure gate / rollback:** Never point the interactive run at `cipherlens-v1.yaml`. A fingerprint mismatch must leave SQLite and attempt directories untouched.

### Task 17: Add accidental-shortcut audit and dataset-quality reporting

**Goal:** Detect obvious laboratory fingerprints before bulk generation without building ML features or a model.

**Files:**
- Create: `ipsec_sentinel/dataset/audit.py`
- Modify: `ipsec_sentinel/dataset/cli.py`
- Modify: `ipsec_sentinel/dataset/models.py`
- Modify: `ipsec_sentinel/dataset/runner.py`
- Modify: `ipsec_sentinel/dataset/artifacts.py`
- Modify: `ipsec_sentinel/dataset/validation.py`
- Create: `tests/test_dataset_audit.py`
- Modify: `tests/test_dataset_validation.py`

**Interfaces:**
- Produces: `ShortcutFinding(code, severity, classes, evidence, mitigation)`
- Produces: `ShortcutAuditReport(passed, findings, distributions)`
- Produces: `audit_dataset(dataset_root) -> ShortcutAuditReport`
- CLI: `python3 -m ipsec_sentinel.dataset audit <dataset_root>`

- [ ] **Step 1: Write failing synthetic audit fixtures.**

  Construct fixtures for fixed class ports, class-specific addresses, invariant/disjoint durations, invariant payload sizes, fixed directionality, fixed packet counts, startup/rekey timing patterns, scenario imbalance, and profile imbalance; assert named findings.

- [ ] **Step 2: Run audit tests and confirm failure.**

  Run: `python3 -m unittest tests.test_dataset_audit -v`

- [ ] **Step 3: Record dataset-only lifecycle timings.**

  Add dataset `StageTiming(name, started_unix_ns, finished_unix_ns, duration_ns)` for tunnel establishment, service preparation/readiness, workload, profile apply/remove, and rekey. Do not alter the shared Phase 1 `StageRecord` contract.

- [ ] **Step 4: Implement deterministic descriptive checks.**

  Report, but do not ML-score: per-class uniqueness/ranges for ports, IPs, durations, payload fields, direction signatures, packet counts, relative startup/tunnel/rekey timings, and class × scenario × profile session counts. Hard failures are role leakage, class-specific addresses, fixed class ports, or missing dimensions; statistical warnings remain documented review items.

- [ ] **Step 5: Integrate audit output with validation artifacts.**

  Write `shortcut_audit.json` atomically. Dataset validation requires no hard findings for the extension smoke; warnings must include explicit mitigation/justification.

- [ ] **Step 6: Run focused and full ordinary tests.**

  Run: `python3 -m unittest tests.test_dataset_audit tests.test_dataset_validation -v`  
  Run: `python3 -m unittest discover -s tests -v`

- [ ] **Step 7: Review scope and commit.**

  Confirm the audit reads metadata and summaries only and creates no feature table, training split, or model.  
  Commit: `git add ipsec_sentinel tests && git commit -m "feat: audit dataset shortcut risks"`

**Failure gate / rollback:** A hard shortcut finding blocks smoke acceptance and bulk recommendation. Do not “fix” natural class behavior by equalizing raw packet counts.

### Task 18: Run the exact extension smoke, full regression, documentation, and final review

**Goal:** Prove the complete expansion and leave the resumable bulk command without generating the bulk dataset.

**Files:**
- Modify: `README.md`
- Create: `docs/evidence/dataset-expansion-smoke.md`
- Modify: `tests/test_dataset_integration.py`
- No committed PCAP/dataset directories

**Interfaces:** Uses `configs/datasets/extension-smoke-v1.yaml` and `configs/datasets/cipherlens-v1.yaml`.

- [ ] **Step 1: Add final smoke validator assertions before collection.**

  Assert exactly 11 independent successful slots, expected supervised/OOD distributions, non-empty ESP captures, strict ML capture roles, workload ledger agreement, algorithm/PFS policy agreement, profile cleanup, meaningful seeded variation, and manifest/summary/filesystem agreement.

- [ ] **Step 2: Run the exact 11-session extension smoke once.**

  Run: `sudo python3 -m ipsec_sentinel.dataset generate configs/datasets/extension-smoke-v1.yaml`  
  Do not add Web/Video sessions to this matrix; their real integrations run separately.

- [ ] **Step 3: Validate, audit, and test resume without regeneration.**

  Run: `sudo python3 -m ipsec_sentinel.dataset validate dataset/cipherlens-extension-smoke-v1`  
  Run: `sudo python3 -m ipsec_sentinel.dataset audit dataset/cipherlens-extension-smoke-v1`  
  Snapshot run directories and manifest attempts, then run:  
  `sudo python3 -m ipsec_sentinel.dataset generate configs/datasets/extension-smoke-v1.yaml --resume`  
  Assert no successful run directory or attempt row was added/changed.

- [ ] **Step 4: Demonstrate retry/failure preservation without enlarging the smoke.**

  Use the existing injected-failure privileged integration, not another smoke slot, to prove FAILED → new attempt, preserved failed directory/diagnostics, separate cleanup result, and successful resume.

- [ ] **Step 5: Run Checkpoint F inspection.**

  Record per-class session, ESP packet, byte, and duration counts; capture size; sample seed variation; OOD roles; configured/observed algorithms; PFS/no-PFS evidence; zero IKE/UDP4500/non-ESP in every ML capture; and no namespace/socket/qdisc/XFRM residue.

- [ ] **Step 6: Run the complete ordinary and privileged regression suite (Checkpoint G).**

  Run: `python3 -m unittest discover -s tests -v`  
  Run: `sudo env IPSEC_SENTINEL_INTEGRATION=1 python3 -m unittest tests.test_secure_baseline_integration -v`  
  Run: `sudo env IPSEC_SENTINEL_DATASET_INTEGRATION=1 python3 -m unittest tests.test_dataset_integration -v`

- [ ] **Step 7: Perform the raw-diff/source leakage review.**

  Ask whether classification could be driven by fixed ports, class addresses, durations, service startup, tunnel/rekey timing, payload sizes, direction patterns, packet counts, scenario/profile imbalance, labels/metadata, or capture boundaries. Fix obvious shortcuts; document unavoidable semantic differences.

- [ ] **Step 8: Update operator documentation and smoke evidence.**

  Document generator disclosures, role invariant, proposals/PFS semantics, netem lifecycle, exact commands, smoke statistics, leakage findings, known limitations, and runtime/storage estimates derived from observed samples.

- [ ] **Step 9: Verify the future bulk matrix without executing it.**

  Confirm config expansion is 420 supervised + 72 OOD = 492 and retain this unattended command:

  ```bash
  sudo nohup python3 -m ipsec_sentinel.dataset generate \
    configs/datasets/cipherlens-v1.yaml --resume \
    > cipherlens-v1-generation.log 2>&1 &
  ```

- [ ] **Step 10: Run final diff/status checks and commit implementation.**

  Run: `git diff --check`  
  Run: `git status --short`  
  Commit only source/tests/config/docs—not generated datasets—with a reviewed Phase 3-ready message.

**Failure gate / rollback:** Any failed checkpoint blocks completion. Preserve all failed attempts; do not rerun or enlarge the smoke to hide a failure. Bulk generation remains unexecuted.

**Expected result:** Checkpoints F and G pass; the branch contains validated factory expansion, evidence, configs, and documentation only.

## 8. Test Strategy

### Test layers

1. **Pure deterministic planning:** every resolver, port candidate sequence, netem seed, matrix slot, and fingerprint.
2. **Protocol/unit validation:** RTP headers, SMTP dialogue/MIME receipts, framed ledgers, SHA-256 transfer integrity, OOD request/response relationships, proposal normalization, netem readback.
3. **State/persistence:** schema migration, role disagreement, state transitions, interruption recovery, retries, successful skip, exhaustion, immutable artifacts, fingerprint mismatch.
4. **Offline artifact validation:** manifest/JSON/registry agreement, strict PCAP parsing, configured-versus-observed policy, summaries, audit findings.
5. **Privileged real integration:** every new supervised generator, both OOD generators, every new scenario, every profile, existing ICMP/Web/Video, and Phase 1 baseline.
6. **Exact extension smoke:** eleven sessions only, followed by validation, audit, resume-no-op, and quality inspection.

### Mandatory checkpoint commands

All commands run from the repository root inside WSL2. Privileged commands require Linux root.

```bash
python3 -m unittest discover -s tests -v

sudo env IPSEC_SENTINEL_INTEGRATION=1 \
  python3 -m unittest tests.test_secure_baseline_integration -v

sudo env IPSEC_SENTINEL_DATASET_INTEGRATION=1 \
  python3 -m unittest tests.test_dataset_integration -v
```

The exact 11-session smoke is separate from existing Web/Video regression integrations; this resolves the apparent tension between “exactly 11 smoke sessions” and “prove existing ICMP/Web/Video paths” without changing the approved smoke.

## 9. Risk and Impact Analysis

| Risk | Impact | Control |
|---|---|---|
| OOD label enters supervised set | Invalid future evaluation | Registry-authoritative role, dual selector, four-way artifact/manifest validation |
| Shared runtime abstraction breaks Web/Video | Phase 2 regression | Task 3 immediate ordinary + privileged Checkpoint A |
| Service process leaks | Cross-run contamination/hangs | Bounded readiness, TERM/KILL, idempotent cleanup, namespace leak assertions |
| Generator fixed signature | Inflated classifier accuracy | Multi-dimensional seeded plans and Task 17 audit |
| Scenario normalization accepts wrong cipher/auth | False ground truth | Exact definition expectations plus swanctl and XFRM agreement |
| no-PFS absence is misreported | Incorrect security label | Require successful SPI/XFRM replacement and explicit absence of CHILD DH |
| netem remains active | Later label contamination | Remove before rekey, final idempotent cleanup, following-clean-run test |
| Manifest migration corrupts resume history | Lost/duplicated attempts | Transactional idempotent migration fixture and unchanged state-machine tests |
| Fingerprint omits behavior definition | Unsafe resume into changed matrix | Include roles, generator/scenario/profile versions/digests and exact slots |
| Exact smoke quietly grows | Excess session cost/confounded evidence | Explicit-case config count assertion equals 11 |
| Capture window leaks IKE/rekey | Training-data leakage | Existing strict parser plus per-run tcpdump/PCAP validation retained |
| Phase 1 models change incompatibly | Baseline regression | Dataset-only timing model; immediate Phase 1 gates after shared changes |

## 10. Files Expected to Change

| File/group | Symbols/responsibility | Reason |
|---|---|---|
| `ipsec_sentinel/traffic/base.py`, `traffic/__init__.py` | `TrafficClassSpec`, registry, allowlists | Authoritative supervised/OOD role |
| `traffic/ports.py`, `process.py`, `framing.py`, `payload.py`, `port_probe.py` | shared runtime primitives | Seeded collision-safe local services |
| `traffic/{voip,email,messaging,file_transfer}.py` and peer modules | new supervised generators | Four required classes |
| `traffic/{remote_desktop_like,database_query_like}.py` and peer modules | OOD generators | Evaluation-only behavioral workloads |
| `traffic/web.py`, `video.py`, `http_service.py` | shared ports/processes | Remove fixed-port shortcut, preserve semantics |
| `dataset/config.py`, `matrix.py` | Cartesian/OOD/explicit cases, fingerprint | Expanded deterministic matrix |
| `dataset/models.py`, `manifest.py` | schema v2 and role/definition persistence | Migration and resume correctness |
| `dataset/artifacts.py`, `summary.py`, `validation.py` | role/evidence persistence and agreement | Quality versus supervised eligibility |
| `dataset/network.py` | profile registry/netem lifecycle | Clean, latency, jitter/loss |
| `dataset/runner.py` | lifecycle order/timings/factories | Common capture/profile/scenario ownership |
| `dataset/audit.py`, `dataset/cli.py` | shortcut audit and registry-driven CLI | Pre-bulk leakage review |
| `scenario.py`, `strongswan.py`, `evidence.py`, `models.py`, `session.py` | scenario-aware rendering/evidence/rekey | Multiple ciphers and correct PFS semantics |
| `scenarios/*.yaml` | four allowlisted configurations | Reproducible scenario definitions |
| `configs/datasets/*.yaml` | exact smoke and future 492-session matrix | Safe bounded validation and unattended resume |
| `tests/test_*.py` | unit/state/offline/privileged gates | TDD and regression proof |
| `README.md`, `docs/evidence/dataset-expansion-smoke.md` | operations/evidence/limitations | Reviewable handoff |

## 11. Reusable Implementation Context

```yaml
implementation_context:
  task_summary: "Expand the validated Phase 2 factory with supervised/OOD traffic, allowlisted IPsec scenarios, netem profiles, exact smoke validation, and leakage audit while preserving Phase 1/2."
  acceptance_criteria:
    - "All Checkpoints A-G pass in dependency order."
    - "Seven supervised classes and two evaluation-only OOD workloads are role-safe."
    - "Four scenarios and three profiles have real evidence."
    - "Exactly 11 extension-smoke sessions are generated; 492-session bulk config is not executed."
    - "No feature extraction or model training is added."
  evidence_provenance:
    schema_version: 2
    head_commit: "d45c4ac6c2255e83a5f54c6902d4496f72914896"
    generated_plan_path: "docs/plans/2026-09-25-gitnexus-plan-dataset-expansion-implementation.md"
    global_dirty_digest:
      algorithm: "sha256"
      canonicalization: "gitnexus-evidence-provenance-v2 NUL-framed UTF-8 records"
      value: "0a9c85780067d9afcd0764f307b60891e3cee927ee11eaeb5ec7826d10fd82cd"
    cited_path_manifest:
      - {"path":"README.md","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:fd33d11868fe26d71b2a85fd69ed306542041467149f8ba5adec78574eb8b4b6","index_digest":"sha256:fd33d11868fe26d71b2a85fd69ed306542041467149f8ba5adec78574eb8b4b6","worktree_digest":"sha256:eda5e6098354c000e1cb93203d129ab4e0d113cfaaee2e66a21b8f8bbb6e86b5","untracked_digest":"absent"}
      - {"path":"configs/smoke-v1.yaml","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:ffa4085278ee54bdffaef61aafa19283c12abbd95308caadaa84d10be03e17cd","index_digest":"sha256:ffa4085278ee54bdffaef61aafa19283c12abbd95308caadaa84d10be03e17cd","worktree_digest":"sha256:ffa4085278ee54bdffaef61aafa19283c12abbd95308caadaa84d10be03e17cd","untracked_digest":"absent"}
      - {"path":"docs/superpowers/specs/2026-09-25-ipsec-sentinel-dataset-expansion-design.md","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:106523983550f6eb6ee482a6c2dc9a11d96328830b0f7f0f77c32623c576c79e","index_digest":"sha256:106523983550f6eb6ee482a6c2dc9a11d96328830b0f7f0f77c32623c576c79e","worktree_digest":"sha256:106523983550f6eb6ee482a6c2dc9a11d96328830b0f7f0f77c32623c576c79e","untracked_digest":"absent"}
      - {"path":"ipsec_sentinel/dataset/artifacts.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:29acf981313c7a1416939fc1e3590128da269eae12722d8420b6606a60340a4e","index_digest":"sha256:29acf981313c7a1416939fc1e3590128da269eae12722d8420b6606a60340a4e","worktree_digest":"sha256:29acf981313c7a1416939fc1e3590128da269eae12722d8420b6606a60340a4e","untracked_digest":"absent"}
      - {"path":"ipsec_sentinel/dataset/cli.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:6c68054e34c9d9c47970b84e8a8b7afc06d8f3ba551f905c415f738f432b6dfb","index_digest":"sha256:6c68054e34c9d9c47970b84e8a8b7afc06d8f3ba551f905c415f738f432b6dfb","worktree_digest":"sha256:6c68054e34c9d9c47970b84e8a8b7afc06d8f3ba551f905c415f738f432b6dfb","untracked_digest":"absent"}
      - {"path":"ipsec_sentinel/dataset/config.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:345c25c4f9c7b255d9da61921defac39dbb061ef6ea6e68966d0394ff976193b","index_digest":"sha256:345c25c4f9c7b255d9da61921defac39dbb061ef6ea6e68966d0394ff976193b","worktree_digest":"sha256:345c25c4f9c7b255d9da61921defac39dbb061ef6ea6e68966d0394ff976193b","untracked_digest":"absent"}
      - {"path":"ipsec_sentinel/dataset/manifest.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:8130fe892510f610adf833747460f64ddc3fdf8e8ce9196417cb22e0750bc0db","index_digest":"sha256:8130fe892510f610adf833747460f64ddc3fdf8e8ce9196417cb22e0750bc0db","worktree_digest":"sha256:8130fe892510f610adf833747460f64ddc3fdf8e8ce9196417cb22e0750bc0db","untracked_digest":"absent"}
      - {"path":"ipsec_sentinel/dataset/matrix.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:46f739ccbd02059295bde9966235f451ea4ab352c7df70f70d864f4c2e0e7228","index_digest":"sha256:46f739ccbd02059295bde9966235f451ea4ab352c7df70f70d864f4c2e0e7228","worktree_digest":"sha256:46f739ccbd02059295bde9966235f451ea4ab352c7df70f70d864f4c2e0e7228","untracked_digest":"absent"}
      - {"path":"ipsec_sentinel/dataset/models.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:efa45100098b06d97510a8e58c13390c1e552ab97e5eab513a9d507a1c2832c3","index_digest":"sha256:efa45100098b06d97510a8e58c13390c1e552ab97e5eab513a9d507a1c2832c3","worktree_digest":"sha256:efa45100098b06d97510a8e58c13390c1e552ab97e5eab513a9d507a1c2832c3","untracked_digest":"absent"}
      - {"path":"ipsec_sentinel/dataset/network.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:7d99d07564c0a27b94a2012ac9490821519a29895e12613356e5a2a2100fdec2","index_digest":"sha256:7d99d07564c0a27b94a2012ac9490821519a29895e12613356e5a2a2100fdec2","worktree_digest":"sha256:7d99d07564c0a27b94a2012ac9490821519a29895e12613356e5a2a2100fdec2","untracked_digest":"absent"}
      - {"path":"ipsec_sentinel/dataset/runner.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:7b58e37a028a510e495c494d814b1ae9616c35f793df4f133b032e2472447e20","index_digest":"sha256:7b58e37a028a510e495c494d814b1ae9616c35f793df4f133b032e2472447e20","worktree_digest":"sha256:7b58e37a028a510e495c494d814b1ae9616c35f793df4f133b032e2472447e20","untracked_digest":"absent"}
      - {"path":"ipsec_sentinel/dataset/summary.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:238eeecaa19cdd3c9e811e6c8cc06a9db2fabeab780ef6dab506f6b539cac6fc","index_digest":"sha256:238eeecaa19cdd3c9e811e6c8cc06a9db2fabeab780ef6dab506f6b539cac6fc","worktree_digest":"sha256:238eeecaa19cdd3c9e811e6c8cc06a9db2fabeab780ef6dab506f6b539cac6fc","untracked_digest":"absent"}
      - {"path":"ipsec_sentinel/dataset/validation.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:ac9d4fb66d9a55dbb030bbfe9d60dab84d5b984bd68859d08b8e7b38df01723d","index_digest":"sha256:ac9d4fb66d9a55dbb030bbfe9d60dab84d5b984bd68859d08b8e7b38df01723d","worktree_digest":"sha256:ac9d4fb66d9a55dbb030bbfe9d60dab84d5b984bd68859d08b8e7b38df01723d","untracked_digest":"absent"}
      - {"path":"ipsec_sentinel/evidence.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:cb8203a7365ca8e290ed6ca94990cafb02c24ce4e3a6bb8c3106c4a0bf19435e","index_digest":"sha256:cb8203a7365ca8e290ed6ca94990cafb02c24ce4e3a6bb8c3106c4a0bf19435e","worktree_digest":"sha256:908711e9cc63d2f7d2be8aa4364c40c68c6a51aa8b818157e2b57058a312b4b7","untracked_digest":"absent"}
      - {"path":"ipsec_sentinel/models.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:782fb491a8c1aa1a49afedf57dcf84465e454b73bba3bcd4d050b314b85fb637","index_digest":"sha256:782fb491a8c1aa1a49afedf57dcf84465e454b73bba3bcd4d050b314b85fb637","worktree_digest":"sha256:f7fd4944d882b6ccced1498a078f61046638599dc45f968da88cce5d4a1df403","untracked_digest":"absent"}
      - {"path":"ipsec_sentinel/pcap.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:02f0cf46258c115cbdbec3845504cd1b0a1e64b2387afc2eb6807a80ca3d1250","index_digest":"sha256:02f0cf46258c115cbdbec3845504cd1b0a1e64b2387afc2eb6807a80ca3d1250","worktree_digest":"sha256:02f0cf46258c115cbdbec3845504cd1b0a1e64b2387afc2eb6807a80ca3d1250","untracked_digest":"absent"}
      - {"path":"ipsec_sentinel/runner.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:d519fa908bd3b2dd5d8a91fb9a1709a610287e895b3f0a657953e15edab527b6","index_digest":"sha256:d519fa908bd3b2dd5d8a91fb9a1709a610287e895b3f0a657953e15edab527b6","worktree_digest":"sha256:d519fa908bd3b2dd5d8a91fb9a1709a610287e895b3f0a657953e15edab527b6","untracked_digest":"absent"}
      - {"path":"ipsec_sentinel/scenario.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:d8b633dedd18b3cbb8d2ebc7b70ff60ed9e260112854dabb06c8cf6161bb3b1b","index_digest":"sha256:d8b633dedd18b3cbb8d2ebc7b70ff60ed9e260112854dabb06c8cf6161bb3b1b","worktree_digest":"sha256:83f5eaaac822ee494466c54f2a17e354c9f751863033fa76db96876ae665f7a4","untracked_digest":"absent"}
      - {"path":"ipsec_sentinel/session.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:016b0f96630c7b4219f916271825d0fbce829ce90f26b0f5f6f00089b19d0dda","index_digest":"sha256:016b0f96630c7b4219f916271825d0fbce829ce90f26b0f5f6f00089b19d0dda","worktree_digest":"sha256:016b0f96630c7b4219f916271825d0fbce829ce90f26b0f5f6f00089b19d0dda","untracked_digest":"absent"}
      - {"path":"ipsec_sentinel/strongswan.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:0fd199eb7fd76c27817e2e42dc2d8c1d2b1cf6b5a36d4bccf5810f5720070e1d","index_digest":"sha256:0fd199eb7fd76c27817e2e42dc2d8c1d2b1cf6b5a36d4bccf5810f5720070e1d","worktree_digest":"sha256:513abb322d721a9a3cd172f7fce733ea1ee9be3ce4c761c829e99eafcc670546","untracked_digest":"absent"}
      - {"path":"ipsec_sentinel/topology.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:becedc448e74b6f2b0a47c3fb2e302425905414500b081cbfd33df0c8d138d2c","index_digest":"sha256:becedc448e74b6f2b0a47c3fb2e302425905414500b081cbfd33df0c8d138d2c","worktree_digest":"sha256:8b7cb8834988d75dd9a08f9a1e66cc539531fb4a6cc39bfe4e7b506570177dc3","untracked_digest":"absent"}
      - {"path":"ipsec_sentinel/traffic/__init__.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:67070d9d6c1daf1575fb2e90a78ad50506590e50e58215f858eec19a803195c7","index_digest":"sha256:67070d9d6c1daf1575fb2e90a78ad50506590e50e58215f858eec19a803195c7","worktree_digest":"sha256:67070d9d6c1daf1575fb2e90a78ad50506590e50e58215f858eec19a803195c7","untracked_digest":"absent"}
      - {"path":"ipsec_sentinel/traffic/base.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:a135183d456501dc80a0892ba040d1d1ce6d25f91cc98e4c207838bafe6edd10","index_digest":"sha256:a135183d456501dc80a0892ba040d1d1ce6d25f91cc98e4c207838bafe6edd10","worktree_digest":"sha256:a135183d456501dc80a0892ba040d1d1ce6d25f91cc98e4c207838bafe6edd10","untracked_digest":"absent"}
      - {"path":"ipsec_sentinel/traffic/http_service.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:801d45572f52be1f16544c6ef16f1d8c5e1c01a3ff8023258e3e33d598f8233d","index_digest":"sha256:801d45572f52be1f16544c6ef16f1d8c5e1c01a3ff8023258e3e33d598f8233d","worktree_digest":"sha256:801d45572f52be1f16544c6ef16f1d8c5e1c01a3ff8023258e3e33d598f8233d","untracked_digest":"absent"}
      - {"path":"ipsec_sentinel/traffic/video.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:c1c4ba05a610c80838092b9e5e64b94a2ec5e9a4a525dc6ef72f7a78cb7d776e","index_digest":"sha256:c1c4ba05a610c80838092b9e5e64b94a2ec5e9a4a525dc6ef72f7a78cb7d776e","worktree_digest":"sha256:c1c4ba05a610c80838092b9e5e64b94a2ec5e9a4a525dc6ef72f7a78cb7d776e","untracked_digest":"absent"}
      - {"path":"ipsec_sentinel/traffic/web.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:3d20917447f523e4c39707c3b2d175ae9861bdfb1a3c93adce3be75a8a8b7f7e","index_digest":"sha256:3d20917447f523e4c39707c3b2d175ae9861bdfb1a3c93adce3be75a8a8b7f7e","worktree_digest":"sha256:3d20917447f523e4c39707c3b2d175ae9861bdfb1a3c93adce3be75a8a8b7f7e","untracked_digest":"absent"}
      - {"path":"tests/test_dataset_config.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:a35ef005fcfec896eb41458f8093c4bdb74152e23f6b3a331236a8b4e462a93d","index_digest":"sha256:a35ef005fcfec896eb41458f8093c4bdb74152e23f6b3a331236a8b4e462a93d","worktree_digest":"sha256:a35ef005fcfec896eb41458f8093c4bdb74152e23f6b3a331236a8b4e462a93d","untracked_digest":"absent"}
      - {"path":"tests/test_dataset_integration.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:66b0a0c00ad46fb8d8b0b2c87db14ab80fbfd1f9d32628c3540456e2dfba8c7b","index_digest":"sha256:66b0a0c00ad46fb8d8b0b2c87db14ab80fbfd1f9d32628c3540456e2dfba8c7b","worktree_digest":"sha256:66b0a0c00ad46fb8d8b0b2c87db14ab80fbfd1f9d32628c3540456e2dfba8c7b","untracked_digest":"absent"}
      - {"path":"tests/test_dataset_manifest.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:6cc01f3fd7131bb568c47e12d66f7a40bdf0612f0e25784ff875fb0d2c2a2d69","index_digest":"sha256:6cc01f3fd7131bb568c47e12d66f7a40bdf0612f0e25784ff875fb0d2c2a2d69","worktree_digest":"sha256:6cc01f3fd7131bb568c47e12d66f7a40bdf0612f0e25784ff875fb0d2c2a2d69","untracked_digest":"absent"}
      - {"path":"tests/test_dataset_matrix.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:4684dd1679cfcabc0d1d98fb7fce72282409e72fc70c4ceef7faffe2909ccab7","index_digest":"sha256:4684dd1679cfcabc0d1d98fb7fce72282409e72fc70c4ceef7faffe2909ccab7","worktree_digest":"sha256:4684dd1679cfcabc0d1d98fb7fce72282409e72fc70c4ceef7faffe2909ccab7","untracked_digest":"absent"}
      - {"path":"tests/test_dataset_runner.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:d034f506c0db88997e2d6b9b3be31ee24991442a6fb08bea9f7abdcd5efe9a36","index_digest":"sha256:d034f506c0db88997e2d6b9b3be31ee24991442a6fb08bea9f7abdcd5efe9a36","worktree_digest":"sha256:d034f506c0db88997e2d6b9b3be31ee24991442a6fb08bea9f7abdcd5efe9a36","untracked_digest":"absent"}
      - {"path":"tests/test_dataset_validation.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:262d7d16edcf6c6a1ffef34cd1388cc2b9f462a4ff3cf34ca5a0d4b77545bd8d","index_digest":"sha256:262d7d16edcf6c6a1ffef34cd1388cc2b9f462a4ff3cf34ca5a0d4b77545bd8d","worktree_digest":"sha256:262d7d16edcf6c6a1ffef34cd1388cc2b9f462a4ff3cf34ca5a0d4b77545bd8d","untracked_digest":"absent"}
      - {"path":"tests/test_evidence.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:1902109bdea639c2b4fe3d0dfdeaadb3d8468578fe5998887736a0c62867d1e0","index_digest":"sha256:1902109bdea639c2b4fe3d0dfdeaadb3d8468578fe5998887736a0c62867d1e0","worktree_digest":"sha256:4331f64134f5ce84acc03a34569cc4e20e5866447f09390dcd6ca94a588c206f","untracked_digest":"absent"}
      - {"path":"tests/test_pcap_workload.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:4e5fcef96a7f6e4f5021798f66883bf1c76e590bf9613f17db846744754224bb","index_digest":"sha256:4e5fcef96a7f6e4f5021798f66883bf1c76e590bf9613f17db846744754224bb","worktree_digest":"sha256:4e5fcef96a7f6e4f5021798f66883bf1c76e590bf9613f17db846744754224bb","untracked_digest":"absent"}
      - {"path":"tests/test_scenario.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:12302f69c1474ca49db901e0759e2cc8f6bed34c9703268e00e02a030065db7d","index_digest":"sha256:12302f69c1474ca49db901e0759e2cc8f6bed34c9703268e00e02a030065db7d","worktree_digest":"sha256:0c2184d4f0d70d38399e747bc65db20ba14e109ca4bf55e42d65a604d5a67bc8","untracked_digest":"absent"}
      - {"path":"tests/test_secure_baseline_integration.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:96a4e29f8726f31767efdc2e485581a772fe7dddbca8bb7bd25dde30bbf8a77a","index_digest":"sha256:96a4e29f8726f31767efdc2e485581a772fe7dddbca8bb7bd25dde30bbf8a77a","worktree_digest":"sha256:ba177ce72d36378de77ad2de9154c98d0b4ac55e0a6ef3db8f9e3e6ef0cc9ec1","untracked_digest":"absent"}
      - {"path":"tests/test_session.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:8a69132f2b84e0c03d233b09792b263ba0a31ed8809adea3b39e707c0007ed88","index_digest":"sha256:8a69132f2b84e0c03d233b09792b263ba0a31ed8809adea3b39e707c0007ed88","worktree_digest":"sha256:8a69132f2b84e0c03d233b09792b263ba0a31ed8809adea3b39e707c0007ed88","untracked_digest":"absent"}
      - {"path":"tests/test_strongswan.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:4b11c67c529fd0c02f9fa0aef5e638d39bae62a2b73427b3167b402d695c859f","index_digest":"sha256:4b11c67c529fd0c02f9fa0aef5e638d39bae62a2b73427b3167b402d695c859f","worktree_digest":"sha256:9b362b183f17768ea73dd9e133b40c1b6a60d77c1d1f7033234a899a4d325b31","untracked_digest":"absent"}
      - {"path":"tests/test_traffic_contract.py","object_kind":{"head":"regular","index":"regular","worktree":"regular","untracked":"absent"},"state":"clean","rename_from":null,"rename_to":null,"head_digest":"sha256:913a7fba9d9f4faf315a27fb6c91a97e026b33677df04ba3fd4a2af33039e595","index_digest":"sha256:913a7fba9d9f4faf315a27fb6c91a97e026b33677df04ba3fd4a2af33039e595","worktree_digest":"sha256:913a7fba9d9f4faf315a27fb6c91a97e026b33677df04ba3fd4a2af33039e595","untracked_digest":"absent"}
  primary_symbols:
    - {symbol: "run_dataset_attempt", file: "ipsec_sentinel/dataset/runner.py", lines: "281-592", role: "single attempt lifecycle and cleanup owner"}
    - {symbol: "generate_dataset", file: "ipsec_sentinel/dataset/runner.py", lines: "613-674", role: "serial matrix/retry/resume orchestrator"}
    - {symbol: "Manifest", file: "ipsec_sentinel/dataset/manifest.py", lines: "147-561", role: "transactional state and attempt history"}
    - {symbol: "SecureSession", file: "ipsec_sentinel/session.py", lines: "52-296", role: "real topology/daemon/capture/rekey lifecycle"}
    - {symbol: "evaluate_ipsec", file: "ipsec_sentinel/evidence.py", lines: "263-282", role: "configured-versus-observed security verdict"}
  related_symbols:
    - {symbol: "DatasetConfig.load", relationship: "feeds expand_matrix/generate_dataset", relevance: "strict matrix shape"}
    - {symbol: "expand_matrix", relationship: "feeds Manifest.initialize", relevance: "deterministic slots and roles"}
    - {symbol: "build_terminal_payloads", relationship: "consumes attempt/session/generator evidence", relevance: "terminal ground truth"}
    - {symbol: "validate_dataset", relationship: "reparses PASS artifacts and encrypted PCAP", relevance: "offline quality gate"}
    - {symbol: "StrongSwanPair", relationship: "owned by SecureSession", relevance: "rendering/VICI/rekey evidence"}
    - {symbol: "inspect_ml_pcap", relationship: "called by runner and validator", relevance: "strict ESP-only ML capture"}
  execution_path:
    - "Load strict matrix and authoritative registries."
    - "Initialize/resume manifest; recover stale RUNNING attempts."
    - "Allocate immutable attempt and derived seed."
    - "Start full capture, establish and verify scenario, then apply verified profile."
    - "Prepare service outside workload window; run/validate traffic inside window."
    - "Remove profile, rekey and verify scenario-specific PFS policy."
    - "Stop full capture; derive and strictly validate encrypted.pcap."
    - "Persist artifacts, cleanup result, terminal state, summaries, validation, and audit."
  pdg_constraints:
    - {description: "No target-repository PDG layer is available; preserve source-observed workload/rekey/profile ordering.", affected_statements: ["ipsec_sentinel/dataset/runner.py:281"], implementation_consequence: "Run focused ordering tests and real capture checks after lifecycle edits."}
  architectural_patterns:
    - {pattern: "Frozen dataclass plans resolved from a recorded seed", example_location: "ipsec_sentinel/traffic/icmp.py:15", usage_guidance: "All generator intent is deterministic and serialized."}
    - {pattern: "Five-method TrafficGenerator protocol", example_location: "ipsec_sentinel/traffic/base.py:33", usage_guidance: "New generators use the same lifecycle."}
    - {pattern: "Independent cleanup attempts", example_location: "ipsec_sentinel/dataset/runner.py:453", usage_guidance: "Never let one cleanup failure suppress later layers."}
    - {pattern: "Strict exact-mapping YAML parsing", example_location: "ipsec_sentinel/dataset/config.py:17", usage_guidance: "Reject unknown/mixed matrix forms."}
  files_to_modify:
    - {file: "ipsec_sentinel/traffic/base.py", symbols: ["TrafficClassSpec", "register_generator", "is_supervised_eligible"], intended_change: "authoritative class roles"}
    - {file: "ipsec_sentinel/dataset/runner.py", symbols: ["run_dataset_attempt", "generate_dataset"], intended_change: "registry factories, lifecycle order, timings"}
    - {file: "ipsec_sentinel/dataset/manifest.py", symbols: ["Manifest", "SCHEMA"], intended_change: "schema-v2 additive migration and role persistence"}
    - {file: "ipsec_sentinel/scenario.py", symbols: ["Scenario", "ScenarioDefinition"], intended_change: "four-entry allowlist"}
    - {file: "ipsec_sentinel/evidence.py", symbols: ["parse_sa", "parse_xfrm", "evaluate_ipsec", "evaluate_rekey_policy"], intended_change: "scenario-aware algorithm/PFS evidence"}
    - {file: "ipsec_sentinel/dataset/network.py", symbols: ["NetworkProfileSpec", "create_network_profile"], intended_change: "verified netem profiles"}
    - {file: "ipsec_sentinel/dataset/audit.py", symbols: ["audit_dataset"], intended_change: "shortcut review tooling"}
  tests:
    - {file: "tests/test_traffic_foundation.py", scenarios: ["seed/purpose/protocol -> stable shared-range ports", "collision -> deterministic fallback", "timeout/repeated stop -> no process leak"]}
    - {file: "tests/test_traffic_voip.py", scenarios: ["seed -> RTP plan", "packet bytes -> valid RTP-v2 header", "two ledgers -> bidirectional validation"]}
    - {file: "tests/test_traffic_email.py", scenarios: ["SMTP/MIME plan -> exact server receipts and attachment digests"]}
    - {file: "tests/test_traffic_messaging.py", scenarios: ["bursts/directions -> both endpoint ledgers"]}
    - {file: "tests/test_traffic_file_transfer.py", scenarios: ["direction/size/chunks -> exact bytes and SHA-256"]}
    - {file: "tests/test_traffic_remote_desktop_like.py", scenarios: ["input/update behavior -> OOD role and ledger"]}
    - {file: "tests/test_traffic_database_query_like.py", scenarios: ["query/result behavior -> OOD role and ledger"]}
    - {file: "tests/test_dataset_network.py", scenarios: ["profile apply/readback/cleanup", "interruption -> no stale qdisc"]}
    - {file: "tests/test_dataset_audit.py", scenarios: ["each accidental shortcut -> named finding"]}
    - {file: "tests/test_dataset_integration.py", scenarios: ["all real generators/scenarios/profiles and retry/resume"]}
  verification_commands:
    - "python3 -m unittest discover -s tests -v"
    - "sudo env IPSEC_SENTINEL_INTEGRATION=1 python3 -m unittest tests.test_secure_baseline_integration -v"
    - "sudo env IPSEC_SENTINEL_DATASET_INTEGRATION=1 python3 -m unittest tests.test_dataset_integration -v"
    - "sudo python3 -m ipsec_sentinel.dataset generate configs/datasets/extension-smoke-v1.yaml"
    - "sudo python3 -m ipsec_sentinel.dataset validate dataset/cipherlens-extension-smoke-v1"
    - "sudo python3 -m ipsec_sentinel.dataset audit dataset/cipherlens-extension-smoke-v1"
  risks:
    - "Role disagreement can silently contaminate future supervised data."
    - "Lifecycle ordering changes can leak IKE/rekey or profile effects into encrypted.pcap."
    - "CBC and no-PFS evidence can be falsely judged by baseline-only parsers."
    - "Process/qdisc cleanup failures can contaminate later serial runs."
    - "Synthetic plan invariants can become trivial classifier fingerprints."
  assumptions:
    - "Re-run the existing strongSwan/kernel algorithm preflight before Task 10 privileged gates; stop if installed support differs."
    - "Run implementation and privileged commands inside the existing WSL2 environment from the repository root."
  open_questions: []
  avoid:
    - "Do not repeat full repository discovery."
    - "Do not replace the working Phase 1 topology/capture foundation without a proven bug."
    - "Do not accept arbitrary scenario strings, profile commands, or external services."
    - "Do not weaken inspect_ml_pcap or move rekey into the workload window."
    - "Do not generate the 492-session dataset during implementation."
    - "Do not add feature extraction or any ML component."
```

## 12. Assumptions and Open Questions

- [assumed] The previously validated WSL2 environment still exposes strongSwan AES-GCM, AES-CBC, HMAC-SHA-256, PRF-SHA-384, ECP-384, XFRM, and netem seed support. Task 10 re-runs preflight before relying on it.
- [verified] The target repository has no GitNexus index, so this plan makes no graph/PDG blast-radius claim. Source/tests are authoritative.
- [inferred] The exact 11-session smoke and existing Web/Video proof are compatible because Web/Video run as separate privileged regressions and are not added to the smoke.
- [inferred] Moving Web/Video from fixed 8080/8081 ports to seeded shared-range ports changes infrastructure detail, not their approved workload semantics, and is required by the approved leakage design.
- No design contradiction or technical impossibility was found. If ECP-384 or netem behavior differs at execution time, stop at the named checkpoint and document the concrete compatibility evidence rather than changing the design silently.

Explicitly deferred: all feature extraction, ML dataset creation/splitting, models, calibration, OOD rejection model, inference, UI, assessment, and reporting work.

## 13. Definition of Done

- Tasks 1-18 are implemented in order with TDD and their local commits.
- Checkpoints A-G all pass; a failed checkpoint halted dependent work until fixed.
- Phase 1 baseline and all existing Phase 2 ordinary/privileged tests pass.
- Four new supervised and two OOD generators pass real IPsec integrations with seeded variation and complete metadata.
- OOD sessions are quality-valid but structurally absent from supervised selection and summaries.
- All four scenarios pass real ICMP/IKE/CHILD/XFRM/ESP/configured-observed checks; PFS-enabled and no-PFS rekey semantics are correctly distinguished.
- All three profiles pass apply/readback/metadata/cleanup checks, including following-clean-run leakage proof.
- Every ML capture is non-empty expected-peer ESP only with zero IKE, UDP/4500, rekey, or unrelated plaintext traffic.
- The exact 11-session smoke passes validation/audit/resume without regeneration; retry/failure preservation is demonstrated separately.
- Shortcut audit findings are fixed or documented, with no hard finding outstanding.
- `configs/datasets/cipherlens-v1.yaml` expands to exactly 420 supervised + 72 OOD sessions and is not executed.
- No feature extraction or training code exists.
- Final implementation worktree is clean after commit, with generated datasets excluded.
