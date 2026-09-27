# IPsec Sentinel Live Lab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the existing polished frontend a real, locally controlled, event-driven IPsec Live Lab while preserving offline analysis, Guided Demo, and every validated Phase 1/2 behavior.

**Architecture:** Extend the loopback-only standard-library frontend bridge into a single privileged Sentinel Agent. A persisted session orchestrator adapts `SecureSession`, publishes real backend observations through replayable SSE, retains one continuous evidence capture, and derives only the latest completed workload window for ML. A React Live Lab context reduces those events into progressive UI state without fabricated timers.

**Tech Stack:** Python 3.14 standard library, Linux namespaces/XFRM, strongSwan/swanctl, tcpdump, existing traffic generators and Extra Trees model, React 19, TypeScript 6, Vite 8, Vitest 5, Playwright 1.63.

**Spec:** `docs/superpowers/specs/2026-09-27-ipsec-sentinel-live-lab-design.md`

## Global Constraints

- Bind the privileged agent only to `127.0.0.1`; validate loopback `Host` values and add no permissive CORS.
- Permit exactly one active Live Lab session and serialize all mutating commands.
- Reuse `SecureSession`; do not duplicate topology, strongSwan, capture, traffic, rekey, or cleanup logic.
- Start the authoritative capture before IKE and keep it running until analysis seals it, disconnect, or failure.
- Persist ordered UTC-timestamped JSONL events before publishing; replay events strictly after `Last-Event-ID`.
- Drive every frontend product transition from a committed backend event, never from a progress timer.
- Keep Mystery scenario identity and configured ground truth server-side until explicit post-analysis reveal.
- Run ML and workload X-Ray on only the latest successfully completed workload window; analyze protocol/security evidence from the full capture.
- Preserve `ipsec-sentinel.analysis/v1`, `run_secure_baseline()`, all existing generators, and offline/frontend behavior.
- Cleanup and stale recovery must be idempotent and exact-resource scoped; never wildcard-kill or broadly delete.
- Add no FastAPI, WebSocket, helper daemon, cloud SDK, cloud credential, or GCP resource in Phase A.
- Use test-driven development and stop at any failed checkpoint until it is fixed.

## Review Focus

- A disconnected SSE client reconnects after several events: it receives every event after its acknowledged ID exactly once and reconstructs the same state.
- A command races with another command or a second session create: the server returns a stable `409` and performs no hidden queued work.
- Ping succeeds and Video then succeeds: the full capture contains both, but ML/X-Ray are derived from Video's window only.
- The agent crashes with stale PIDs and namespace records: recovery acts only on verified owned resources and preserves evidence.
- A Mystery response, event, error, or artifact is serialized before reveal: no scenario ID, configured proposal, PFS intent, or encoding path leaks.

---

## File structure

- `ipsec_sentinel/live/models.py`: lifecycle/status enums, session/action/workload snapshots, problem types, serialization and transition rules.
- `ipsec_sentinel/live/events.py`: durable JSONL event store and replay cursor.
- `ipsec_sentinel/live/provider.py`: `LabProvider`, `LocalLabProvider`, and Phase-A cloud boundary.
- `ipsec_sentinel/live/observations.py`: strongSwan-log and capture-derived live observations.
- `ipsec_sentinel/live/runtime.py`: exact runtime ownership, process lock, and stale recovery.
- `ipsec_sentinel/live/orchestrator.py`: command serialization and interactive `SecureSession` lifecycle.
- `ipsec_sentinel/live/api.py`: REST routing, request validation, SSE framing, and HTTP error mapping.
- `ipsec_sentinel/live/__init__.py`: stable package exports.
- `ipsec_sentinel/session.py`: small reusable lifecycle/capture snapshot extensions only.
- `ipsec_sentinel/capture.py`: safe flush/snapshot support for a running capture.
- `ipsec_sentinel/analyzer/pipeline.py`: optional traffic-capture source while retaining full-capture protocol/security analysis.
- `ipsec_sentinel/frontend/bridge.py`: compose the existing offline bridge with the Live Lab API.
- `ipsec_sentinel/frontend/__main__.py`: Live Lab CLI/runtime options.
- `frontend/src/lib/live/types.ts`: event/session/action runtime types.
- `frontend/src/lib/live/schema.ts`: runtime validation and safe decoding.
- `frontend/src/lib/live/client.ts`: REST client and replaying `EventSource` adapter.
- `frontend/src/app/LiveLabContext.tsx`: event reducer, reconnect lifecycle, command actions, and analysis handoff.
- `frontend/src/app/views/LiveLabView.tsx`: scenario selection, connection progress, session header, event timeline, and controls.
- `frontend/src/components/live/*`: focused live header, scenario, timeline, traffic, action, and progressive-status components.
- Existing shell, tunnel, traffic, security, evidence, report, route, and style files: integrate progressive live state without replacing final-analysis components.
- `tests/test_live_*.py`: unit/service tests for state, events, provider, runtime, orchestration, and API.
- `tests/test_live_lab_integration.py`: privileged real-network Phase-A proof.
- `frontend/src/**/*.test.ts(x)`: reducer, decoder, reconnect, controls, and view tests.
- `frontend/e2e/live-lab.spec.ts`: browser Live Lab flows.

### Task 1: Persisted session domain and command rules

**Files:**
- Create: `ipsec_sentinel/live/__init__.py`
- Create: `ipsec_sentinel/live/models.py`
- Create: `tests/test_live_models.py`

**Interfaces:**
- Produces: `SessionState`, `TunnelStatus`, `CaptureStatus`, `CleanupStatus`, `LiveAction`, `WorkloadWindow`, `LiveSessionSnapshot`, `LiveProblem`, `allowed_actions(snapshot)`, and `transition(snapshot, target, reason)`.

- [ ] **Step 1: Write failing state-machine tests** for the exact state set, orthogonal statuses, valid connect/traffic/rekey/analyze/reveal/disconnect rules, busy action rejection, post-`READY` restrictions, idempotent terminal disconnect, and stable problem codes.
- [ ] **Step 2: Run** `python3 -m unittest tests.test_live_models -v`; expect import/test failures.
- [ ] **Step 3: Implement immutable domain models and transition guards** in `models.py`; ensure snapshots contain `latest_event_id`, `allowed_actions`, completed windows, failure, and cleanup status without private Mystery fields.
- [ ] **Step 4: Run** `python3 -m unittest tests.test_live_models -v`; expect PASS.
- [ ] **Step 5: Commit** `test/live models` with message `feat: define Live Lab session state machine`.

### Task 2: Durable event store and replay cursor

**Files:**
- Create: `ipsec_sentinel/live/events.py`
- Create: `tests/test_live_events.py`

**Interfaces:**
- Consumes: `LiveSessionSnapshot` from Task 1.
- Produces: `LiveEvent`, `EventStore.append(type, state, reason, data, evidence) -> LiveEvent`, `EventStore.replay(after_id) -> tuple[LiveEvent, ...]`, `EventStore.wait(after_id, timeout)`, and `format_sse(event) -> bytes`.

- [ ] **Step 1: Write failing tests** proving monotonic IDs, RFC 3339 UTC timestamps, append-before-notify ordering, atomic snapshot persistence, incomplete-tail quarantine, replay strictly after ID, duplicate-free concurrent readers, SSE `id/event/data`, and non-state-changing heartbeat comments.
- [ ] **Step 2: Run** `python3 -m unittest tests.test_live_events -v`; expect failure.
- [ ] **Step 3: Implement JSONL persistence and condition-based readers** with flush for every event and `fsync` for transitions/security evidence.
- [ ] **Step 4: Run** `python3 -m unittest tests.test_live_events -v`; expect PASS.
- [ ] **Step 5: Commit** with message `feat: persist replayable Live Lab events`.

### Task 3: Reusable continuous-capture lifecycle

**Files:**
- Modify: `ipsec_sentinel/capture.py`
- Modify: `ipsec_sentinel/session.py`
- Modify: `tests/test_capture.py`
- Modify: `tests/test_session.py`

**Interfaces:**
- Produces: `CaptureSession.running`, `CaptureSession.flush()`, `CaptureSession.snapshot(destination)`, `SecureSession.capture_snapshot(destination)`, `SecureSession.refresh_sas()`, and a sealed-but-still-connected session path; existing public methods remain compatible.

- [ ] **Step 1: Write failing tests** for safe repeated flush, stable snapshot copy from an active immediate-mode `tcpdump`, no premature stop, repeated stop/cleanup, and preserving existing `evidence()` behavior.
- [ ] **Step 2: Run** `python3 -m unittest tests.test_capture tests.test_session -v`; expect failure.
- [ ] **Step 3: Implement the minimum lifecycle extensions** using the owned capture PID and bounded snapshot validation; do not alter Phase 1 ordering or names.
- [ ] **Step 4: Run focused tests**, then `python3 -m unittest discover -s tests -v`; expect all unprivileged tests PASS.
- [ ] **Step 5: Run the privileged regression gate**: `sudo env IPSEC_SENTINEL_INTEGRATION=1 python3 -m unittest tests.test_secure_baseline_integration -v`; expect one real secure-baseline PASS before continuing.
- [ ] **Step 6: Commit** with message `refactor: expose interactive secure-session lifecycle`.

### Task 4: Provider boundary and evidence observation

**Files:**
- Create: `ipsec_sentinel/live/provider.py`
- Create: `ipsec_sentinel/live/observations.py`
- Create: `tests/test_live_provider.py`
- Create: `tests/test_live_observations.py`

**Interfaces:**
- Consumes: `SecureSession` from Task 3.
- Produces: `LabProvider` protocol, `LocalLabProvider`, `ProviderEndpoint`, `StrongSwanObservationParser.feed(line)`, and `summarize_esp(snapshot_path, prior_totals)`.

- [ ] **Step 1: Write failing provider tests** proving local calls delegate to `SecureSession`, only the four validated scenarios are accepted, endpoint public/private fields are separated, and the GCP boundary has no implementation side effects.
- [ ] **Step 2: Write failing observation tests** using genuine retained strongSwan lines for SA_INIT request/response, selected proposal, IKE_AUTH, IKE established, and CHILD_SA installed; prove absent markers produce no fabricated event.
- [ ] **Step 3: Add failing ESP-summary tests** for peer validation, packet/byte direction deltas, zero-delta suppression, and truncated in-progress snapshot tolerance.
- [ ] **Step 4: Run** `python3 -m unittest tests.test_live_provider tests.test_live_observations -v`; expect failure.
- [ ] **Step 5: Implement provider and evidence parsers** without embedding UI copy or cloud calls.
- [ ] **Step 6: Run focused tests**; expect PASS.
- [ ] **Step 7: Commit** with message `feat: add local lab provider and live evidence parsers`.

### Task 5: Interactive connect orchestration

**Files:**
- Create: `ipsec_sentinel/live/orchestrator.py`
- Create: `tests/test_live_orchestrator.py`

**Interfaces:**
- Consumes: Tasks 1–4.
- Produces: `LiveLabOrchestrator.create_session(scenario_id)`, `submit(session_id, action, payload)`, `get_session(session_id)`, and background connect execution.

- [ ] **Step 1: Write failing tests** for create/IDLE, one-active-session rejection, action lock rejection, exact connect state order, capture-before-initiate, log-derived IKE events, SA/XFRM verification before `TUNNEL_ACTIVE`, failure preservation, and finally-path cleanup.
- [ ] **Step 2: Add a Mystery test** proving server selection is allowlisted and all snapshots/events/errors remain redacted before reveal.
- [ ] **Step 3: Run** `python3 -m unittest tests.test_live_orchestrator -v`; expect failure.
- [ ] **Step 4: Implement creation and connect actions** with injected provider/session factories and an executor suitable for deterministic tests.
- [ ] **Step 5: Run focused tests**; expect PASS.
- [ ] **Step 6: Commit** with message `feat: orchestrate interactive IPsec connection`.

### Task 6: Seeded traffic windows and live ESP activity

**Files:**
- Modify: `ipsec_sentinel/live/orchestrator.py`
- Create: `tests/test_live_traffic.py`

**Interfaces:**
- Produces: `run_traffic(session_id, workload_id)`, persisted `WorkloadWindow` records, `latest_completed_workload`, and `esp.observed` event batches.

- [ ] **Step 1: Write failing tests** proving generator `prepare/run/validate/cleanup` ordering, server-recorded seed/metadata, cleanup on failure, successful-pointer advancement only after validation, allowlist rejection, and active-tunnel requirement.
- [ ] **Step 2: Add the review-focus test**: ICMP then Video selects only Video as `latest_completed_workload`; a later failed workload does not replace it.
- [ ] **Step 3: Add ESP-event tests** proving positive real deltas emit and zero deltas do not create packet animation events.
- [ ] **Step 4: Run** `python3 -m unittest tests.test_live_traffic -v`; expect failure.
- [ ] **Step 5: Implement traffic actions using the existing registry and `TrafficContext`**; persist each `traffic.json` and validation outcome.
- [ ] **Step 6: Run focused tests and existing generator contract tests**; expect PASS.
- [ ] **Step 7: Commit** with message `feat: run interactive protected workloads`.

### Task 7: Separate full-session analysis from workload ML

**Files:**
- Modify: `ipsec_sentinel/analyzer/pipeline.py`
- Modify: `ipsec_sentinel/frontend/xray.py`
- Modify: `ipsec_sentinel/frontend/bridge.py`
- Modify: `tests/test_analyzer_contract.py`
- Modify: `tests/test_analyzer_real_pcaps.py`
- Modify: `tests/test_frontend_bridge.py`

**Interfaces:**
- Produces: backward-compatible `analyze_capture(..., traffic_capture_path: Path | None = None)` and `analyze_for_frontend(..., traffic_capture_path: Path | None = None)`.

- [ ] **Step 1: Write failing tests** proving omitted traffic path preserves byte-for-byte contract semantics, while an override changes only traffic intelligence/workload X-Ray source and leaves full-capture protocols/IKE/SA/PFS/security inputs intact.
- [ ] **Step 2: Write failure tests** proving invalid or non-ESP workload capture returns no prediction and cannot silently fall back to mixed full-session traffic.
- [ ] **Step 3: Run focused analyzer/bridge tests**; expect failure.
- [ ] **Step 4: Implement the optional source** by parsing both captures and passing workload observations only to inference/X-Ray; add evidence/limitation provenance while retaining schema v1.
- [ ] **Step 5: Run analyzer contract, real-capture, bridge, and frontend schema tests**; expect PASS.
- [ ] **Step 6: Commit** with message `feat: isolate live workload inference window`.

### Task 8: Rekey, sealing, analysis, reveal, and disconnect

**Files:**
- Modify: `ipsec_sentinel/live/orchestrator.py`
- Create: `tests/test_live_actions.py`

**Interfaces:**
- Produces: `trigger_rekey`, `refresh`, `analyze`, `reveal`, and `disconnect` actions with persisted artifacts/results.

- [ ] **Step 1: Write failing rekey tests** for CHILD_SA prerequisite, before/after SPI events, configured-versus-observed PFS semantics, no-PFS evidence, and UNKNOWN on insufficient evidence.
- [ ] **Step 2: Write failing analysis tests** proving the full capture seals once, `encrypted.pcap` derives from the latest workload timestamps, strict ESP-only validation rejects IKE/UDP 4500/plaintext, and `READY` prohibits further capture-changing actions.
- [ ] **Step 3: Write failing reveal/disconnect tests** for post-READY Mystery reveal, provenance comparison, idempotent cleanup, separate cleanup status/failure, and preserved primary failure.
- [ ] **Step 4: Run** `python3 -m unittest tests.test_live_actions -v`; expect failure.
- [ ] **Step 5: Implement all five actions** by delegating to existing rekey, workload-PCAP, analyzer, evidence, and cleanup code.
- [ ] **Step 6: Run live unit tests and full Python tests**; expect PASS.
- [ ] **Step 7: Commit** with message `feat: complete Live Lab security actions`.

### Task 9: Runtime ownership and safe stale recovery

**Files:**
- Create: `ipsec_sentinel/live/runtime.py`
- Create: `tests/test_live_runtime.py`
- Modify: `ipsec_sentinel/live/orchestrator.py`

**Interfaces:**
- Produces: `RuntimeOwnership`, `LiveLabLock.acquire()`, `record_resource(...)`, `recover_stale_runtime(...)`, and exact cleanup audit.

- [ ] **Step 1: Write failing tests** for live-owner refusal, stale-owner detection, PID start-identity mismatch refusal, exact PID cleanup, exact namespace/path cleanup, partial cleanup diagnostics, evidence preservation, and repeated recovery.
- [ ] **Step 2: Run** `python3 -m unittest tests.test_live_runtime -v`; expect failure.
- [ ] **Step 3: Implement ownership persistence, locking, and recovery** using exact resource names and `/proc` identity; do not use wildcard process matching or recursive broad deletion.
- [ ] **Step 4: Integrate ownership updates with orchestration and cleanup**, preserving cleanup outcome independently.
- [ ] **Step 5: Run runtime/orchestrator tests**; expect PASS.
- [ ] **Step 6: Commit** with message `feat: recover stale Live Lab resources safely`.

### Task 10: Loopback REST and replayable SSE API

**Files:**
- Create: `ipsec_sentinel/live/api.py`
- Modify: `ipsec_sentinel/frontend/bridge.py`
- Modify: `ipsec_sentinel/frontend/__main__.py`
- Create: `tests/test_live_api.py`
- Modify: `tests/test_frontend_bridge.py`

**Interfaces:**
- Consumes: orchestrator and event store.
- Produces: all `/api/lab/*` routes from the specification, SSE `Last-Event-ID`, `--enable-live-lab`, and loopback-only server composition.

- [ ] **Step 1: Write failing route tests** for scenarios/create/get/connect/traffic/rekey/refresh/analyze/reveal/disconnect, `202` acceptance, stable `409` problems, JSON content type, unknown IDs/routes, and existing `/api/analyze` compatibility.
- [ ] **Step 2: Write failing security/SSE tests** for loopback Host validation, no CORS wildcard, ordered replay, query fallback, live wait/notify, heartbeat comments, disconnecting readers, and no gaps during replay-to-live handoff.
- [ ] **Step 3: Run** `python3 -m unittest tests.test_live_api tests.test_frontend_bridge -v`; expect failure.
- [ ] **Step 4: Implement API routing and SSE streaming** within the existing `ThreadingHTTPServer`; keep action workers outside request threads.
- [ ] **Step 5: Implement CLI startup recovery and shutdown cleanup** only when Live Lab is explicitly enabled.
- [ ] **Step 6: Run focused and full Python tests**; expect PASS.
- [ ] **Step 7: Commit** with message `feat: serve loopback Live Lab REST and SSE`.

### Task 11: Frontend live schema, reducer, and reconnect client

**Files:**
- Create: `frontend/src/lib/live/types.ts`
- Create: `frontend/src/lib/live/schema.ts`
- Create: `frontend/src/lib/live/client.ts`
- Create: `frontend/src/lib/live/schema.test.ts`
- Create: `frontend/src/lib/live/client.test.ts`
- Create: `frontend/src/app/LiveLabContext.tsx`
- Create: `frontend/src/app/LiveLabContext.test.tsx`
- Modify: `frontend/src/app/App.tsx`

**Interfaces:**
- Produces: validated `LiveEvent`, `LiveSession`, `LiveProblem`, `LiveLabServices`, `LiveLabProvider`, and `useLiveLab()` actions/state.

- [ ] **Step 1: Write failing decoder tests** for every event/status, unknown/unsafe payload rejection, literal false payload-decryption semantics, and Mystery redaction assumptions.
- [ ] **Step 2: Write failing reducer tests** for exact ordered event application, duplicate suppression, replay restoration, reconnect from last ID, command errors, and full-analysis envelope handoff.
- [ ] **Step 3: Add the review-focus reconnect test** where the client disconnects during traffic and rebuilds the same active state from missed persisted events.
- [ ] **Step 4: Run** `npm test -- --run src/lib/live src/app/LiveLabContext.test.tsx`; expect failure.
- [ ] **Step 5: Implement schemas, REST client, EventSource lifecycle, and context**; no timers may modify product state.
- [ ] **Step 6: Run focused frontend tests**; expect PASS.
- [ ] **Step 7: Commit** with message `feat: consume replayable Live Lab events`.

### Task 12: Live-first frontend and interactive controls

**Files:**
- Create: `frontend/src/app/views/LiveLabView.tsx`
- Create: `frontend/src/components/live/LiveSessionHeader.tsx`
- Create: `frontend/src/components/live/ScenarioPicker.tsx`
- Create: `frontend/src/components/live/ConnectionTimeline.tsx`
- Create: `frontend/src/components/live/TrafficControls.tsx`
- Create: `frontend/src/components/live/SecurityActions.tsx`
- Create: `frontend/src/components/live/live.css`
- Modify: `frontend/src/components/shell/Landing.tsx`
- Modify: `frontend/src/components/shell/Navigation.tsx`
- Modify: `frontend/src/components/shell/AppShell.tsx`
- Modify: `frontend/src/app/routes.tsx`
- Modify: `frontend/src/components/tunnel/LiveTunnel.tsx`
- Modify: `frontend/src/app/views/TunnelView.tsx`
- Modify: `frontend/src/app/views/TrafficView.tsx`
- Modify: `frontend/src/app/views/SecurityView.tsx`
- Add/modify focused component and view tests.

**Interfaces:**
- Consumes: `useLiveLab()` and existing analysis components.
- Produces: primary Start Live Lab flow, progressive session UI, real traffic/rekey controls, event-driven tunnel/ESP/X-Ray states, and secondary Offline PCAP/Guided Demo access.

- [ ] **Step 1: Write failing landing/navigation tests** proving Live Lab is primary, Offline PCAP secondary, Guided Demo tertiary, and existing offline/demo routes still work.
- [ ] **Step 2: Write failing Live Lab view tests** for scenario/create/connect, server `allowed_actions`, event timeline, compact header, no pre-populated crypto/ML/score, action errors, Mystery reveal, and disconnect.
- [ ] **Step 3: Write failing visualization tests** proving tunnel activation and packet flow require corresponding events, prediction appears only after inference, PFS updates only after rekey evidence, and final score only after analysis.
- [ ] **Step 4: Run focused Vitest files**; expect failure.
- [ ] **Step 5: Implement the live-first UI by adapting existing components and tokens**, retaining accessibility, responsive behavior, and provenance labels.
- [ ] **Step 6: Remove timer-driven analysis progress from Live Lab paths** while preserving appropriate offline upload feedback that does not fabricate protocol results.
- [ ] **Step 7: Run all frontend unit tests, lint, and build**; expect PASS.
- [ ] **Step 8: Commit** with message `feat: make Live Lab the primary product flow`.

### Task 13: Real local integration and browser proof

**Files:**
- Create: `tests/test_live_lab_integration.py`
- Create: `frontend/e2e/live-lab.spec.ts`
- Modify: `frontend/e2e/support.ts`
- Modify: `frontend/playwright.config.ts`
- Modify: `README.md`

**Interfaces:**
- Produces: opt-in privileged integration suite, real-agent Playwright project, and exact local run instructions.

- [ ] **Step 1: Write the privileged integration test** covering real secure-baseline connect, IKE event order, ICMP, Video, ESP deltas, Video-only ML window, rekey/new SPI/PFS, full analysis, disconnect, replay, concurrent-session rejection, and independent cleanup checks.
- [ ] **Step 2: Run it before final wiring** with `sudo env IPSEC_SENTINEL_LIVE_INTEGRATION=1 IPSEC_SENTINEL_MODEL_DIR=<model> python3 -m unittest tests.test_live_lab_integration -v`; expect a precise first failing boundary.
- [ ] **Step 3: Fix only the proven boundary and rerun** until the real flow passes without weakening assertions.
- [ ] **Step 4: Add Playwright local Live Lab tests** for happy path, Video/X-Ray/ML, rekey, SSE page reload restoration, second-session rejection, and endpoint-failure cleanup; critical happy path targets the real root agent.
- [ ] **Step 5: Run Playwright repeatedly** and inspect screenshots/traces for progressive truth, responsive layout, and accessibility.
- [ ] **Step 6: Document the loopback root-agent start command, non-root frontend behavior, retained artifacts, shutdown, and no-cloud status** in `README.md`.
- [ ] **Step 7: Commit** with message `test: prove real local Live Lab workflow`.

### Task 14: Whole-system verification and cloud-access handoff

**Files:**
- Create: `docs/evidence/live-lab-local.md`
- Modify only if evidence exposes a defect: implementation/test files above.

**Interfaces:**
- Produces: final local evidence record and the data needed for the user-facing `GCP ACCESS REQUIRED` report; creates no cloud resources.

- [ ] **Step 1: Run the complete Python suite**: `/home/black/.venvs/ipsec-sentinel-ml/bin/python -m unittest discover -s tests -v`; record counts and expected skips.
- [ ] **Step 2: Run Phase 1 and Phase 2 privileged regressions** from README, including secure baseline and existing ICMP/Web/Video dataset integrations; record real results.
- [ ] **Step 3: Run the new privileged Live Lab integration** and verify cleanup independently with namespace, process, route/XFRM, lock, and runtime-path checks.
- [ ] **Step 4: Run frontend verification**: `npm test -- --run`, `npm run lint`, `npm run build`, and `npm run e2e`; record exact counts and bundle advisory if present.
- [ ] **Step 5: Perform a manual evidence audit** proving full capture includes IKE/ESP/rekey, latest `encrypted.pcap` is ESP-only and inside the Video window, ML label comes from that window, and Mystery values were absent before reveal.
- [ ] **Step 6: Perform a failure/recovery audit** by interrupting one session, restarting the agent, verifying scoped recovery, reconnecting SSE, and confirming a new session can start.
- [ ] **Step 7: Review the whole diff** for fabricated timers, duplicated networking code, leaked Mystery identity, overly broad cleanup, arbitrary command/path input, stale state, contract drift, and offline regressions; fix and rerun affected gates.
- [ ] **Step 8: Write `docs/evidence/live-lab-local.md`** with commands, environment, session IDs, artifact paths, packet/event counts, results, limitations, and proof that no GCP action occurred.
- [ ] **Step 9: Commit** with message `docs: record local Live Lab verification`.
- [ ] **Step 10: Stop and return the exact `GCP ACCESS REQUIRED` report** containing all 18 requested cloud-planning and local-readiness items; do not run `gcloud`.

