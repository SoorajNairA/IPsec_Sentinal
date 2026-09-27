# IPsec Sentinel Live Lab Design Specification

**Date:** 2026-09-27  
**Status:** Proposed for review  
**Target branch:** `feat/ipsec-sentinel-live-lab`  
**Delivery scope:** Local Phase A only; cloud provisioning is explicitly excluded

## 1. Purpose

IPsec Sentinel will become a live, interactive IPsec experimentation and security-analysis environment. The primary experience will establish a real VPN in an isolated local lab, stream evidence-backed lifecycle events, run selected workloads through the tunnel, trigger a genuine CHILD_SA rekey, and analyze the resulting capture. Offline PCAP analysis remains available as a secondary workflow, and Guided Demo remains the reliability fallback.

This work reuses the validated networking, capture, traffic-generator, analyzer, ML, assessment, and frontend foundations. It does not replace or independently reimplement them.

## 2. Scope and non-goals

### In scope

- A single loopback-only Sentinel Agent using the Python standard-library HTTP server already used by the frontend bridge.
- REST commands for user actions and Server-Sent Events (SSE) for ordered server-to-frontend updates.
- An explicit, persisted interactive session state machine.
- A `LocalLabProvider` that adapts the existing `SecureSession` lifecycle.
- One active Live Lab session at a time.
- Continuous full-session capture from before IKE establishment through traffic and rekey actions.
- Independent workload windows, with ML inference restricted to the latest successfully completed workload.
- Full-session protocol and security analysis using the existing `ipsec-sentinel.analysis/v1` contract.
- Real-time, evidence-backed frontend progression, traffic summaries, X-Ray data, rekey evidence, and analysis results.
- Mystery VPN selection whose true scenario remains server-side until explicit reveal.
- Idempotent disconnect, failure cleanup, and safe stale-resource recovery at startup.
- Local privileged integration and browser end-to-end verification.
- A narrow provider contract suitable for a later `GcpLabProvider`.

### Out of scope

- Creating, starting, stopping, or configuring any Google Cloud resource.
- Requesting Google Cloud credentials before local Phase A is proven.
- WebSocket, FastAPI, microservices, or a second privileged helper process.
- New ML models, dataset generation, additional protocols, additional crypto scenarios, arbitrary remote targets, or public server scanning.
- Routing the user's host through the demo VPN.

## 3. Architectural principles

1. **Evidence precedes presentation.** A UI state, value, or success marker may appear only after its backend action completes or its evidence is parsed.
2. **One lifecycle implementation.** `SecureSession` remains the authority for topology, strongSwan, capture, SA verification, traffic, rekey, diagnostics, and cleanup. Interactive orchestration exposes pause points around that lifecycle instead of copying it.
3. **Two evidence scopes.** The full capture supports protocol and security analysis; a separately derived ESP-only capture for the latest workload supports ML inference and workload X-Ray presentation.
4. **Least exposure.** The privileged agent binds only to `127.0.0.1`, accepts allowlisted operations, and never accepts arbitrary command lines, endpoints, paths, or scenarios.
5. **Recoverable state.** Events and runtime ownership are persisted so the UI can reconnect and the agent can safely recover from a prior crash.
6. **Cloud is an adapter.** The frontend and session API operate against a provider boundary and do not contain GCP-specific assumptions.

## 4. Process and trust boundary

The Live Lab runs as one privileged Sentinel Agent inside WSL/Linux because namespaces, XFRM, strongSwan, `tcpdump`, routes, and `tc` require Linux privileges. The same process serves the built frontend, REST API, and SSE stream.

The server must:

- bind explicitly to `127.0.0.1` and reject non-loopback bind configuration;
- validate the HTTP `Host` as loopback/localhost;
- disable permissive cross-origin access and avoid wildcard CORS;
- require JSON for mutation requests;
- accept only known scenario IDs, workload IDs, and session actions;
- expose no arbitrary filesystem or subprocess API;
- serialize mutating session commands;
- hold an exclusive process/runtime lock while enabled.

Offline analysis and Guided Demo remain usable without privileged Live Lab support. Live controls report a clear availability state when the agent is not running with the required capabilities.

## 5. Core components

### 5.1 Sentinel Agent

The existing local frontend bridge is extended rather than replaced. It owns:

- HTTP route dispatch;
- request validation and error mapping;
- the active-session registry;
- the orchestration worker and command lock;
- event persistence and SSE delivery;
- startup recovery;
- static frontend delivery;
- existing offline `/api/analyze` compatibility.

Long-running actions execute outside the request-handler thread. A successful REST command means the action was accepted and returns `202 Accepted`; progress and completion arrive through SSE. Synchronous validation failures return an appropriate `4xx` response and do not mutate session state.

### 5.2 Interactive session orchestrator

The orchestrator owns user-action boundaries and calls granular `SecureSession` operations. It does not contain shell commands that duplicate existing tunnel behavior.

Conceptually:

```python
session = orchestrator.create_session(scenario)
session.connect()                 # prepare through verified tunnel active
session.run_traffic("video")     # one independently recorded workload window
session.trigger_rekey()           # genuine CHILD_SA rekey
session.analyze()                 # seal capture and run full + workload analysis
session.disconnect()              # tear down and clean idempotently
```

The orchestrator pauses after `connect`, every traffic action, rekey, refresh, and analysis. It records all completed actions and exposes only currently valid actions.

### 5.3 Provider boundary

The provider interface is intentionally small:

```python
class LabProvider(Protocol):
    def start_scenario(self, context): ...
    def wait_until_ready(self, context): ...
    def endpoint(self, context): ...
    def health(self, context): ...
    def stop_scenario(self, context): ...
```

`LocalLabProvider` delegates local endpoint/topology ownership to `SecureSession`; it does not create a parallel namespace implementation. `GcpLabProvider` is represented only by the stable boundary during Phase A. No cloud SDK calls or credentials are added in this phase.

Provider endpoint data is split into public display data and private connection/ground-truth data so Mystery mode cannot leak through generic serialization.

## 6. Session identity and storage

Each session receives a non-predictive display ID in the form `SNT-XXXXXXXX`. Artifacts live beneath:

```text
runs/live/<session-id>/
```

The directory contains, as applicable:

```text
session.json
events.jsonl
runtime-ownership.json
full-evidence.pcap
encrypted.pcap
traffic/<sequence>/traffic.json
traffic/<sequence>/validation.json
evidence/
analysis.json
logs/
```

Private Mystery ground truth is stored in an agent-private record and is not returned by session serialization, events, analysis data, or ordinary artifact endpoints before reveal. Filesystem permissions must not make private state part of the browser-served static tree.

## 7. State model

### 7.1 Lifecycle states

The persisted lifecycle state is one of:

```text
CREATING_SESSION
IDLE
PREPARING_SANDBOX
STARTING_ENDPOINT
WAITING_FOR_ENDPOINT
STARTING_CAPTURE
IKE_NEGOTIATING
AUTHENTICATING
CHILD_SA_ESTABLISHED
TUNNEL_ACTIVE
TRAFFIC_RUNNING
REKEYING
ANALYZING
READY
DISCONNECTING
CLEANING_UP
COMPLETE
FAILED
```

`IDLE` means the session exists but has not connected. `READY` means analysis has sealed the capture and results are available while the tunnel may still exist until disconnect. `FAILED` preserves the primary failure and does not imply cleanup failed.

### 7.2 Orthogonal status fields

Lifecycle state must not overload independent facts. The session snapshot also records:

- `tunnel_status`: `INACTIVE`, `ACTIVE`, `DISCONNECTED`, or `FAILED`;
- `capture_status`: `NOT_STARTED`, `RUNNING`, `SEALED`, `STOPPED`, or `FAILED`;
- `cleanup_status`: `NOT_RUN`, `RUNNING`, `SUCCEEDED`, or `FAILED`;
- `active_action`: the accepted command, or `null`;
- `failure`: stable code, user-safe message, failing operation, and diagnostic references;
- `allowed_actions`: server-computed action allowlist;
- completed workload windows and latest workload sequence;
- analysis availability and reveal status.

Cleanup outcome remains separate from the primary lifecycle failure. Cleanup may be retried without erasing the original error.

### 7.3 Command validity

The server rejects invalid commands with `409 Conflict` and a stable error code:

- create is rejected while any non-terminal session owns the lab;
- connect is allowed only from `IDLE`;
- traffic, refresh, and rekey are allowed only with an active verified tunnel and no active action;
- rekey additionally requires an established CHILD_SA;
- analyze requires at least one successfully completed workload;
- after `READY`, traffic and rekey are rejected because the capture has been sealed;
- reveal is allowed only for a Mystery session after analysis reaches `READY`;
- disconnect is accepted from any non-clean terminal or active state and is idempotent;
- repeated disconnect of a cleaned terminal session returns its current snapshot without recreating resources.

The action lock serializes mutation. A second command received while an action is running is rejected rather than queued invisibly.

## 8. Event model and SSE replay

### 8.1 Event envelope

Every event uses `ipsec-sentinel.live-event/v1`:

```json
{
  "schema": "ipsec-sentinel.live-event/v1",
  "event_id": 42,
  "session_id": "SNT-8A31D2F0",
  "timestamp": "2026-09-27T14:32:10.312Z",
  "type": "child_sa.established",
  "state": "CHILD_SA_ESTABLISHED",
  "reason": "swanctl reported an installed CHILD_SA",
  "data": {},
  "evidence": []
}
```

Event IDs are monotonically increasing integers scoped to the session. Timestamps are UTC RFC 3339 values. `reason` states why a transition or observation is being emitted. Evidence references identify the parser, log/capture artifact, and relevant record without exposing arbitrary host paths.

### 8.2 Durability and ordering

Within the orchestration lock, the event store:

1. allocates the next event ID;
2. appends one JSON object to `events.jsonl`;
3. flushes it before publication;
4. updates the persisted session snapshot atomically;
5. notifies connected SSE readers.

State transitions and security-relevant evidence also force durable synchronization. A partial final JSONL line after a crash is ignored and quarantined during recovery; prior complete events remain replayable.

### 8.3 SSE endpoint

The SSE response emits standard `id`, `event`, and `data` fields. On connection it:

1. reads the `Last-Event-ID` header, with a query fallback for browser/test tooling;
2. replays every persisted event whose ID is greater than the acknowledged ID;
3. waits on an in-process condition for new committed events;
4. sends SSE comment heartbeats while idle so intermediaries can detect a live connection.

Heartbeats are transport maintenance, not product events, and never alter UI state. Reconnects do not create synthetic progress. The frontend reducer rebuilds the visible session solely from replayed events, then continues with live events.

## 9. Real evidence and progressive disclosure

No user-visible completion transition is driven by an arbitrary timeout. A `*.started` event may be emitted when its backend operation actually begins, but its successful completion event is emitted only after the operation or parser succeeds.

During connection, the agent tails the real initiator strongSwan log and maps observed records such as:

- generated IKE_SA_INIT request;
- parsed IKE_SA_INIT response;
- selected IKE proposal;
- generated and parsed IKE_AUTH;
- established IKE_SA;
- established CHILD_SA.

Crypto values are emitted only from the parsed negotiation result. CHILD_SA and tunnel-active transitions additionally require the existing independent `swanctl` and XFRM checks. If a detailed log marker is absent, the corresponding fine-grained event is omitted; it is never invented to fill a visual step.

ESP activity is computed from a stable capture snapshot and emitted in action-level batches. It includes observed packet and byte deltas, direction totals, peer validation, and the captured time range. The UI must not animate packet flow when no new real ESP observation exists.

## 10. Capture lifecycle and analysis boundaries

### 10.1 Continuous full-evidence capture

`SecureSession.start_captures()` runs before IKE initiation. Its capture remains open across connect, all traffic actions, refreshes, and rekeys. It stops only when:

- analysis seals the session capture;
- disconnect occurs before analysis; or
- failure handling stops it.

The existing immediate-write capture mode is retained. A flush/snapshot facility may signal `tcpdump` and copy a stable prefix for live parsing, but it must not stop or replace the authoritative capture. Snapshot parsing must tolerate an in-progress final record and retry boundedly rather than treating incomplete data as evidence.

### 10.2 Workload windows

Every traffic action records:

- workload ID and generator version;
- server-selected random seed;
- generator parameters;
- start timestamp immediately before the generator begins protected traffic;
- end timestamp immediately after generator validation succeeds;
- validation and cleanup outcome;
- full-capture packet/byte deltas.

Failed workloads remain recorded but do not become the ML source. The `latest_completed_workload` pointer advances only after generator validation succeeds.

### 10.3 Sealing and derived ML capture

Analysis first transitions to `ANALYZING`, stops and seals `full-evidence.pcap`, validates it, and derives `encrypted.pcap` deterministically from only the latest completed workload interval. The strict existing parser must prove that the derived capture contains:

- ESP only;
- only the expected transit peers;
- timestamps inside the selected workload window;
- no UDP/500;
- no UDP/4500;
- no IKE establishment or rekey material;
- no unrelated plaintext packets.

If this validation fails, analysis fails and no ML inference is presented. A prior Ping followed by Video therefore yields Video-only ML input, while the full capture retains Ping, Video, IKE, and rekey evidence for security analysis.

### 10.4 Analyzer and ML integration

The analyzer gains an optional workload-capture input while keeping the existing call behavior unchanged:

```python
analyze_capture(
    full_capture_path,
    *,
    model_dir=...,
    evidence_dir=...,
    traffic_capture_path=None,
)
```

When `traffic_capture_path` is omitted, offline behavior is unchanged. For Live Lab:

- protocol, IKE, SA, ESP, PFS, chronology, and security evidence use `full-evidence.pcap` plus the existing active evidence sources;
- traffic inference and workload X-Ray features use only validated `encrypted.pcap`;
- the output remains `ipsec-sentinel.analysis/v1`;
- evidence records disclose the distinct capture source used by ML;
- the model label remains `AI_INFERRED` and confidence remains `raw_uncalibrated`;
- payload visibility remains `0%` and `payload_decrypted` remains literal `false`.

Security results and final normalized score appear only after analysis completes. Prior to sufficient evidence, categories explicitly show `WAITING` or `UNKNOWN` rather than a guessed value.

## 11. Traffic actions

The interactive panel exposes the existing allowlisted generators:

- `icmp` — Ping Server;
- `web` — Browse Test Site;
- `video` — Start Video Stream;
- `voip` — Simulate VoIP;
- `email` — Send Email;
- `messaging` — Send Messages;
- `file_transfer` — Transfer File.

Each action uses the common generator lifecycle `prepare()`, `run()`, `validate()`, `cleanup()`, and `metadata()` with a recorded seed. Generator cleanup runs even when execution or validation fails. Traffic occurs only inside the protected client namespace and targets only the controlled lab server.

Phase A's required proof runs ICMP and Video interactively. Other buttons reuse the same integration and are covered by unit/service tests plus existing privileged generator regressions.

## 12. Rekey and PFS semantics

`Trigger Rekey` invokes the existing real CHILD_SA rekey machinery. Before and after evidence captures `swanctl` state, XFRM state/policy, strongSwan log segment, CHILD_SA proposal, SPI transition, and capture chronology.

The UI first shows the request, then updates SA chronology only after a replacement CHILD_SA is observed. It reports:

- `PFS VERIFIED` only when the configured PFS policy and fresh CHILD_SA DH evidence satisfy the existing verification rules;
- `PFS DISABLED` only for the allowlisted no-PFS scenario when configured and observed absence semantics agree;
- `UNKNOWN` or failed verification when evidence is insufficient.

Passive packet timing or an arbitrary SPI change alone is not promoted to proof of PFS.

## 13. Mystery VPN confidentiality

Creating a Mystery session causes the agent to select one of the four validated scenarios using a server-side secure choice. The client receives only a display alias such as `Mystery VPN #03`.

Before reveal, the following are prohibited from responses and ordinary events unless independently observed by Sentinel:

- internal scenario ID;
- configured proposal;
- intended PFS setting;
- provider-private endpoint configuration;
- ground-truth file names or paths that encode the scenario.

Observed or derived analyzer values may appear progressively because they are experimental results, not leaked configuration. `POST /reveal` is accepted only after `READY` and returns a provenance-labelled comparison of Sentinel results and ground truth. The reveal itself is appended as an event.

## 14. REST API

The Phase A API is:

```text
GET  /api/lab/scenarios
POST /api/lab/sessions
GET  /api/lab/sessions/{id}
GET  /api/lab/sessions/{id}/events
POST /api/lab/sessions/{id}/connect
POST /api/lab/sessions/{id}/traffic
POST /api/lab/sessions/{id}/rekey
POST /api/lab/sessions/{id}/refresh
POST /api/lab/sessions/{id}/analyze
POST /api/lab/sessions/{id}/reveal
POST /api/lab/sessions/{id}/disconnect
```

`GET /events` is the SSE stream. The traffic request body contains only an allowlisted workload ID. Session creation contains an allowlisted scenario ID or the literal Mystery selector. Seeds are generated and returned by the server rather than accepted as arbitrary runtime controls in the primary UI.

Responses use stable problem objects:

```json
{
  "error": {
    "code": "TUNNEL_NOT_ACTIVE",
    "message": "Traffic requires an active verified tunnel.",
    "session_id": "SNT-8A31D2F0"
  }
}
```

Session snapshots are projections of persisted state, not an alternate source of fabricated progression. They include the latest event ID so a client can establish the correct replay boundary.

## 15. Failure handling, cleanup, and startup recovery

Every action failure records the original exception category, operation, diagnostics, and a user-safe message, transitions to `FAILED`, and enters cleanup in a `finally` path when tunnel integrity cannot be retained. A recoverable workload failure may return to `TUNNEL_ACTIVE` only if explicit SA, XFRM, capture-process, and provider health checks all pass.

Cleanup is idempotent and scoped. It removes or stops:

- the four owned namespaces and their veth interfaces;
- owned strongSwan processes and runtime/VICI paths;
- owned `tcpdump` processes;
- temporary routes, XFRM state/policy, and traffic-control state;
- generator services and temporary payloads;
- session locks and temporary runtime records.

The runtime-ownership file records exact resource names, PIDs, process start identities, and paths. Startup recovery:

1. acquires the exclusive Live Lab lock;
2. refuses to start if a verified live owner still holds it;
3. reads an abandoned ownership record if present;
4. terminates a recorded PID only when `/proc` identity and start metadata still match;
5. invokes the existing scope-limited topology reset for exact known resource names;
6. removes only recorded Live Lab runtime paths;
7. preserves prior session evidence and records recovery outcome.

There are no wildcard process kills, broad recursive deletes, or cleanup of unrelated namespaces. The topology's fixed names are the reason only one session may own the lab at a time.

## 16. Frontend experience

### 16.1 Entry and navigation

The home experience is ordered:

1. **Start Live Lab** — primary call to action;
2. **Offline PCAP Analysis** — secondary;
3. **Guided Demo** — fallback.

Primary product navigation becomes Live Lab, Tunnel, Traffic, Security, Evidence, and Report, with Offline PCAP separately accessible. Existing polished components are retained and adapted to live state.

### 16.2 Event-driven session UI

A Live Lab context owns an SSE client and a deterministic reducer over the event schema. The frontend never schedules product-state transitions with timers. On network interruption it reconnects with the last applied event ID; replay reconstructs state without clearing the timeline or briefly displaying default final values.

The compact session header shows session ID, display VPN name, redacted or known endpoint, tunnel status, and capture status. Action buttons are enabled from the server-provided `allowed_actions` set, not from optimistic client guesses.

### 16.3 Tunnel, traffic, and X-Ray

The tunnel visualization moves from connecting to active only on the verified tunnel event. ESP flow appears only when a real `esp.observed` batch reports a positive delta. Workload events identify the generator and its validated completion.

X-Ray renders real sizes, timestamps, directions, bursts, and density from the latest workload window. Prediction UI is absent until that window has been validated and inference completes.

### 16.4 Security, evidence, and report

Before analysis, security categories show collecting/waiting/unknown states. Rekey evidence may progressively update the PFS category, but the final analysis and normalized score are rendered only from `ipsec-sentinel.analysis/v1`. Existing Evidence and Report views continue to distinguish observed, derived, AI-inferred, and ground-truth provenance.

## 17. Observability

All logs and artifacts are associated with the session ID. Separate logs are retained for orchestration, provider lifecycle, strongSwan, traffic generators, capture, and analyzer activity. The default UI shows curated persisted events; raw logs remain diagnostic artifacts and are not streamed indiscriminately.

Logs must redact secrets and must not include the unrevealed Mystery scenario in user-facing event records. Server-side logs may retain a protected scenario mapping for diagnosis.

## 18. Testing strategy

Implementation follows test-driven development and preserves existing Phase 1, Phase 2, analyzer, ML, bridge, frontend, and Playwright suites.

### Unit tests

- complete state-transition and allowed-action table;
- invalid action rejection and busy-action rejection;
- one-active-session enforcement;
- event ordering, timestamps, JSONL persistence, crash-tail handling, and replay boundaries;
- SSE `Last-Event-ID` behavior and idle heartbeats;
- Mystery serialization/redaction/reveal rules;
- latest-successful-workload selection for ML;
- full-capture versus workload-capture analyzer routing;
- cleanup idempotency and separate cleanup failure status;
- safe stale-resource ownership validation and recovery;
- provider contract behavior;
- frontend reducer replay and duplicate-event handling.

### Service integration tests

- REST command acceptance and asynchronous completion;
- reconnecting SSE clients receive no gaps or duplicates;
- server restart rehydrates terminal/session history safely;
- concurrent create returns `ACTIVE_SESSION_EXISTS`;
- unavailable endpoint produces a clean failure and cleanup;
- loopback and allowlist enforcement.

### Privileged local integration

A real local flow must prove:

1. session creation and sandbox setup;
2. capture starts before IKE;
3. secure-baseline IKEv2 and CHILD_SA establishment;
4. real parsed IKE/tunnel events;
5. interactive ICMP completion and ESP observation;
6. interactive Video completion and ESP observation;
7. Video-only ML capture and inference after ICMP then Video;
8. genuine CHILD_SA rekey, new SPI evidence, and PFS verification;
9. full-session analysis while tunnel state remains coherent;
10. disconnect and complete resource cleanup;
11. SSE reconnect/replay during the active session;
12. rejection of a second concurrent session.

After cleanup, tests independently verify absence of owned namespaces, interfaces, strongSwan processes, capture processes, routes, locks, and runtime paths.

### Browser end-to-end tests

Playwright covers the real local happy path from Start Live Lab through disconnect, the Video/X-Ray/ML path, rekey evidence, SSE reconnection/state restoration, and endpoint failure presentation. Deterministic in-memory/service fixtures may support frontend edge cases, but they do not replace the privileged real-network Playwright proof.

## 19. Delivery gates

Implementation proceeds in these gates after this specification is reviewed:

1. persisted state machine, event store, SSE replay, and command validation;
2. provider boundary and interactive `SecureSession` refactor with full regression run;
3. real local connect and continuous evidence capture;
4. ICMP and Video workload windows, live ESP summaries, and isolated ML input;
5. rekey/PFS, analyzer, and security result integration;
6. Live Lab frontend conversion and SSE reconstruction;
7. privileged API and Playwright end-to-end verification;
8. cleanup/stale-recovery audit and complete regression run.

Every gate must pass before the next one begins. No implementation may silently weaken existing capture validation, PFS semantics, cleanup guarantees, or the analysis contract.

## 20. Cloud checkpoint

After all local requirements pass, work stops before any cloud operation. The handoff report is titled exactly:

```text
GCP ACCESS REQUIRED
```

It will enumerate proposed resources, region, machine types, VM/public-IP count, firewall and protocol requirements, NAT-T choice, costs, IAM roles, exact user-run `gcloud` commands, credential approach, shutdown/destruction procedure, security implications, APIs, and the complete local verification evidence.

No Google Cloud credentials are requested and no billable or destructive cloud command is run before explicit approval after that report.

## 21. Acceptance criteria

Phase A is complete only when all of the following are demonstrated with real local evidence:

- the agent is loopback-only and permits one active session;
- the frontend creates a sandbox and establishes a real IPsec tunnel;
- real IKE, CHILD_SA, XFRM, and ESP observations drive the UI;
- ICMP and Video run interactively through the protected tunnel;
- ML uses only the latest completed workload window;
- full-session security analysis remains independent of ML-window capture;
- a genuine rekey updates SPI and PFS evidence correctly;
- Mystery ground truth remains private until reveal;
- analysis updates the existing security, evidence, X-Ray, and report UI;
- SSE reconnect replays persisted events and restores current state;
- invalid and concurrent commands are rejected cleanly;
- disconnect and failure cleanup are complete and idempotent;
- stale startup resources are safely recovered;
- existing offline analysis and Guided Demo behavior remain intact;
- all relevant unit, backend, privileged integration, frontend, lint, build, and Playwright tests pass;
- no cloud resource has been created.

