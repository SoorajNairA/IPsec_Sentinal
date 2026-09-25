# IPsec Sentinel Dataset Expansion Specification

**Status:** Proposed for review  
**Date:** 2026-09-25  
**Base commit:** `6460d234deabdf9e295f7e48fb57fe5039f0cc0f`  
**Target branch:** `feat/ipsec-sentinel-dataset-expansion`

## 1. Purpose

This phase expands the validated Phase 2 dataset factory without replacing its networking foundation. It adds four supervised traffic generators, two evaluation-only out-of-distribution (OOD) workloads, three additional allowlisted IPsec scenarios, and two controlled network-impairment profiles.

The phase produces only enough real traffic to validate the new dimensions. It does not extract features, clean data for machine learning, split datasets, train models, or implement inference.

## 2. Compatibility and Safety Requirements

The implementation must preserve:

- the Phase 1 namespace topology and real IKEv2/IPsec behavior;
- the backward-compatible `run_secure_baseline()` entry point;
- Phase 2 retry, resume, recovery, and SQLite manifest semantics;
- separate `full-evidence.pcap` and workload-only `encrypted.pcap` artifacts;
- strict ESP-only parsing of `encrypted.pcap`;
- per-attempt immutable artifacts and diagnostics;
- separate primary run state and cleanup outcome;
- serial execution; and
- seeded, recorded, reproducible workload intent.

The expansion branch remains stacked on the validated Phase 2 commit until its dependency is merged. The work must not be rebased onto stale `main`, merged, or pushed automatically.

## 3. Success Criteria

The phase is complete only when:

1. Phase 1 and all existing Phase 2 behavior still pass.
2. VoIP, Email, Messaging, and File Transfer each complete a real privileged end-to-end dataset run.
3. At least one run of each OOD workload completes, remains marked evaluation-only, and is excluded from supervised selection.
4. Every generator demonstrates deterministic planning for equal seed/config/version and meaningful variation for different seeds.
5. Every additional IPsec scenario is independently proven with IKE SA, CHILD SA, XFRM state/policy, protected traffic, ESP capture, and configured-versus-observed evidence.
6. PFS-enabled scenarios retain rekey-based verification, while the no-PFS scenario records and verifies the intended absence of CHILD-SA DH/PFS.
7. Network impairments are deterministic, recorded, validated, and removed after every attempt.
8. The extension smoke contains approximately 11 independent sessions only.
9. Capture validation proves every `encrypted.pcap` contains only expected-peer ESP packets from the workload window and contains no IKE, UDP/4500, rekey, or unrelated plaintext traffic.
10. Resume, retry, recovery, cleanup, and manifest/filesystem agreement remain correct.
11. A final leakage review finds no unaddressed laboratory shortcut.

## 4. Non-Goals

This phase does not build:

- feature extraction or pandas training tables;
- dataset cleaning for ML;
- train/validation/test splitting;
- any classifier or neural network;
- calibration or OOD-rejection models;
- inference APIs, user interfaces, security assessment, LLM, or report features; or
- a full production dataset during the interactive development session.

## 5. Architectural Approach

The existing Phase 2 run orchestrator remains the single owner of the tightly coupled lifecycle:

1. allocate an immutable attempt;
2. establish the selected IPsec scenario;
3. start full-session evidence capture;
4. verify the initial IKE and CHILD SAs;
5. apply and verify the selected network profile;
6. prepare the selected local workload;
7. mark the workload-window start;
8. run and validate the workload;
9. mark the workload-window end;
10. remove any active impairment;
11. perform scenario-specific rekey/PFS verification;
12. stop the full capture;
13. deterministically derive `encrypted.pcap` from the workload window;
14. validate both captures and all ground truth;
15. persist status, summaries, and cleanup outcome; and
16. clean the generator, impairment, tunnel, namespaces, services, and runtime paths idempotently.

Traffic generators, IPsec scenarios, and network profiles are registries consumed by this common lifecycle. They must not create their own tunnel or capture boundaries.

## 6. Traffic-Class and OOD Invariants

### 6.1 Supervised allowlist

The only normal supervised classes are:

```text
icmp
web
video
voip
email
messaging
file_transfer
```

Every registry entry for these classes has `known_training_class: true`.

### 6.2 Evaluation-only allowlist

The controlled OOD workloads are:

```text
remote_desktop_like
database_query_like
```

Every registry entry and persisted run for these workloads has `known_training_class: false`. These names describe behavioral simulations. They do not claim to implement or reproduce a particular commercial remote-desktop product or database wire protocol.

### 6.3 Hard supervised-selection invariant

Future Phase 3 training-set construction must require both:

```text
known_training_class == true
AND
traffic_class in {
  icmp, web, video, voip, email, messaging, file_transfer
}
```

Neither condition is sufficient alone. This dual check prevents an OOD run from entering supervised training if a label, matrix file, or manifest field is later edited incorrectly.

The authoritative generator registry defines class role. Matrix parsing must reject an OOD class in the supervised `traffic.classes` list and reject a supervised class in the OOD list. Dataset validation must cross-check the registry role against `traffic.json`, run metadata, and manifest fields. A mismatch makes the attempt invalid and not training-ready.

`training_ready` continues to mean that the run passed dataset-quality checks; it does not imply supervised eligibility. A valid OOD attempt may be quality-ready for evaluation while remaining categorically excluded from supervised training by the dual invariant.

## 7. Common Generator Contract

All generators preserve the established interface or its exact equivalent:

- `prepare()`: allocate local services and deterministic resources;
- `run()`: execute only the planned protected workload;
- `validate()`: independently prove expected delivery and class ground truth;
- `cleanup()`: remove generator-owned state idempotently; and
- `metadata()`: return the complete seed, generator identity/version, selected parameters, validation results, and class role.

Each generator must be local, controlled, unattended-safe, and independent of public services. The plan derived from `generator version + seed + scenario inputs` must be reproducible where practical. Packet timestamps and complete PCAP bytes need not be identical.

### 7.1 Shared seeded port selection

Generators use one common seeded port allocator rather than permanent class-specific ports. Ports are drawn without collision from a documented unprivileged range, initially `20000-29999`, using the run seed plus a stable purpose key.

The selected ports are recorded in `traffic.json`, validated as available during preparation, and never used as class labels. Retry attempts for the same slot and seed reproduce the same planned ports unless an explicitly recorded deterministic collision fallback is required.

Because ESP hides inner transport headers, ports are not visible in the intended encrypted feature input. Shared allocation still prevents ports, service setup, or future plaintext diagnostics from becoming a trivial class identifier.

### 7.2 Shared service behavior

All local servers bind only inside the protected server namespace. Generators use common startup/readiness/termination helpers, consistent validation timeouts, and randomized-but-recorded short readiness-to-workload gaps. Service startup must finish before the workload capture window begins.

## 8. Supervised Generator Designs

### 8.1 VoIP

The initial VoIP generator is an explicitly documented synthetic RTP-like workload using valid RTP version-2 headers over UDP. It models voice cadence; it is not described as a full SIP/PBX or audio-codec implementation.

Seeded parameters include:

- call duration, initially sampled from approximately 3.5-7 seconds for smoke runs;
- packetization interval from a supported set such as 10, 20, or 30 ms;
- RTP payload-size profile and bounded per-packet variation;
- initial sequence number, timestamp offset, and SSRC;
- bidirectional activity ratio;
- alternating talk-spurt and silence/suppression pattern; and
- small controlled start offsets between directions.

Both peers send and receive. Validation checks expected call duration tolerance, per-direction datagram delivery, RTP sequence/timestamp structure, packet-count ranges derived from the recorded plan, and successful transport across the protected networks. Metadata must say `rtp_like_synthetic: true`.

### 8.2 Email

Email uses a lightweight real local SMTP workflow. A controlled SMTP receiver runs in the protected server namespace, accepts MIME messages, and writes a receipt ledger with message identifiers, byte counts, attachment digests, and transaction outcomes.

Seeded parameters include:

- two to five sequential SMTP transactions;
- message order and body sizes;
- presence, count, and size of attachment-like MIME parts;
- recipient count within a small local set;
- think-time gaps; and
- connection reuse versus reconnect behavior.

Validation requires successful SMTP completion and exact agreement between the planned message ledger and the server receipt ledger, including attachment checksum where present. No external email provider, DNS delivery, IMAP, or POP is required.

### 8.3 Messaging

Messaging uses a persistent bidirectional, length-framed TCP session to model interactive chat without claiming compatibility with a commercial messaging protocol.

Seeded parameters include:

- message count and size distribution;
- burst count and burst sizes;
- short and occasional longer idle intervals;
- direction sequence and reply probability;
- occasional larger payloads; and
- bounded reconnect behavior if included in the declared generator version.

Both endpoints maintain receive ledgers. Validation checks message identifiers, direction, sizes, digests, order constraints, and receipt by the intended side.

### 8.4 File Transfer

File Transfer is a sustained bulk TCP workload and must remain behaviorally distinct from segmented, paced Video traffic.

Seeded parameters include:

- total size, initially approximately 1-8 MiB for smoke;
- upload, download, or bounded bidirectional direction;
- application write/chunk sizes;
- write grouping and limited inter-write gaps; and
- deterministic payload-generation seed.

The workload has no media-segment sequence or playback pacing. Validation checks exact transferred byte counts, successful completion, and end-to-end SHA-256 digest.

## 9. Evaluation-Only OOD Generator Designs

### 9.1 `remote_desktop_like`

This is a controlled behavioral simulation of interactive display/control traffic, not an implementation of RDP, VNC, or another commercial protocol.

It combines small client-to-server input-event bursts with irregular server-to-client update bursts. Seeded parameters include input-event clusters, update sizes, burst density, idle gaps, direction ratios, and occasional larger screen-update-like payloads. Validation checks both directional ledgers and the recorded request/update relationship.

### 9.2 `database_query_like`

This is a controlled behavioral simulation of database query/response traffic, not an implementation of a specific database wire protocol.

It uses a persistent framed connection with small query-like requests followed by variable response sets. Seeded parameters include query count, request sizes, response-row counts, row-size profiles, think times, transaction-group boundaries, and occasional larger result sets. Validation checks request/response identifiers, expected response totals, byte counts, and digests.

## 10. Preventing Fixed Synthetic-Generator Fingerprints

Controlled workloads are acceptable only if a class cannot be recognized from one invariant implementation template. Every new generator must vary meaningful behavior through its recorded seed while retaining its class semantics.

At minimum, tests and smoke evidence must cover variation in:

- VoIP packetization interval, RTP payload-size distribution, duration, talk-spurt structure, and bidirectional activity;
- Email message sizes, attachment sizes, SMTP transaction count, ordering, timing, and connection behavior;
- Messaging burst sizes, idle intervals, message sizes, direction sequences, and reply patterns;
- File Transfer direction, total size, write/chunk behavior, and bounded gaps; and
- OOD request/update or request/response burst and timing characteristics.

Same seed, generator version, and scenario must yield the same planned parameters. Different tested seeds must differ in more than identifiers or payload bytes: at least one traffic-shaping parameter and one volume/timing/direction parameter must change where the generator design permits.

The final review must compare parameter plans and observed packet/byte/duration summaries within each class to identify accidental fixed templates or near-identical sessions.

## 11. Allowlisted IPsec Scenarios

Scenarios are explicit registry entries, not arbitrary proposal strings from dataset configuration. This protects unattended execution and makes evidence expectations scenario-specific.

| Scenario | IKE proposal | CHILD/ESP proposal | Intended CHILD PFS |
|---|---|---|---|
| `secure-baseline` | `aes256gcm16-prfsha384-ecp384` | `aes256gcm16-ecp384` | ECP-384 |
| `aes128-gcm` | `aes128gcm16-prfsha384-ecp384` | `aes128gcm16-ecp384` | ECP-384 |
| `aes256-cbc` | `aes256-sha256-prfsha384-ecp384` | `aes256-sha256-ecp384` | ECP-384 |
| `no-pfs` | `aes256gcm16-prfsha384-ecp384` | `aes256gcm16` | Disabled |

The AES-128 and AES-256-GCM variants keep ECP-384 constant so encryption strength is the intended changed dimension. ECP-256 must not replace ECP-384 unless a concrete compatibility failure is reproduced and documented. The installed environment has been probed and reports AES-GCM, AES-CBC, HMAC-SHA2-256-128, PRF-HMAC-SHA2-384, ECP-256, and ECP-384 support.

### 11.1 Scenario validation

Before a scenario enters any dataset matrix, an ICMP validation run must independently prove:

- IKE SA establishment and negotiated IKE algorithms;
- CHILD SA establishment and negotiated ESP algorithms;
- matching XFRM state and policy on both gateways;
- client-to-server protected ICMP;
- real protocol-50 ESP between the expected transit peers;
- agreement between configured and observed algorithms; and
- scenario-specific PFS evidence.

Configured policy, observed evidence, and verification state are separate persisted fields.

For the three PFS-enabled scenarios, initial CHILD-SA configuration is only configured-policy evidence. PFS is verified only after a CHILD-SA rekey produces a fresh DH exchange and the new CHILD SA/XFRM state is observed.

For `no-pfs`, the scenario must verify that the CHILD proposal omits a DH group and that CHILD-SA creation/rekey evidence shows no CHILD DH/PFS exchange. It records `configured: disabled`, the observed absence evidence, and a positive verification result for the intended disabled state. Absence must not be reported as a failed PFS-enabled check.

## 12. Network Profiles

The allowlisted profiles are:

| Profile | Initial egress netem parameters |
|---|---|
| `clean` | no qdisc impairment |
| `moderate_latency` | `delay 50ms` |
| `jitter_loss` | `delay 25ms 5ms distribution normal loss random 0.5%` |

Impairment is applied symmetrically to each gateway's transit-facing egress interface after tunnel establishment and before the workload window. The kernel-supported netem seed is derived from the run seed and recorded. Exact command-equivalent parameters, interface targets, seed, apply timestamp, verification output, removal timestamp, and cleanup result are stored in ground truth.

The profile implementation must:

1. validate the target interface and selected allowlisted parameters;
2. remove stale root qdiscs before applying the selected profile;
3. apply the impairment deterministically;
4. read back `tc qdisc` state and reject disagreement;
5. remove the qdisc in normal and exceptional cleanup; and
6. verify that no impairment remains before the next attempt.

`clean` also verifies absence of an unintended netem qdisc. Network-profile cleanup is idempotent and its outcome remains separate from primary run status.

## 13. Dataset Matrix Design

The existing configuration architecture is extended, not replaced. The normal matrix remains a Cartesian selection over:

- supervised traffic classes;
- allowlisted IPsec scenarios;
- allowlisted network profiles; and
- runs per combination.

Evaluation-only OOD classes are selected in a separate section and expanded independently. An illustrative configuration is:

```yaml
dataset:
  name: cipherlens-v1

traffic:
  classes:
    - icmp
    - web
    - video
    - voip
    - email
    - messaging
    - file_transfer

ipsec:
  scenarios:
    - secure-baseline
    - aes128-gcm
    - aes256-cbc
    - no-pfs

network_profiles:
  - clean
  - moderate_latency

runs_per_combination: 5

evaluation:
  ood_classes:
    - remote_desktop_like
    - database_query_like
  runs_per_combination: 3
```

The matrix fingerprint includes normalized class selections and class roles, generator versions, scenario IDs and scenario-definition digest, profile IDs and normalized parameters, run counts, schema versions, and seed policy.

For targeted validation, configuration additionally supports an explicit `cases` list. Explicit cases use the same validation and persistence path but select exact traffic/scenario/profile combinations rather than expanding a full Cartesian matrix. Mixing `cases` with Cartesian selectors is rejected. This enables the exact extension smoke without accidentally generating a large experiment.

Existing Phase 2 matrix files containing only `traffic.classes`, `ipsec.scenarios`, and `network_profiles: [clean]` remain valid and supervised-only.

## 14. Persistence and Summary Compatibility

Schema changes are additive and versioned. Existing Phase 2 manifests remain readable. New persisted data includes:

- authoritative `known_training_class` and class role;
- generator ID and version;
- IPsec scenario ID and scenario-definition version/digest;
- network profile ID, version, parameters, and netem seed;
- configured-versus-observed algorithm/PFS evidence;
- per-attempt workload duration, ESP packet count, and ESP byte count; and
- generator validation ledgers or their digests.

The SQLite manifest receives an idempotent migration rather than destructive recreation. Recovery, retry history, successful-slot skipping, exhausted retries, fingerprint mismatch rejection, and the prohibition on regenerating successful slots remain unchanged.

Summaries report, separately for supervised and OOD sets:

- independent session counts by class, scenario, and profile;
- ESP packet and byte counts by class;
- workload duration by class;
- PASS/FAILED/INCOMPLETE counts;
- cleanup outcomes; and
- artifact/manifest consistency.

No retry may overwrite a previous attempt directory, and no failure may be hidden by a later successful retry.

## 15. Capture and Lifecycle Invariants

`full-evidence.pcap` remains the complete session record and preserves IKE establishment, protected workload traffic, and rekey/PFS evidence where applicable.

`encrypted.pcap` is derived deterministically from the full capture using the recorded workload start/end boundary. The strict parser must prove:

- link/network decoding is valid;
- every included packet is protocol-50 ESP;
- every packet is between the expected `192.0.2.x` transit peers;
- at least one valid ESP packet is present;
- no UDP/500 IKE packet is present;
- no UDP/4500 packet is present;
- no plaintext or unrelated packet is present; and
- establishment and post-workload rekey packets fall outside the derived window.

Generator services must be ready before the start boundary. Scenario rekey must begin only after the end boundary. Adding new generators, scenarios, or profiles must not weaken these rules.

## 16. Extension Smoke Matrix

The interactive development session generates approximately 11 successful sessions:

| # | Traffic | IPsec scenario | Network profile | Role |
|---:|---|---|---|---|
| 1 | `voip` | `secure-baseline` | `clean` | supervised |
| 2 | `email` | `secure-baseline` | `clean` | supervised |
| 3 | `messaging` | `secure-baseline` | `clean` | supervised |
| 4 | `file_transfer` | `secure-baseline` | `clean` | supervised |
| 5 | `remote_desktop_like` | `secure-baseline` | `clean` | OOD evaluation |
| 6 | `database_query_like` | `secure-baseline` | `clean` | OOD evaluation |
| 7 | `icmp` | `aes128-gcm` | `clean` | supervised |
| 8 | `icmp` | `aes256-cbc` | `clean` | supervised |
| 9 | `icmp` | `no-pfs` | `clean` | supervised |
| 10 | `icmp` | `secure-baseline` | `moderate_latency` | supervised |
| 11 | `icmp` | `secure-baseline` | `jitter_loss` | supervised |

These sessions prove dimensions; they are not the first full dataset. If a case fails, work stops at that validation layer until corrected. The implementation must not compensate by launching a larger matrix.

## 17. Testing and Integration Gates

### 17.1 Unit and contract tests

Tests cover:

- each new generator's complete metadata and validation contract;
- equal-seed planning reproducibility and different-seed meaningful variation;
- shared port allocation, collision handling, and absence of fixed class ports;
- supervised/OOD registry roles and dual eligibility filtering;
- matrix Cartesian and explicit-case expansion;
- rejection of class-role, scenario, and profile mismatches;
- scenario proposal parsing and configured-versus-observed comparison;
- PFS-enabled and deliberately disabled evidence semantics;
- network-profile parsing, deterministic seed, readback, and idempotent cleanup;
- additive manifest migration and old-manifest compatibility;
- retry/resume/recovery/fingerprint behavior; and
- strict capture parsing.

### 17.2 Privileged integration gates

Real privileged tests, without mocking the critical path, must prove:

- Phase 1 secure baseline;
- existing Phase 2 ICMP, Web, and Video behavior;
- one successful secure-baseline run for each of VoIP, Email, Messaging, and File Transfer;
- at least one successful evaluation-only OOD run;
- one ICMP validation run for every new IPsec scenario;
- the selected network impairment is observed and then absent after cleanup; and
- every new run preserves full-evidence/ML-capture separation.

### 17.3 Final dataset validation

The smoke is accepted only if manifest, summaries, and filesystem artifacts agree; all 11 sessions are independent; class roles are correct; captures are non-empty and valid; workload ground truth matches generator ledgers; algorithms and PFS evidence match scenario intent; parameters vary between tested seeds; and no stale namespace, daemon, socket, qdisc, route, or XFRM state contaminates later runs.

## 18. Accidental-Shortcut Review

Before bulk generation, the review must explicitly ask:

> Could a classifier achieve high accuracy using accidental laboratory artifacts rather than traffic behavior?

The review examines:

- fixed ports;
- class-specific IP addresses;
- unique run durations;
- service startup timing;
- tunnel establishment or rekey timing;
- fixed payload sizes;
- fixed directionality patterns;
- generator-specific packet counts;
- IPsec-scenario imbalance;
- network-profile imbalance;
- capture-boundary placement; and
- any generator-specific metadata that a future feature pipeline might accidentally ingest.

Obvious shortcuts must be removed. Any unavoidable artifact must be documented with its expected effect and a Phase 3 mitigation. The review compares planned parameters and observed session summaries within and across classes, and specifically checks for accidental synthetic-generator fingerprints.

Future feature extraction must consume only approved features derived from `encrypted.pcap`; it must not ingest `traffic.json`, class labels, ports from plaintext generator metadata, scenario names, seeds, file paths, run ordering, full-evidence establishment/rekey data, or manifest fields that reveal the target.

## 19. Recommended First Full Dataset

After the extension smoke and review pass, the first unattended dataset is:

### 19.1 Supervised

```text
7 traffic classes
x 4 IPsec scenarios
x 3 network profiles
x 5 independent runs
= 420 supervised sessions
```

### 19.2 OOD evaluation

```text
2 OOD workloads
x 4 IPsec scenarios
x 3 network profiles
x 3 independent runs
= 72 OOD sessions
```

Total: 492 sessions.

The OOD sessions remain in a separate evaluation selection and never contribute to normal supervised training. Raw packet counts are not artificially equalized; balance is based on independent experimental sessions. Per-class packet, byte, and duration distributions are reported for later Phase 3 weighting and sampling decisions.

The implementation must provide a checked-in matrix configuration and an unattended, resumable invocation equivalent to:

```powershell
python -m ipsec_sentinel.dataset run --config configs/datasets/cipherlens-v1.yaml --output datasets/cipherlens-v1 --resume
```

The exact command, runtime estimate, and storage estimate are finalized from observed extension-smoke samples. Bulk generation is not run during this phase's interactive implementation session.

## 20. Documentation Deliverables

Implementation must update operator documentation with:

- generator semantics and synthetic-workload disclosures;
- all seeded parameters and validation evidence;
- supervised/OOD selection invariants;
- IPsec scenario proposals and PFS semantics;
- network-profile commands, validation, and cleanup;
- extension-smoke invocation;
- unattended bulk command and interruption/resume procedure;
- per-class/session/packet/byte/duration reporting;
- leakage and generator-fingerprint review findings; and
- known limitations.

## 21. Branch and Review Policy

This specification is the only deliverable in the current review step. No production or test implementation begins until it is reviewed and approved.

The eventual implementation remains on `feat/ipsec-sentinel-dataset-expansion`, stacked on Phase 2 while Phase 2 is unmerged. Nothing is merged, rebased, pushed, or automatically opened as a pull request without a later explicit instruction.
