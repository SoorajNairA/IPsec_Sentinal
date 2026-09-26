# IPsec Sentinel External Dataset Integration Specification

**Status:** Proposed for review  
**Date:** 2026-09-26  
**Base commit:** `865d93803f7af987a55cf2c8c2a7e7f9151c09bf`  
**Target branch:** `feat/ipsec-sentinel-external-datasets`

## 1. Purpose

This work establishes a provenance-first, storage-safe way to acquire, inspect, catalog, and normalize selected public VPN datasets for later external evaluation of IPsec Sentinel. It is intentionally separate from the native IPsec dataset factory and from the independently running 168-session collection.

The first source set is:

1. USBVPN2022 / Encrypted VPN Dataset;
2. the 2026 WireGuard, OpenVPN, and strongSwan/IPsec dataset;
3. the MIT Lincoln Laboratory VPN/Non-VPN Network Application Traffic Dataset (VNAT); and
4. ISCXVPN2016 metadata, without its full initial download.

This phase inventories what the sources actually contain, verifies downloaded artifacts, defines explicit label mappings, and introduces a separate normalization boundary. It does not combine public and native data or retrain a model.

## 2. Safety, Isolation, and Compatibility Invariants

The implementation must preserve all of the following:

- The active native collector is not signaled, restarted, reconfigured, or inspected through its mutable runtime resources.
- No changes are made in the collector's worktree while collection is active.
- The external-dataset branch remains stacked on validated commit `865d93803f7af987a55cf2c8c2a7e7f9151c09bf` unless a later, explicit integration decision changes its base.
- Public archives, packet data, extracted files, normalized observations, and caches never enter Git or the OneDrive-backed repository.
- The native `encrypted.pcap` reader remains strict ESP-only and fail-closed. Supporting external formats must not weaken, add fallbacks to, or bypass that parser.
- Native manifest eligibility and native supervised-training selection remain unchanged.
- Source identity, filenames, paths, native labels, VPN protocol, session identifiers, and other provenance fields must never become classifier feature columns.
- No public data is appended to the native dataset, used to refit preprocessing, or used for model training during this phase.

All implementation and ordinary tests run in the isolated external-dataset worktree. Privileged integration tests are unnecessary for public-file adapters and must not be run merely to validate this work while the collector is active.

## 3. Goals and Non-Goals

### 3.1 Goals

The phase must:

- maintain a tracked source registry with stable identifiers, official citations, acquisition details, format/protocol declarations, licensing evidence, checksums, and intended use;
- place large mutable artifacts under a configurable WSL ext4 root, initially `/home/black/ipsec-sentinel-external-datasets`;
- acquire only the approved, bounded artifacts with resumable and atomic download behavior;
- compare locally computed digests with publisher-provided digests when those exist;
- inspect archive/table structure before finalizing any source-specific adapter;
- normalize compatible packet observations through an external-only layer;
- map only explicitly compatible application labels to the seven-class supervised vocabulary;
- retain unsupported or semantically incompatible labels as unmapped or OOD candidates rather than forcing them into a known class;
- produce machine-readable inventories and a human-readable compatibility report; and
- document disk use and deliberately omitted downloads.

### 3.2 Non-goals

This phase does not:

- alter the native IPsec capture lifecycle, traffic generators, scenarios, matrix, or SQLite manifest;
- relax the native ESP capture parser;
- download the VNAT 36.1 GB raw-PCAP archive;
- initially download the approximately 28 GB ISCXVPN2016 collection;
- assume that a file contains IPsec merely because a dataset title mentions VPN;
- infer encrypted inner ports, addresses, or protocols that are not present in a source;
- treat aggregate performance metrics as packet-level ML samples;
- mix external and native sessions in one training table;
- perform feature extraction over the complete external corpus before compatibility is proven;
- split, train, calibrate, evaluate, or export a new model; or
- redistribute third-party binaries.

## 4. Source Registry

### 4.1 Tracked registry and local configuration

The repository will track:

```text
metadata/external-datasets.yaml
configs/external-datasets.example.yaml
```

The registry is authoritative for source identity and policy. The example configuration documents the external root and acquisition selections without containing machine-specific secrets or paths.

A developer may create:

```text
configs/external-datasets.local.yaml
```

This file is ignored by Git. The environment variable `IPSEC_SENTINEL_EXTERNAL_DATA_ROOT` overrides its root setting for unattended use. Resolution must fail closed when the root is missing, points inside the repository, or resolves to a Windows-mounted path such as `/mnt/c` for artifacts designated as large. The initial recommended WSL ext4 root is:

```text
/home/black/ipsec-sentinel-external-datasets
```

The implementation must resolve and record the absolute data root before acquisition. It must never default large downloads into the current directory, user Downloads folder, repository, `.worktrees`, or OneDrive.

### 4.2 Registry schema

Each source record contains at least:

- stable `source_id` and display name;
- source version or record identifier;
- DOI and official landing-page URL where available;
- citation text and publication reference;
- publisher/maintainer and publication date;
- declared VPN protocols and capture/measurement formats;
- artifact entries with official download URL, publisher-declared size, and publisher checksum;
- license or terms label, evidence URL, and an explicit `redistribution_status`;
- application labels advertised by the source;
- intended IPsec Sentinel use;
- acquisition state and inspection state;
- compatible adapter identifier/version, if any;
- explicit label mappings and unmapped labels; and
- notes distinguishing publisher claims from locally observed facts.

Publisher metadata and local verification must remain separate. For example:

```yaml
publisher_checksum:
  algorithm: md5
  value: 35a4aef78526440cd6e352de49c4daf2
local_verification:
  sha256: null
  verified_at: null
  result: not_downloaded
```

An absent publisher checksum must be recorded as absent, never replaced with a locally computed digest and presented as publisher-provided.

### 4.3 Initial source records

#### USBVPN2022

- Stable source ID: `usbvpn2022`
- Official record: `https://zenodo.org/records/7301756`
- DOI: `10.5281/zenodo.7301756`
- Publisher artifact: `encrypted_vpn_dataset.zip`
- Publisher size: `811738498` bytes
- Publisher MD5: `35a4aef78526440cd6e352de49c4daf2`
- License metadata: CC BY 4.0
- Intended use: inspect the actual archive and determine whether its L2TP-IPsec subset exposes packet-level observations compatible with the external normalization contract.

The registry must not predeclare individual archive members, packet counts, traffic labels, or usable L2TP-IPsec sessions before local inspection proves them. The dataset title alone is not sufficient evidence of IPsec compatibility.

#### strongSwan/IPsec 2026

- Stable source ID: `vpn_protocol_performance_2026`
- Official record: `https://zenodo.org/records/21645499`
- DOI: `10.5281/zenodo.21645499`
- Publisher artifact: `wireguard-openvpn-ipsec-(strongswan)_dataset.zip`
- Publisher size: `4701066` bytes
- Publisher MD5: `bca99ce9a6ad9a3e2ad03c9f0b63db48`
- License metadata: CC BY 4.0
- Advertised scope: 189 observations across 63 configurations and three repetitions, covering WireGuard, OpenVPN, and strongSwan/IPsec on Raspberry Pi, VM, and WSL2 environments under clean and impaired conditions.
- Intended use: protocol/configuration/environment catalog and external evidence reference, not application-class training.

Expected publisher-described members such as `metadata.json`, environment/network snapshots, CPU data, iperf/ping results, and `ipsec_status.txt` remain expectations until archive inspection confirms their exact paths and schemas. Aggregate throughput or status observations must not be converted into synthetic packet sessions.

#### MIT Lincoln Laboratory VNAT

- Stable source ID: `mit_ll_vnat`
- Official page: `https://www.ll.mit.edu/r-d/datasets/vpnnonvpn-network-application-traffic-dataset-vnat`
- Selected artifact: `VNAT_Dataframe_release_1.h5`
- Publisher-advertised size: approximately 1.05 GB
- HTTP content length observed during design: `1045436008` bytes
- Publisher checksum: not found during initial discovery
- Advertised scope: VPN and non-VPN observations from 33,711 connections, 272 hours, ten applications, and Streaming, VoIP, Chat, C2, and File Transfer categories.
- Intended use: inspect and, where semantics permit, adapt the packet dataframe without downloading the 36.1 GB raw-PCAP archive.

The registry must treat the HDF5 schema, time units, packet-length semantics, direction encoding, connection identifiers, VPN protocol detail, and labeling granularity as unknown until inspected. The observed HTTP content length is transport metadata, not a cryptographic integrity value.

#### ISCXVPN2016

- Stable source ID: `iscxvpn2016`
- Official page: `https://www.unb.ca/cic/datasets/vpn.html`
- Advertised scope: OpenVPN/UDP traffic with Web, Email, Chat, Streaming, File Transfer, VoIP, and P2P labels, distributed as PCAP and flow CSV forms.
- Approximate full size: 28 GB
- Initial acquisition state: `metadata_only`
- Intended use: preserve authoritative citation, protocol/label inventory, access constraints, and a future adapter decision without downloading the full collection in this phase.

The official page's research-use/citation language must be recorded as terms evidence. It must not be represented as a CC or SPDX license unless such a grant is found. A failed or gated download form must be documented; it must not be bypassed.

## 5. Licensing and Redistribution Policy

Every registry record must distinguish:

1. the source's stated license or terms;
2. the URL and retrieval date for that evidence;
3. whether local analytical use appears permitted;
4. whether redistribution of original or derived artifacts is clearly allowed; and
5. unresolved restrictions requiring human review.

`redistribution_status` is one of `allowed`, `restricted`, or `unknown`. Unknown and restricted sources may be locally inspected when their terms permit access, but their binaries and row-level derivatives must not be committed, packaged, uploaded, or redistributed by project tooling.

CC BY metadata for the two Zenodo records does not eliminate the need to preserve attribution. VNAT and ISCX must remain `unknown` or `restricted` until explicit terms are captured. This specification is not legal advice; ambiguity fails closed for redistribution.

## 6. External Storage Layout

The external root uses source- and digest-scoped paths:

```text
<external-root>/
  downloads/<source-id>/
  extracted/<source-id>/<source-sha256>/
  inventories/<source-id>/<source-sha256>/
  normalized/<source-id>/<adapter-version>/<source-sha256>/
  reports/
  logs/
  tmp/
```

Rules:

- Download targets use a `.part` suffix until byte count and checksum validation succeed.
- A validated file is atomically renamed to its final name.
- Extraction occurs into a new digest-scoped temporary directory and is atomically published only after archive-safety checks and inventory completion.
- Archive extraction rejects absolute paths, parent traversal, unsafe links, duplicate normalized paths, and unreasonable declared expansion sizes.
- Existing validated artifacts are never silently overwritten. A checksum mismatch is retained as a diagnostic and fails the operation.
- Resumption may continue a partial HTTP download only when the server confirms compatible range semantics and the saved acquisition metadata matches the URL/validator. Otherwise the partial file is restarted explicitly.
- Source archives remain read-only inputs. Derived inventory and normalized output never modify them.
- Every operation writes a machine-readable receipt containing URLs, timestamps, HTTP validators where available, byte counts, publisher checksum comparison, local SHA-256, tool version, and result.

Git ignore rules must cover the local config and any defensive in-repository artifact-directory names, but path validation is the primary protection. Ignore rules are not authorization to write large data inside the repository.

## 7. Acquisition and Inspection Workflow

Acquisition and adaptation are separate gates:

1. resolve the external root and source registry entry;
2. confirm the artifact is allowlisted for this phase;
3. retrieve official metadata and record its retrieval time;
4. estimate required free space for the archive, safe extraction, and derived inventory;
5. download to `.part`, with bounded retries and resumable behavior where supported;
6. verify exact byte count when declared;
7. verify publisher checksum when declared;
8. compute local SHA-256 for every acquired artifact;
9. atomically publish the verified archive/file;
10. perform a read-only structural inventory;
11. inspect schemas, protocols, labels, time/length/direction semantics, and session boundaries;
12. update the compatibility decision and registry evidence;
13. implement or enable an adapter only after the decision is reviewable; and
14. run a bounded sample normalization and invariant checks before any corpus-wide conversion.

Archive inspection records file names, member sizes, MIME/type probes, nested archives, tabular schemas, row counts where inexpensive, label values, and candidate packet/session identifiers. Sensitive or enormous member listings may be summarized with a digest and counts, but the report must retain enough evidence to reproduce the compatibility decision.

The first approved acquisition set is:

- USBVPN2022 ZIP;
- strongSwan/IPsec 2026 ZIP; and
- VNAT's approximately 1.05 GB HDF5 packet dataframe.

ISCXVPN2016 remains metadata-only. The VNAT raw-PCAP archive and the ISCXVPN2016 full collection are explicitly disallowed unless a later user decision changes scope.

## 8. External Normalization Boundary

### 8.1 Separation from native parsing

External datasets enter through `ipsec_sentinel.external`, not through the native dataset manifest or `encrypted.pcap` parsing path. The external package owns source adapters, normalized models, inventories, and compatibility validation.

The existing strict native parser continues to accept only validated native ESP captures with expected peers and workload boundaries. It must continue rejecting IKE, UDP/4500, non-ESP traffic, wrong peers, and out-of-window packets. No external format detection, permissive packet fallback, or source-specific exception may be added to it.

If statistical feature computation is later shared, only the calculator's typed observation input boundary may be generalized. Native PCAP parsing and external source adaptation must independently produce validated observations before the calculator runs.

### 8.2 Normalized observation

The minimum normalized packet-observation schema is:

```text
schema_version
parent_session_id
packet_index
relative_timestamp_us
packet_size_bytes
direction
label
source_dataset
vpn_protocol
```

Semantics:

- `relative_timestamp_us` is a non-negative integer relative to the first retained observation in the parent session. Source precision and conversion rules are retained in provenance.
- `packet_size_bytes` uses the most defensible source-defined packet/frame length. The adapter records whether this is wire length, captured length, IP length, tunnel payload length, or another measure. Incompatible or ambiguous length semantics fail compatibility rather than being silently equated.
- `direction` is `forward` or `reverse` relative to a documented, stable session endpoint ordering. Unknown direction is not imputed.
- `parent_session_id` is a stable derived identifier scoped by source and source session; it is metadata, not a feature.
- `label` is the canonical mapped class or an explicit unmapped/OOD label. It is never inferred from filenames alone without source documentation or corroborating metadata.
- `source_dataset` is the stable registry ID.
- `vpn_protocol` uses a controlled value such as `l2tp_ipsec`, `openvpn`, `wireguard`, `vpn_unspecified`, or `non_vpn`, based only on observed source evidence.

Adapters may retain additional provenance fields outside the feature vector: source row/connection identifiers, original label, source file/member digest, timestamp/length semantics, adapter version, and normalization warnings.

### 8.3 Session contract

Each normalized session has exactly one parent ID, source, protocol classification, original-label record, canonical-label decision, and ordered observation list. A session fails closed when:

- timestamps cannot be made monotonic without an explicitly justified stable ordering rule;
- packet direction is missing or inconsistent;
- there are fewer observations than the feature contract requires;
- length semantics are unavailable or invalid;
- multiple incompatible labels occur in one source session; or
- VPN and non-VPN records cannot be separated reliably for an intended VPN evaluation.

Rejected sessions remain counted with reason codes in the inventory; adapters must not silently drop them.

## 9. Source Adapter Decisions

### 9.1 USBVPN2022 adapter gate

The first inspection priority is the actual L2TP-IPsec portion. The inventory must answer:

- which archive members belong to L2TP-IPsec;
- whether data is packet-level, flow-level, feature-level, or mixed;
- whether full outer packets, timestamps, packet lengths, directions, and session boundaries exist;
- whether IKE/L2TP/control traffic is present and separable from workload observations;
- how application labels were assigned;
- whether a single capture contains multiple applications or tunnels; and
- whether an ESP-only or otherwise defensible encrypted-workload window can be reconstructed.

Only packet-level records with defensible session, direction, timing, size, protocol, and label semantics are candidates for the normalized observation adapter. Precomputed source features are cataloged but are not treated as native feature-equivalent.

### 9.2 strongSwan/IPsec 2026 catalog adapter

This source is expected to describe protocol performance/configuration experiments rather than application traffic sessions. Its adapter initially produces catalog records only: implementation, platform, network condition, IPsec status/config evidence, and performance measurements.

It must not fabricate packet observations from iperf summaries, ping logs, CPU metrics, or status output. If inspection unexpectedly reveals packet-level artifacts, compatibility requires a separate reviewed decision.

### 9.3 VNAT HDF5 adapter gate

The VNAT adapter may proceed only after HDF5 inspection establishes:

- table/group names and schema;
- whether each row is a packet observation or an aggregate;
- timestamp units and ordering;
- packet length definition;
- direction representation and endpoint/session identifiers;
- VPN versus non-VPN separation;
- tunnel/VPN protocol specificity; and
- original application/category label semantics.

The adapter selects VPN records only for VPN external evaluation. Non-VPN records may be cataloged but must not be mixed with encrypted-session features or relabeled as OOD encrypted traffic. If the VPN protocol is not identified beyond “VPN,” use `vpn_unspecified`; do not guess IPsec.

### 9.4 ISCXVPN2016 metadata adapter

This phase records official metadata, labels, protocol claims, access method, citation, and terms. It may define a prospective format contract from official documentation, but it must not claim row-level compatibility without obtaining and inspecting an artifact.

If a clearly official, substantially smaller flow representation becomes accessible under the stated terms, its URL/size/checksum may be proposed in the report. It is not downloaded automatically under this specification.

## 10. Label Mapping and OOD Rules

The only direct mappings into the current supervised vocabulary are:

| External semantic label | Canonical class |
|---|---|
| Streaming | `video` |
| VoIP | `voip` |
| Chat | `messaging` |
| File Transfer | `file_transfer` |
| Web or Browsing | `web` |
| Email | `email` |

Matching is performed through per-source explicit mapping entries, not unrestricted case folding or substring heuristics. A source label maps only when its documentation supports the same behavioral meaning at the same session granularity.

`icmp` has no generic external mapping unless a source explicitly labels an ICMP workload session. P2P, SSH, RDP, C2, database, gaming, Tor, unknown, mixed, and all other unapproved labels remain unmapped. They may be retained as evaluation/OOD candidates with their original semantic label, but are never coerced into a supervised class.

External OOD status does not imply compatibility with native OOD generators. Every use must retain source and protocol strata. A mapped label indicates semantic alignment only; it does not erase domain shift, VPN protocol differences, capture methodology differences, or source-specific bias.

## 11. Leakage and Feature-Compatibility Controls

The external layer must maintain a hard separation between feature inputs and provenance/selection metadata.

Candidate feature inputs are limited to the same behavioral observation values used by the current encrypted-traffic statistics where their semantics match: relative timing, packet size, direction, and derived statistics over those values.

The following are forbidden from feature columns:

- source dataset or adapter version;
- file, archive-member, directory, or HDF5 table name;
- native or mapped label;
- VPN protocol;
- DOI, citation, license, or acquisition metadata;
- session/connection/flow identifiers;
- IP addresses, host names, application names, and port numbers;
- capture date, absolute timestamp, row index, and record ordering across sessions;
- platform, environment, impairment, and implementation identifiers; and
- checksum, file size, or extraction path.

Feature schema compatibility is not established merely because columns have similar names. The report must compare packet-length layer, direction convention, time precision, session construction, truncation/sampling, and capture boundary behavior with native observations.

Before any future external evaluation, selection must be grouped by parent session and source. No packet rows from one parent session may cross evaluation partitions. Public data may evaluate robustness and domain shift, but it must not tune the trained artifact in this phase.

## 12. Commands and Operational Surface

The eventual command surface should make destructive or large actions explicit. A suitable shape is:

```text
python -m ipsec_sentinel.external registry validate
python -m ipsec_sentinel.external acquire <source-id> [--resume]
python -m ipsec_sentinel.external inspect <source-id>
python -m ipsec_sentinel.external normalize <source-id> --sample-sessions N
python -m ipsec_sentinel.external report
```

Requirements:

- `registry validate` performs no network or large-file writes.
- `acquire` accepts only registry artifact IDs and the phase allowlist; arbitrary URLs are rejected.
- `inspect` never mutates the source artifact.
- `normalize` requires a completed compatible inspection and is bounded by default to a small sample; corpus-wide normalization requires an explicit option.
- `report` summarizes receipts and inventories without embedding third-party records.
- Every command prints the resolved external root and intended byte-scale action before work begins.
- Exit codes distinguish configuration, acquisition, checksum, inspection, incompatibility, and normalization failures.

## 13. Testing Strategy

Implementation follows TDD and uses tiny synthetic fixtures created for the project. No public source binary is committed as a test fixture.

### 13.1 Registry and configuration tests

- valid registry records load deterministically;
- duplicate IDs, unapproved URLs, missing provenance, malformed checksums, and invalid license states fail closed;
- source claims and locally observed facts remain distinct;
- local data roots inside the repository/OneDrive are rejected for large artifacts;
- environment and local-config precedence is deterministic; and
- forbidden large artifacts remain ignored as a secondary safeguard.

### 13.2 Acquisition tests

- resumable range handling is validated with a local HTTP fixture;
- non-range servers restart safely rather than append corrupt bytes;
- publisher checksum and local SHA-256 behavior is correct;
- mismatches never publish the final filename;
- reruns reuse only verified artifacts;
- archive traversal, unsafe links, duplicate paths, and expansion limits fail closed; and
- atomic download/extraction leaves diagnostics without presenting partial data as complete.

### 13.3 Adapter and normalization tests

- each adapter reads a tiny source-shaped synthetic fixture;
- timestamp, length, direction, session, protocol, and label semantics are tested explicitly;
- stable packet ordering and relative-time conversion are deterministic;
- ambiguous sessions are rejected with reason counts;
- source-specific labels map only through explicit tables;
- unmapped/OOD labels remain excluded from supervised mappings;
- provenance is retained but excluded from candidate features; and
- same input digest plus adapter version yields the same normalized intent and inventory.

### 13.4 Native regression tests

The full ordinary suite must remain green. Dedicated regression tests must prove that:

- the native strict ESP reader has not become permissive;
- native training selection still reads only approved native manifest attempts;
- external locations cannot be mistaken for native dataset roots; and
- external provenance fields cannot enter the native feature schema.

Privileged Phase 1/Phase 2 tests are not required for a documentation-only or file-adapter change. If implementation touches native parsing or lifecycle code unexpectedly, work stops for architectural review before such a change proceeds.

## 14. Evidence and Reports

The implementation report must include:

- exact source record and artifact URLs;
- retrieval timestamps;
- publisher-declared and locally observed sizes;
- publisher checksums and locally computed SHA-256 values;
- archive/HDF5 structure summaries;
- protocols and application classes actually observed;
- license/terms evidence and redistribution status;
- disk usage by source and storage tier;
- adapter compatibility decisions with reasons;
- accepted/rejected session counts for bounded samples;
- canonical mappings and all unmapped labels;
- feature-semantic differences from native data;
- artifacts deliberately not downloaded; and
- confirmation that no public session entered native data or model training.

Reports must use `observed`, `publisher_declared`, `inferred`, and `unknown` language precisely. An inference must cite the observations supporting it.

## 15. Acceptance Criteria

This phase is complete only when:

1. The external branch/worktree remains isolated from the active collector, and the collector's branch/HEAD/runtime were not changed.
2. The tracked registry validates and contains all four source records with citations, artifacts, protocols, formats, label inventories, license evidence, and intended uses.
3. Approved large artifacts live only under the configured WSL ext4 root and are absent from Git status/history.
4. USBVPN2022, strongSwan/IPsec 2026, and VNAT HDF5 downloads have receipts, verified byte counts, local SHA-256 values, and publisher-checksum comparisons where available.
5. USBVPN2022's actual L2TP-IPsec contents have been inventoried before its adapter compatibility is decided.
6. The strongSwan/IPsec source is cataloged without misrepresenting aggregate performance/status data as application packet sessions.
7. VNAT's HDF5 schema and packet/session semantics are explicitly documented before normalization.
8. ISCXVPN2016 remains metadata-only and the 28 GB collection is not downloaded.
9. The VNAT 36.1 GB PCAP archive is not downloaded.
10. Compatible bounded samples normalize to the versioned external observation contract; incompatible sources or sessions fail closed with reasons.
11. Explicit label mappings are applied exactly, while unsupported labels remain unmapped/OOD.
12. Tests prove acquisition integrity, normalization semantics, provenance retention, and feature-column exclusion.
13. The complete ordinary regression suite passes and the native strict ESP path remains unchanged in behavior.
14. No feature extraction over the full public corpus, training, model update, public/native mixing, merge, rebase, push, or PR occurs automatically.

## 16. Deferred Decisions

The following require evidence from acquisition/inspection and are deliberately not guessed in this specification:

- the exact USBVPN2022 archive layout and which L2TP-IPsec members are usable;
- whether USBVPN2022 permits an ESP-workload-equivalent observation stream;
- VNAT HDF5 group/table names and exact packet/session semantics;
- whether VNAT identifies a specific VPN protocol or only generic VPN usage;
- whether an official smaller ISCXVPN2016 form is practically accessible under acceptable terms;
- whether any external source is semantically compatible enough for the current statistical feature calculator; and
- whether future evaluation should be protocol-stratified, source-stratified, or both.

These are inspection results for the implementation phase, not reasons to loosen validation or fill missing data heuristically.
