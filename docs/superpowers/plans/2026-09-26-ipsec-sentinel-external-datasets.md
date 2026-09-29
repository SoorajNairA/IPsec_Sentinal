# IPsec Sentinel External Dataset Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a provenance-first external-dataset acquisition, inspection, and normalization subsystem without changing native ESP validation or mixing public data into model training.

**Architecture:** A new `ipsec_sentinel.external` package owns registry parsing, WSL-ext4 storage guards, verified acquisition, structural inspection, source adapters, normalized observations, and reports. Native PCAP parsing stays strict and independent; only the statistical feature calculator gains a structural observation protocol so a separately validated external session can be compatibility-checked without entering the native dataset builder or training path.

**Tech Stack:** Python 3.14 standard library (`argparse`, `dataclasses`, `hashlib`, `urllib`, `zipfile`), PyYAML 6, h5py 3, `unittest`, WSL2/ext4 storage.

**Spec:** `docs/superpowers/specs/2026-09-26-ipsec-sentinel-external-datasets-design.md`

## Global Constraints

- Work only in `feat/ipsec-sentinel-external-datasets`, stacked on validated commit `865d93803f7af987a55cf2c8c2a7e7f9151c09bf`; do not merge, rebase, push, or create a PR automatically.
- Do not signal, restart, reconfigure, or write inside the active 168-session collector worktree or runtime.
- Store archives, extracted members, inventories, normalized rows, receipts, and logs under `/home/black/ipsec-sentinel-external-datasets` or another explicitly configured WSL-ext4 root, never in the repository, `.worktrees`, OneDrive, `/mnt/c`, or a default Downloads directory.
- Keep `ipsec_sentinel.pcap.read_ml_esp_packets()` strict and behaviorally unchanged: native ML PCAPs remain non-empty, peer-matched, workload-window, monotonic ESP only.
- Do not add external-format fallbacks to `ipsec_sentinel.pcap`, the native manifest, `build_feature_dataset()`, split, train, inference, or native training eligibility.
- Do not download VNAT's 36.1 GB raw-PCAP archive or the approximately 28 GB ISCXVPN2016 collection.
- Do not bypass gated access, fabricate missing checksums/protocols/labels, or equate aggregate metrics with packet sessions.
- Do not commit or redistribute third-party binaries or row-level derivatives.
- Do not train, calibrate, export, or evaluate a replacement model in this phase.
- Follow TDD for code tasks and commit each independently reviewable task.

## Review Focus

- A resumed HTTP download whose ETag/Last-Modified or range semantics changed must restart safely or fail, never append bytes from two objects; Task 3 pins this.
- A ZIP with traversal, absolute paths, symlinks, duplicate normalized names, or excessive expansion must be rejected before publication; Task 4 pins this.
- Ambiguous HDF5 length, direction, timestamp, VPN, label, or session semantics must produce an incompatible decision with reason codes, not guessed normalized rows; Tasks 4 and 9 pin this.
- A symlinked/configured data root that ultimately resolves into the repo, OneDrive, or `/mnt/*` must fail before any large write; Task 2 pins this.
- Provenance and selection fields must remain unavailable to `FEATURE_NAMES`, even when external observations are feature-compatible; Task 10 pins this.

---

### Task 1: Versioned Source Registry and Policy Models

**Files:**
- Create: `metadata/external-datasets.yaml`
- Create: `ipsec_sentinel/external/__init__.py`
- Create: `ipsec_sentinel/external/registry.py`
- Create: `tests/test_external_registry.py`

**Interfaces:**
- Produces: `ExternalDatasetRegistry.load(path: Path) -> ExternalDatasetRegistry`
- Produces: `ExternalDatasetRegistry.source(source_id: str) -> SourceRecord`
- Produces: frozen `SourceRecord`, `ArtifactRecord`, `ChecksumRecord`, and `LicenseRecord` dataclasses
- Produces: controlled states `AcquisitionState`, `InspectionState`, and `RedistributionStatus`

- [ ] **Step 1: Write failing registry tests**

Add tests named `test_loads_four_sources_with_separate_publisher_and_local_facts`, `test_rejects_duplicate_ids_unknown_fields_and_malformed_checksums`, `test_requires_license_evidence_and_explicit_redistribution_state`, and `test_registry_does_not_claim_uninspected_usb_or_vnat_schema`. Assert the four stable IDs, exact DOI/artifact size/MD5 values from the spec, VNAT's absent publisher checksum, and ISCX's `metadata_only` state.

- [ ] **Step 2: Run the tests and verify RED**

Run: `python3 -m unittest tests.test_external_registry -v`  
Expected: FAIL because `ipsec_sentinel.external.registry` and the registry file do not exist.

- [ ] **Step 3: Implement the typed registry loader**

Implement strict key validation and immutable records in `registry.py`. Define `REGISTRY_SCHEMA_VERSION = "ipsec-sentinel.external-registry/v1"`; preserve publisher claims, local verification, and inspection facts in separate fields; reject duplicate source/artifact IDs and checksum algorithms outside `md5` and `sha256`.

- [ ] **Step 4: Add the four reviewed registry records**

Populate USBVPN2022, strongSwan/IPsec 2026, VNAT, and ISCXVPN2016 exactly from the spec. Use `unknown` rather than guessed values, explicit mapping entries rather than substring rules, and official landing/download URLs only.

- [ ] **Step 5: Run focused and baseline tests**

Run: `python3 -m unittest tests.test_external_registry -v`  
Expected: PASS.  
Run: `python3 -m unittest tests.test_pcap_workload tests.test_ml_features tests.test_ml_dataset -v`  
Expected: PASS with native behavior unchanged.

- [ ] **Step 6: Commit**

```bash
git add metadata/external-datasets.yaml ipsec_sentinel/external tests/test_external_registry.py
git commit -m "feat: add external dataset registry"
```

### Task 2: External Configuration and Storage Boundary

**Files:**
- Create: `configs/external-datasets.example.yaml`
- Create: `ipsec_sentinel/external/config.py`
- Create: `ipsec_sentinel/external/storage.py`
- Create: `tests/test_external_storage.py`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: `ExternalDatasetRegistry` from Task 1
- Produces: `ExternalConfig.load(path: Path | None, environ: Mapping[str, str]) -> ExternalConfig`
- Produces: `resolve_external_root(raw_root: str, repo_root: Path, *, require_wsl_ext4: bool = True) -> Path`
- Produces: `ExternalPaths.create(root: Path) -> ExternalPaths` with `downloads`, `extracted`, `inventories`, `normalized`, `reports`, `logs`, and `tmp`

- [ ] **Step 1: Write failing root/configuration tests**

Add `test_environment_root_overrides_local_config`, `test_default_example_resolves_expected_wsl_ext4_root`, `test_rejects_missing_root_repo_one_drive_mnt_and_symlink_escape`, and `test_external_paths_create_only_under_resolved_root`. Use temporary Linux paths and symlinks; assert failure occurs before directory creation for rejected roots.

- [ ] **Step 2: Run the tests and verify RED**

Run: `python3 -m unittest tests.test_external_storage -v`  
Expected: FAIL because the config/storage interfaces do not exist.

- [ ] **Step 3: Implement strict configuration and canonical path guards**

Resolve all ancestors with `Path.resolve(strict=False)`, reject roots equal to or beneath the repository/common Git directory, reject paths containing the repository's OneDrive root, and reject `/mnt/<drive>` when `require_wsl_ext4` is true. Create directories only after all checks pass.

- [ ] **Step 4: Add example/local ignore policy**

Set the tracked example root to `/home/black/ipsec-sentinel-external-datasets`; add `configs/external-datasets.local.yaml`, `external-data/`, and `.external-data/` to `.gitignore` as defense in depth.

- [ ] **Step 5: Run tests and verify clean path behavior**

Run: `python3 -m unittest tests.test_external_storage -v`  
Expected: PASS.  
Run: `git check-ignore configs/external-datasets.local.yaml external-data/probe .external-data/probe`  
Expected: all three paths are ignored.

- [ ] **Step 6: Commit**

```bash
git add .gitignore configs/external-datasets.example.yaml ipsec_sentinel/external/config.py ipsec_sentinel/external/storage.py tests/test_external_storage.py
git commit -m "feat: isolate external dataset storage"
```

### Task 3: Verified, Resumable, Atomic Acquisition

**Files:**
- Create: `ipsec_sentinel/external/acquire.py`
- Create: `tests/test_external_acquire.py`

**Interfaces:**
- Consumes: `ArtifactRecord` and `ExternalPaths`
- Produces: `acquire_artifact(artifact: ArtifactRecord, paths: ExternalPaths, *, resume: bool = True, opener: UrlOpener | None = None) -> AcquisitionReceipt`
- Produces: frozen `AcquisitionReceipt` with URL, validators, declared/observed bytes, publisher checksum result, local SHA-256, timestamps, tool version, final path, and outcome
- Produces: `verify_download(path: Path, artifact: ArtifactRecord) -> VerifiedArtifact`

- [ ] **Step 1: Write failing local-HTTP acquisition tests**

Use an in-process HTTP server and add `test_download_publishes_only_after_size_md5_and_sha256_pass`, `test_resume_uses_matching_range_and_validator`, `test_changed_validator_or_ignored_range_restarts_without_concatenation`, `test_checksum_mismatch_retains_diagnostic_but_not_final_file`, `test_verified_rerun_reuses_exact_artifact`, and `test_insufficient_space_fails_before_request`.

- [ ] **Step 2: Run the tests and verify RED**

Run: `python3 -m unittest tests.test_external_acquire -v`  
Expected: FAIL because acquisition is not implemented.

- [ ] **Step 3: Implement download state and integrity verification**

Use `<filename>.part` plus `<filename>.part.json`; issue `Range` only with a stored matching validator; require `206` and a correct `Content-Range` before appending. Stream hashes, `fsync`, compare declared size and publisher checksum, compute SHA-256, then atomically rename. Write the JSON receipt atomically after final publication.

- [ ] **Step 4: Implement bounded retry and disk-space checks**

Retry transient transport failures with bounded attempts and no long uninterruptible sleep. Use declared/content length plus a fixed safety margin for preflight; return stable failure categories for configuration, transport, size, checksum, and space.

- [ ] **Step 5: Run acquisition and regression tests**

Run: `python3 -m unittest tests.test_external_acquire -v`  
Expected: PASS.  
Run: `python3 -m unittest tests.test_artifacts tests.test_command -v`  
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add ipsec_sentinel/external/acquire.py tests/test_external_acquire.py
git commit -m "feat: verify external dataset downloads"
```

### Task 4: Safe ZIP/HDF5 Structural Inspection

**Files:**
- Create: `requirements-external.txt`
- Create: `ipsec_sentinel/external/inspect.py`
- Create: `tests/test_external_inspect.py`

**Interfaces:**
- Consumes: `VerifiedArtifact`, `ExternalPaths`
- Produces: `inspect_artifact(source: SourceRecord, artifact: VerifiedArtifact, paths: ExternalPaths) -> InspectionReport`
- Produces: `safe_extract_zip(artifact: VerifiedArtifact, destination: Path, *, max_expanded_bytes: int, max_members: int) -> ExtractionReceipt`
- Produces: versioned `InspectionReport` containing member/table schemas, counts, labels, semantic findings, warnings, and compatibility reasons

- [ ] **Step 1: Add h5py and write failing structural-inspection tests**

Pin `h5py>=3.15,<4` and `PyYAML>=6,<7`. Build tiny ZIP and HDF5 fixtures during each test. Add `test_zip_inventory_records_members_types_sizes_and_digest`, `test_zip_rejects_traversal_absolute_symlink_duplicate_and_expansion_bomb`, `test_hdf5_inventory_records_groups_datasets_dtypes_shapes_and_sample_values`, and `test_ambiguous_packet_semantics_are_incompatible_with_reason_codes`.

- [ ] **Step 2: Install the optional dependency and verify RED**

Run: `/home/black/.venvs/ipsec-sentinel-ml/bin/python -m pip install -r requirements-external.txt`  
Run: `/home/black/.venvs/ipsec-sentinel-ml/bin/python -m unittest tests.test_external_inspect -v`  
Expected: FAIL because inspection is not implemented.

- [ ] **Step 3: Implement archive safety and digest-scoped publication**

Normalize member paths before extraction; reject absolute/parent paths, Windows drive paths, symlinks, duplicate normalized names, excessive member counts, and declared expansion over the configured limit. Extract into a temporary directory and atomically publish under `extracted/<source>/<sha256>/` only after inspection succeeds.

- [ ] **Step 4: Implement bounded HDF5 inspection**

Traverse groups/datasets without loading the full file, recording dtype, shape, attributes, bounded label/value samples, and candidate time/size/direction/session columns. Mark every required semantic as `observed`, `publisher_declared`, `inferred`, or `unknown`; compatibility requires observed, unambiguous fields.

- [ ] **Step 5: Run tests**

Run: `/home/black/.venvs/ipsec-sentinel-ml/bin/python -m unittest tests.test_external_inspect -v`  
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add requirements-external.txt ipsec_sentinel/external/inspect.py tests/test_external_inspect.py
git commit -m "feat: inspect external dataset artifacts safely"
```

### Task 5: External Observation Contract and Explicit Label Mapping

**Files:**
- Create: `ipsec_sentinel/external/models.py`
- Create: `ipsec_sentinel/external/labels.py`
- Create: `ipsec_sentinel/external/adapters/__init__.py`
- Create: `ipsec_sentinel/external/adapters/base.py`
- Create: `tests/test_external_models.py`
- Create: `tests/test_external_labels.py`

**Interfaces:**
- Produces: frozen `ExternalPacketObservation(schema_version, parent_session_id, packet_index, relative_timestamp_us, packet_size_bytes, direction, label, source_dataset, vpn_protocol)`
- Produces: frozen `ExternalSession(observations, provenance, compatibility)`
- Produces: `ExternalAdapter.iter_sessions(*, limit: int | None = None) -> Iterator[ExternalSession]`
- Produces: `map_external_label(source_id: str, original_label: str, registry: ExternalDatasetRegistry) -> LabelDecision`

- [ ] **Step 1: Write failing contract tests**

Add `test_observation_requires_nonnegative_monotonic_fields_valid_size_and_direction`, `test_session_rejects_mixed_parent_source_protocol_or_label`, `test_explicit_mappings_cover_only_streaming_voip_chat_file_web_email`, `test_p2p_ssh_rdp_c2_mixed_and_unknown_remain_unmapped`, and `test_mapping_requires_exact_per_source_entry_not_substring_match`.

- [ ] **Step 2: Run tests and verify RED**

Run: `python3 -m unittest tests.test_external_models tests.test_external_labels -v`  
Expected: FAIL because models/mapping do not exist.

- [ ] **Step 3: Implement immutable normalized models**

Set `EXTERNAL_OBSERVATION_SCHEMA_VERSION = "ipsec-sentinel.external-observation/v1"`. Validate packet indices, non-negative microseconds, positive byte lengths, `forward|reverse`, one parent/source/protocol/label per session, monotonic ordering, and non-empty sessions. Keep original IDs/labels and source member digests only in provenance.

- [ ] **Step 4: Implement registry-driven exact mapping**

Return `mapped_supervised`, `unmapped`, or `ood_candidate`; never map `icmp` without an explicit registry entry. Keep canonical label, original label, reason, and `known_training_class` separate.

- [ ] **Step 5: Run tests**

Run: `python3 -m unittest tests.test_external_models tests.test_external_labels -v`  
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add ipsec_sentinel/external/models.py ipsec_sentinel/external/labels.py ipsec_sentinel/external/adapters tests/test_external_models.py tests/test_external_labels.py
git commit -m "feat: define external observation contract"
```

### Task 6: External CLI and Fail-Closed Operational Surface

**Files:**
- Create: `ipsec_sentinel/external/cli.py`
- Create: `ipsec_sentinel/external/__main__.py`
- Create: `tests/test_external_cli.py`

**Interfaces:**
- Consumes: registry, config, acquisition, inspection, and adapter interfaces from Tasks 1-5
- Produces: `build_parser() -> argparse.ArgumentParser`
- Produces: `main(argv: list[str] | None = None) -> int`
- Commands: `registry validate`, `acquire SOURCE_ID [--resume]`, `inspect SOURCE_ID`, `normalize SOURCE_ID --sample-sessions N`, and `report`

- [ ] **Step 1: Write failing CLI tests**

Add `test_registry_validate_is_read_only`, `test_acquire_accepts_only_registry_source_and_phase_allowlist`, `test_every_mutating_command_prints_resolved_root_and_byte_scale`, `test_normalize_defaults_to_bounded_sample_and_requires_compatible_inspection`, and `test_exit_codes_distinguish_config_acquire_checksum_inspection_and_incompatibility`.

- [ ] **Step 2: Run tests and verify RED**

Run: `python3 -m unittest tests.test_external_cli -v`  
Expected: FAIL because CLI modules do not exist.

- [ ] **Step 3: Implement parser and dependency-injectable command dispatch**

Do not accept arbitrary URLs or output roots on `acquire`. Resolve source/artifact through the registry, root through Task 2, and require explicit `--all-sessions` before unbounded normalization. Print JSON summaries without embedding source rows.

- [ ] **Step 4: Run CLI and native parser tests**

Run: `python3 -m unittest tests.test_external_cli tests.test_pcap_workload tests.test_ml_inference -v`  
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ipsec_sentinel/external/cli.py ipsec_sentinel/external/__main__.py tests/test_external_cli.py
git commit -m "feat: add external dataset CLI"
```

### Task 7: Acquire and Inspect USBVPN2022 and strongSwan 2026

**Files:**
- Modify: `metadata/external-datasets.yaml`
- Create: `docs/evidence/2026-09-26-external-dataset-inventory.md`
- External only: `/home/black/ipsec-sentinel-external-datasets/**`

**Interfaces:**
- Consumes: Tasks 1-6 operational commands
- Produces: verified local artifacts/receipts/inventories outside Git and reviewed observed facts in the registry/evidence document

- [ ] **Step 1: Preflight isolation and free space**

Verify the current worktree branch/HEAD, resolved external root, root filesystem, available space, and absence of staged/untracked binaries. Read-only check that the collector branch/HEAD has not been changed; do not query or signal its mutable runtime.

- [ ] **Step 2: Acquire USBVPN2022 and verify integrity**

Run: `/home/black/.venvs/ipsec-sentinel-ml/bin/python -m ipsec_sentinel.external acquire usbvpn2022 --resume`  
Expected: 811,738,498-byte final ZIP, publisher MD5 `35a4aef78526440cd6e352de49c4daf2` matched, local SHA-256 recorded, and no repository binary.

- [ ] **Step 3: Inspect USBVPN2022 with the L2TP-IPsec questions from the spec**

Run: `/home/black/.venvs/ipsec-sentinel-ml/bin/python -m ipsec_sentinel.external inspect usbvpn2022`  
Expected: member inventory and an evidence-backed decision covering L2TP-IPsec members, data granularity, timestamps, lengths, directions, sessions, labels, control/workload separability, and ESP-equivalent compatibility. Stop this source at `incompatible` if any required semantic is unknown.

- [ ] **Step 4: Acquire and inspect strongSwan/IPsec 2026**

Run: `/home/black/.venvs/ipsec-sentinel-ml/bin/python -m ipsec_sentinel.external acquire vpn_protocol_performance_2026 --resume`  
Expected: 4,701,066-byte ZIP, publisher MD5 `bca99ce9a6ad9a3e2ad03c9f0b63db48` matched, and local SHA-256 recorded.  
Run: `/home/black/.venvs/ipsec-sentinel-ml/bin/python -m ipsec_sentinel.external inspect vpn_protocol_performance_2026`  
Expected: exact member/configuration/environment inventory without converting aggregate metrics into packet sessions.

- [ ] **Step 5: Record observed facts and review the diff**

Update only registry local-verification/inspection fields and the text inventory summary. Include actual sizes, SHA-256, archive contents, protocols, labels, compatibility, license evidence, disk use, and unknowns. Run `git diff --check` and verify `git status --short` contains no archive/extracted/normalized artifact.

- [ ] **Step 6: Commit**

```bash
git add metadata/external-datasets.yaml docs/evidence/2026-09-26-external-dataset-inventory.md
git commit -m "docs: inventory public IPsec datasets"
```

### Task 8: Evidence-Gated USB and strongSwan Adapters

**Files:**
- Create: `ipsec_sentinel/external/adapters/usbvpn2022.py` only if Task 7 proves packet-session compatibility
- Create: `ipsec_sentinel/external/adapters/strongswan2026.py`
- Create: `tests/test_external_usbvpn2022.py`
- Create: `tests/test_external_strongswan2026.py`
- Modify: `metadata/external-datasets.yaml`

**Interfaces:**
- Consumes: Task 7 inspection reports and Task 5 models
- Produces: `StrongSwan2026CatalogAdapter.read() -> tuple[ProtocolExperiment, ...]`
- Conditionally produces: `UsbVpn2022Adapter.iter_sessions(*, limit: int | None = None) -> Iterator[ExternalSession]`

- [ ] **Step 1: Build source-shaped synthetic fixtures from observed schemas**

Create fixtures programmatically in temporary directories; do not copy public rows or binaries. Tests must name the exact observed member/field structure and assert configuration counts, protocol/environment values, and compatibility decisions.

- [ ] **Step 2: Write failing strongSwan catalog tests**

Add `test_catalog_preserves_protocol_platform_condition_and_raw_evidence_paths` and `test_catalog_never_emits_packet_observations_from_iperf_ping_cpu_or_status`.

- [ ] **Step 3: Implement the strongSwan catalog adapter and run tests**

Run: `python3 -m unittest tests.test_external_strongswan2026 -v`  
Expected: PASS with zero normalized packet sessions.

- [ ] **Step 4: Apply the USB evidence gate**

If Task 7 proves all required packet/session semantics, write `test_adapter_normalizes_only_verified_l2tp_ipsec_sessions`, `test_adapter_preserves_original_label_and_rejects_mixed_or_control_only_sessions`, and `test_adapter_is_bounded_and_deterministic`, then implement the adapter. If not, write `test_usb_registry_marks_adapter_unavailable_with_inspection_reasons` and do not create a parser that guesses missing semantics.

- [ ] **Step 5: Run source and normalization tests**

Run: `python3 -m unittest tests.test_external_usbvpn2022 tests.test_external_strongswan2026 tests.test_external_models tests.test_external_labels -v`  
Expected: PASS for the evidence-backed branch selected in Task 7.

- [ ] **Step 6: Commit**

```bash
git add ipsec_sentinel/external/adapters tests/test_external_usbvpn2022.py tests/test_external_strongswan2026.py metadata/external-datasets.yaml
git commit -m "feat: adapt inspected public IPsec sources"
```

### Task 9: Acquire, Inspect, and Evidence-Gate VNAT HDF5

**Files:**
- Create: `ipsec_sentinel/external/adapters/vnat.py` only if inspection proves compatibility
- Create: `tests/test_external_vnat.py`
- Modify: `metadata/external-datasets.yaml`
- Modify: `docs/evidence/2026-09-26-external-dataset-inventory.md`
- External only: `/home/black/ipsec-sentinel-external-datasets/**`

**Interfaces:**
- Consumes: Tasks 1-6 acquisition/inspection and Task 5 normalized models
- Conditionally produces: `VnatAdapter.iter_sessions(*, vpn_only: bool = True, limit: int | None = None) -> Iterator[ExternalSession]`

- [ ] **Step 1: Acquire the selected 1.05 GB dataframe only**

Run: `/home/black/.venvs/ipsec-sentinel-ml/bin/python -m ipsec_sentinel.external acquire mit_ll_vnat --resume`  
Expected: `VNAT_Dataframe_release_1.h5`, observed byte size and local SHA-256 recorded; no attempt to retrieve the 36.1 GB PCAP archive.

- [ ] **Step 2: Inspect the HDF5 structure before adapter code**

Run: `/home/black/.venvs/ipsec-sentinel-ml/bin/python -m ipsec_sentinel.external inspect mit_ll_vnat`  
Expected: observed groups/tables, dtypes, shapes, timestamp units, length definition, direction, session IDs, VPN selection, protocol specificity, and label granularity, with unknowns explicit.

- [ ] **Step 3: Write failing tests for the evidence-backed outcome**

Generate a tiny HDF5 fixture matching the observed schema. If semantics are complete, add `test_vnat_normalizes_vpn_packet_rows_by_parent_session`, `test_vnat_excludes_non_vpn_without_relabeling_it_ood`, `test_vnat_uses_vpn_unspecified_when_source_has_no_protocol_detail`, and `test_vnat_rejects_ambiguous_or_mixed_sessions`. If semantics are incomplete, add `test_vnat_registry_marks_adapter_unavailable_with_inspection_reasons`.

- [ ] **Step 4: Implement only the supported adapter branch**

Read HDF5 incrementally, preserve original connection/session IDs only in provenance, normalize relative time/size/direction exactly as observed, and stop at the requested session limit. Do not load the 1.05 GB file as one in-memory table.

- [ ] **Step 5: Validate a bounded real sample or incompatibility result**

Run: `python3 -m unittest tests.test_external_vnat tests.test_external_models tests.test_external_labels -v`  
Expected: PASS.  
If compatible, run: `/home/black/.venvs/ipsec-sentinel-ml/bin/python -m ipsec_sentinel.external normalize mit_ll_vnat --sample-sessions 10`  
Expected: ten or fewer independently validated VPN sessions plus accepted/rejected reason counts. If incompatible, `normalize` must exit with the documented incompatibility code and write no normalized rows.

- [ ] **Step 6: Update evidence and commit**

Record actual size/SHA-256, HDF5 semantics, labels, VPN protocol detail, compatibility, bounded counts, license evidence, and disk use. Verify the raw-PCAP archive remains absent.

```bash
git add ipsec_sentinel/external/adapters/vnat.py tests/test_external_vnat.py metadata/external-datasets.yaml docs/evidence/2026-09-26-external-dataset-inventory.md
git commit -m "feat: inspect and adapt VNAT dataframe"
```

Omit `ipsec_sentinel/external/adapters/vnat.py` from `git add` when the evidence gate rejects adaptation.

### Task 10: Share Only the Statistical Observation Boundary

**Files:**
- Create: `ipsec_sentinel/ml/observations.py`
- Modify: `ipsec_sentinel/ml/features.py`
- Modify: `ipsec_sentinel/external/models.py`
- Modify: `tests/test_ml_features.py`
- Create: `tests/test_external_feature_compatibility.py`
- Test unchanged: `tests/test_pcap_workload.py`
- Test unchanged: `tests/test_ml_dataset.py`

**Interfaces:**
- Produces: `PacketObservation` protocol with read-only `relative_time_seconds: float`, `length: int`, and `direction: str`
- Changes: `extract_session_features(packets: Sequence[PacketObservation]) -> dict[str, float]`
- Adds to external model: protocol-compatible read-only properties derived from `relative_timestamp_us` and `packet_size_bytes`
- Leaves unchanged: `read_ml_esp_packets(...) -> tuple[EspPacket, ...]` and `build_feature_dataset(...)`

- [ ] **Step 1: Write failing protocol/equivalence tests**

Add `test_external_and_native_observations_with_same_behavior_have_identical_features`, `test_provenance_label_protocol_filename_and_parent_id_are_absent_from_feature_schema`, `test_external_model_exposes_only_time_size_direction_to_calculator`, and `test_native_reader_still_rejects_non_esp_wrong_peer_out_of_window_inversion_and_empty`.

- [ ] **Step 2: Run tests and verify the new type contract fails**

Run: `python3 -m unittest tests.test_external_feature_compatibility tests.test_ml_features tests.test_pcap_workload -v`  
Expected: FAIL because `PacketObservation` and external compatibility properties do not exist; existing native tests remain otherwise green.

- [ ] **Step 3: Generalize the calculator type boundary only**

Move no parsing into `features.py`. Replace the concrete `EspPacket` annotation with `Sequence[PacketObservation]`; keep feature names, formulas, schema version, and result ordering unchanged. Add properties on `ExternalPacketObservation` without exposing provenance through the protocol.

- [ ] **Step 4: Run leakage and native regression tests**

Run: `python3 -m unittest tests.test_external_feature_compatibility tests.test_ml_features tests.test_pcap_workload tests.test_ml_dataset tests.test_ml_inference -v`  
Expected: PASS; native feature values and fail-closed PCAP behavior are unchanged.

- [ ] **Step 5: Commit**

```bash
git add ipsec_sentinel/ml/observations.py ipsec_sentinel/ml/features.py ipsec_sentinel/external/models.py tests/test_ml_features.py tests/test_external_feature_compatibility.py
git commit -m "refactor: share packet observation feature boundary"
```

### Task 11: ISCX Metadata, Compatibility Report, and Complete Verification

**Files:**
- Create: `ipsec_sentinel/external/report.py`
- Create: `tests/test_external_report.py`
- Modify: `ipsec_sentinel/external/cli.py`
- Modify: `metadata/external-datasets.yaml`
- Modify: `docs/evidence/2026-09-26-external-dataset-inventory.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: registry, receipts, inspections, adapter summaries, and external storage paths
- Produces: `build_external_report(registry: ExternalDatasetRegistry, paths: ExternalPaths) -> ExternalDatasetReport`
- Produces externally: `reports/external-datasets.json` and `reports/external-datasets.md`

- [ ] **Step 1: Write failing report tests**

Add `test_report_reconciles_registry_receipts_inventories_and_disk_usage`, `test_report_lists_protocols_classes_mappings_licenses_and_compatibility`, `test_report_names_every_intentionally_omitted_artifact`, `test_report_never_embeds_public_rows_or_paths_as_features`, and `test_iscx_remains_metadata_only_without_download_receipt`.

- [ ] **Step 2: Run tests and verify RED**

Run: `python3 -m unittest tests.test_external_report -v`  
Expected: FAIL because report generation is missing.

- [ ] **Step 3: Implement deterministic JSON/Markdown reporting**

Reconcile exact artifact sizes/checksums, formats, protocols, observed classes, adapters, label mappings, license/terms evidence, usefulness, rejection reasons, and disk usage. Explicitly list VNAT raw PCAP and ISCX full collection as not downloaded. State that external and native datasets were not mixed and no model was trained.

- [ ] **Step 4: Complete ISCX official metadata without downloading data**

Record retrieval date, official page, OpenVPN/UDP claim, formats, advertised classes, access/gating result, citation requirement, and `unknown|restricted` redistribution status. Do not automate around the form or server error.

- [ ] **Step 5: Generate and reconcile the real report**

Run: `/home/black/.venvs/ipsec-sentinel-ml/bin/python -m ipsec_sentinel.external report`  
Expected: external-root JSON/Markdown reports agree with receipts/inventories and the tracked evidence summary. Check `du` under the external root and confirm repository status includes no binary artifact.

- [ ] **Step 6: Run the complete ordinary test suite**

Run: `/home/black/.venvs/ipsec-sentinel-ml/bin/python -m unittest discover -s tests -v`  
Expected: all tests pass; only the existing privilege-gated integration tests skip. Do not run privileged network tests while the independent collector is active.

- [ ] **Step 7: Perform final scope and leakage review**

Confirm `git diff` contains no changes to native PCAP validation, native manifest eligibility, training, splitting, inference, or model artifacts beyond the typed calculator annotation. Search feature names and generated report schemas to prove source, protocol, filenames, IDs, labels, absolute timestamps, addresses, and ports are excluded. Confirm no third-party data is tracked with `git status`, `git ls-files`, and size checks.

- [ ] **Step 8: Commit**

```bash
git add ipsec_sentinel/external/report.py ipsec_sentinel/external/cli.py tests/test_external_report.py metadata/external-datasets.yaml docs/evidence/2026-09-26-external-dataset-inventory.md README.md
git commit -m "docs: report external dataset compatibility"
```

### Task 12: Final Branch Review and Handoff

**Files:**
- Review: all changes from `e12080610559847530fd693f9dcdb53636ccc303..HEAD`
- No new implementation file is required unless review finds a defect

**Interfaces:**
- Consumes: all prior tasks
- Produces: evidence-backed completion report; no merge, push, PR, training, or bulk normalization

- [ ] **Step 1: Verify commit and worktree scope**

Run `git log --oneline e120806..HEAD`, `git diff --stat e120806..HEAD`, `git status --short`, and `git diff --check e120806..HEAD`. Confirm only external integration, the narrow feature type boundary, docs, metadata, requirements, and tests changed.

- [ ] **Step 2: Re-run registry, source, leakage, and full tests from clean state**

Run focused external tests first, then the complete command from Task 11. Expected: PASS with expected privileged skips only.

- [ ] **Step 3: Reconcile real evidence one final time**

Compare registry local-verification fields, acquisition receipts, inventories, normalized sample summaries, report totals, external-root disk use, and tracked evidence. Any disagreement blocks completion.

- [ ] **Step 4: Confirm collector non-interference**

Read only the collector branch and HEAD through Git worktree metadata; confirm they match the pre-implementation values. Do not inspect, signal, or alter the running collector process.

- [ ] **Step 5: Report and stop**

Report branch/commit, sources discovered, exact downloads/sizes/checksums, formats/protocols/classes, adapter outcomes, mappings/unmapped labels, licenses, usefulness, disk usage, deliberately omitted downloads, test results, native-parser evidence, known limitations, and clean/dirty status. State explicitly that no public data was mixed into native training and no model was retrained. Stop for review.
