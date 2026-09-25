# IPsec Sentinel Prototype ML Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Validate four controlled IPsec scenarios, define a resumable 168-session clean-network matrix, and build a leakage-safe ESP-only classical-ML pipeline with an offline prediction CLI.

**Architecture:** Preserve `SecureSession` and `run_dataset_attempt()` as the only privileged lifecycle owners. Generalize scenario policy and evidence checking through an allowlisted scenario catalog, then consume only manifest-approved `encrypted.pcap` files in a separate `ipsec_sentinel.ml` package. Use one full-session feature vector per independent capture; scenario and session identity remain evaluation/grouping metadata and never model inputs.

**Tech Stack:** Python 3.14 standard library, PyYAML, SQLite, Linux XFRM/strongSwan/tcpdump, NumPy, scikit-learn, joblib, `unittest`.

**Spec:** `docs/superpowers/specs/2026-09-25-ipsec-sentinel-dataset-expansion-design.md`, refined by the approved deadline-driven prototype request dated 2026-09-26.

## Global Constraints

- Preserve Phase 1 `run_secure_baseline()` and all Phase 2 traffic/capture/manifest behavior.
- Support only `secure-baseline`, `aes128-gcm`, `aes256-cbc`, and `no-pfs`; all keep IKEv2, tunnel mode, fixed protected/transit networks, no NAT/NAT-T, and clean networking.
- PFS-enabled scenarios require fresh CHILD rekey DH plus reciprocal SPI replacement; `no-pfs` requires reciprocal SPI replacement and verified absence of CHILD DH.
- `encrypted.pcap` remains strictly peer-matched protocol-50 ESP inside the workload window with zero IKE, UDP/4500, plaintext, or unrelated traffic.
- Feature inputs are relative timestamp, captured packet length, and direction derived only from the fixed transit peers. Ports, labels, seeds, paths, run IDs, scenario IDs, and workload metadata are forbidden model features.
- Split only by independent session. Persist deterministic assignments. Select models by validation macro-F1 and report held-out test metrics once.
- Generate only a minimal pilot in-session. Do not run the 168-session matrix, add OOD/netem work, train deep models, or build an API/UI.
- Do not merge, rebase, push, or create a PR.

## Review Focus

- A scenario whose negotiated proposal differs from configuration must fail even when traffic and ESP are present.
- `no-pfs` must not be called PFS-verified merely because a rekey changed SPIs.
- A malformed, empty, non-ESP, wrong-peer, or out-of-window ML PCAP must fail before feature extraction.
- No feature column may encode scenario, label, generator, seed, path, port, or session identity.
- Train/validation/test assignments must have zero session overlap and remain stable across repeated builds.

---

### Task 1: Allowlisted IPsec scenarios and configured-versus-observed verification

**Files:**
- Create: `scenarios/aes128-gcm.yaml`
- Create: `scenarios/aes256-cbc.yaml`
- Create: `scenarios/no-pfs.yaml`
- Modify: `ipsec_sentinel/scenario.py`
- Modify: `ipsec_sentinel/strongswan.py`
- Modify: `ipsec_sentinel/session.py`
- Modify: `ipsec_sentinel/evidence.py`
- Modify: `ipsec_sentinel/models.py`
- Modify: `ipsec_sentinel/dataset/validation.py`
- Test: `tests/test_scenario.py`
- Test: `tests/test_strongswan.py`
- Test: `tests/test_evidence.py`
- Test: `tests/test_dataset_validation.py`

**Interfaces:**
- Produces: `scenario_path(id) -> Path`, scenario-driven `StrongSwanPair.render_configs(..., scenario=Scenario)`, and policy-aware PFS/rekey verification.
- Preserves: baseline defaults when no scenario argument is supplied to rendering and exact Phase 1 public behavior.

- [ ] Write failing table-driven tests for all four exact scenario policies, unknown scenario rejection, scenario-specific rendered proposals, observed IKE/ESP/integrity/DH checks, enabled-PFS rekey, and disabled-PFS rekey.
- [ ] Run `python3 -m unittest tests.test_scenario tests.test_strongswan tests.test_evidence tests.test_dataset_validation -v`; confirm failures name missing scenario/policy support.
- [ ] Add the three YAML definitions and minimal policy-aware parsing/rendering/evaluation. Represent PFS policy, rekey observation, and verification status separately.
- [ ] Re-run the focused tests and then `python3 -m unittest discover -s tests -v`.
- [ ] Commit the scenario/evidence checkpoint.

### Task 2: Prototype matrix and real privileged scenario gates

**Files:**
- Create: `configs/prototype-v1.yaml`
- Modify: `ipsec_sentinel/dataset/config.py`
- Modify: `ipsec_sentinel/dataset/cli.py`
- Modify: `ipsec_sentinel/dataset/manifest.py`
- Modify: `tests/test_dataset_config.py`
- Modify: `tests/test_dataset_matrix.py`
- Modify: `tests/test_dataset_cli.py`
- Modify: `tests/test_dataset_integration.py`

**Interfaces:**
- Produces: a strict four-scenario allowlist, stable scenario-definition digests in fingerprints/manifest rows, and 168 serial supervised slots.
- Consumes: Task 1 scenario catalog and unchanged seven-class traffic registry.

- [ ] Write failing tests proving four-scenario parsing, rejection outside the allowlist, 168-slot expansion, stable fingerprints/digests, CLI choices, and one privileged ICMP integration per new scenario.
- [ ] Run the focused tests and confirm they fail on the current one-scenario restriction.
- [ ] Implement the allowlist/digests/config and keep workers fixed at one and network profile fixed at `clean`.
- [ ] Run focused and full ordinary tests.
- [ ] Run the Phase 1 privileged baseline, then each new scenario as a real one-run ICMP dataset. Inspect IKE/CHILD/XFRM/ESP, rekey/PFS semantics, capture separation, and cleanup before accepting each scenario.
- [ ] Commit the matrix/scenario integration checkpoint.

### Task 3: Strict ESP packet reader and versioned feature extraction

**Files:**
- Create: `requirements-ml.txt`
- Create: `ipsec_sentinel/ml/schema.py`
- Create: `ipsec_sentinel/ml/features.py`
- Create: `ipsec_sentinel/ml/__init__.py`
- Modify: `ipsec_sentinel/pcap.py`
- Create: `tests/test_ml_features.py`

**Interfaces:**
- Produces: `read_ml_esp_packets(path, window, peers) -> tuple[EspPacket, ...]`, `extract_session_features(...) -> dict[str, float]`, and a frozen schema/version.
- Feature families: count/bytes/rates; overall and directional size percentiles/statistics; histogram entropy/unique ratio; IAT/idle gaps; directional ratios/switches/runs; bursts; repetition/CV/autocorrelation.

- [ ] Write failing tests using hand-built PCAPs for direction, relative timing, percentiles, IAT, bursts, short sessions, invalid/empty captures, schema order, and forbidden names.
- [ ] Run `python3 -m unittest tests.test_ml_features -v`; confirm missing reader/extractor failures.
- [ ] Expose the strict packet reader through the existing parser and implement deterministic full-session features without label/scenario/path metadata.
- [ ] Run focused and full ordinary tests.
- [ ] Commit the feature checkpoint.

### Task 4: Manifest-approved dataset table and leakage-safe split

**Files:**
- Create: `ipsec_sentinel/ml/dataset.py`
- Create: `ipsec_sentinel/ml/split.py`
- Create: `tests/test_ml_dataset.py`
- Create: `tests/test_ml_split.py`

**Interfaces:**
- Produces: portable `features.csv`, `feature_schema.json`, `dataset_metadata.json`, and `split_manifest.json`.
- Consumes: only `Manifest.supervised_ready_attempts()`, strict PCAP revalidation, Task 3 ordered features, and label/session/scenario as non-feature columns.

- [ ] Write failing tests for manifest filtering, invalid capture rejection, dataset hashing, exact feature columns, deterministic class/scenario-stratified session assignment, no overlap, and small-pilot behavior.
- [ ] Run focused tests and confirm missing builder/split failures.
- [ ] Implement one row per complete independent session and deterministic per-stratum assignment that prioritizes training coverage for sparse pilot strata.
- [ ] Run focused and full ordinary tests.
- [ ] Commit the dataset/split checkpoint.

### Task 5: Classical model benchmark, evaluation, export, and prediction CLI

**Files:**
- Create: `ipsec_sentinel/ml/train.py`
- Create: `ipsec_sentinel/ml/evaluate.py`
- Create: `ipsec_sentinel/ml/export.py`
- Create: `ipsec_sentinel/ml/cli.py`
- Create: `ipsec_sentinel/ml/__main__.py`
- Create: `tests/test_ml_training.py`
- Create: `tests/test_ml_inference.py`

**Interfaces:**
- Produces: deterministic Random Forest, Extra Trees, and HistGradientBoosting benchmark; validation macro-F1 selection; test and per-scenario/leave-one-scenario-out reporting when sample counts permit; joblib model bundle and JSON metadata; `python3 -m ipsec_sentinel.ml predict <encrypted.pcap>`.
- Prediction output: inferred class, score labelled `raw_confidence` unless a group-safe calibrator is fitted, low-confidence warning, model/schema versions, and explicit `AI-INFERRED`/no-decryption evidence wording.

- [ ] Install the pinned local ML dependencies into the ignored `.venv`, then write failing tests for deterministic training, serialization round-trip, metrics shape, scenario evaluation metadata exclusion, inference, low-confidence warnings, and forbidden feature absence.
- [ ] Run focused tests and confirm missing training/CLI failures.
- [ ] Implement the three-model benchmark, optional group-safe calibration only when folds are supportable, export metadata, and offline prediction.
- [ ] Run focused and full ordinary tests.
- [ ] Commit the ML checkpoint.

### Task 6: Minimal pilot, regression, leakage review, and unattended handoff

**Files:**
- Modify: `README.md`
- Create or update: `docs/evidence/prototype-v1-pilot.md`
- Test: all existing and new tests.

**Interfaces:**
- Produces: validated pilot artifacts sufficient to exercise build/split/train/export/predict and exact unattended commands for the 168-session matrix.

- [ ] Reuse retained valid smoke captures where available; otherwise generate only the smallest additional clean-network sessions needed for seven-class pipeline coverage plus one ICMP validation for each new scenario.
- [ ] Validate every pilot dataset and build the feature table/split/model artifacts. Run prediction against a held-out `encrypted.pcap` and label every metric pilot-only.
- [ ] Run the Phase 1 privileged test, the existing seven Phase 2 workload integrations, each scenario integration, full ordinary suite, `git diff --check`, and a namespace/interface cleanup audit.
- [ ] Audit feature names/serialized model input and dataset selection against the forbidden leakage list; report crypto-scenario imbalance or unsupported generalization rather than hiding it.
- [ ] Document exact `generate --resume`, validate, build, split, train/evaluate/export, and predict commands plus measured runtime/storage estimates.
- [ ] Perform a whole-branch review, fix Important/Critical findings with RED→GREEN tests, commit final documentation/evidence, and leave the worktree clean without merging or pushing.

