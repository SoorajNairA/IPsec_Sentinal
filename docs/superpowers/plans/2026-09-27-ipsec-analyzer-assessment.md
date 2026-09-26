# IPsec Analyzer and Assessment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a working PCAP-to-analysis JSON/CLI pipeline with deterministic IPsec evidence, optional existing-model traffic inference, and transparent security assessment.

**Architecture:** Read each capture once into packet observations, then run focused deterministic analyzers over the shared representation. Build stable evidence-linked results, optionally invoke the existing model for suitable ESP sessions, apply evidence-aware rules, and validate the final v1 JSON contract.

**Tech Stack:** Python standard library, existing NumPy/scikit-learn/joblib ML stack, unittest, real strongSwan-generated PCAPs.

**Spec:** `docs/specs/2026-09-27-ipsec-analyzer-assessment.md`

## Global Constraints

- Preserve all Phase 1, dataset, external-data, and ML behavior.
- Never claim CHILD-SA PFS from rekey alone; unsupported properties remain `UNKNOWN` without penalty.
- ML is used only for encrypted traffic type inference and never decrypts payloads.
- Do not regenerate datasets, train models, merge, push, open a PR, or build frontend code.
- Analyze the capture in one pass and retain raw plus normalized algorithm evidence.

## Review Focus

- Truncated and unsupported captures return structured results without tracebacks.
- Multiple peer pairs are not silently merged into one VPN session.
- IKE proposal offers are not mislabeled as negotiated selections.
- SPI replacement is not mislabeled as PFS evidence.
- Missing model artifacts degrade to `UNKNOWN` while deterministic analysis remains usable.

---

### Task 1: Capture and protocol evidence core

**Files:**
- Create: `ipsec_sentinel/analyzer/{models,capture,protocols,ike,sa}.py`
- Test: `tests/test_analyzer_capture.py`, `tests/test_analyzer_protocols.py`

**Interfaces:** Produces `parse_capture(Path) -> ParsedCapture` and deterministic protocol/IKE/SA observations consumed by Task 2.

- [ ] Add failing tests for missing/empty/malformed/non-IPsec, ESP-only, IKEv2, NAT-T, AH, peers, algorithm normalization, SPI chronology, retransmissions, and incomplete evidence.
- [ ] Run the focused tests and confirm they fail for missing analyzer modules.
- [ ] Implement one-pass classic-PCAP parsing and deterministic analyzers with stable evidence IDs.
- [ ] Run focused tests to green and commit.

### Task 2: ESP intelligence, rules, scoring, and contract

**Files:**
- Create: `ipsec_sentinel/analyzer/{esp,intelligence,rules,contract,pipeline}.py`
- Create: `schemas/ipsec-sentinel-analysis-v1.schema.json`
- Test: `tests/test_analyzer_assessment.py`, `tests/test_analyzer_contract.py`
- Modify: `ipsec_sentinel/ml/inference.py`

**Interfaces:** Consumes Task 1 observations; produces `analyze_capture(...) -> dict[str, object]` validated as `ipsec-sentinel.analysis/v1`.

- [ ] Add failing tests for feature reuse, inference/no-prediction/schema mismatch, provenance links, 10–15 rules, deterministic bounded scoring, and unknown/unassessed weight.
- [ ] Run focused tests and confirm the intended failures.
- [ ] Implement ESP statistics, optional model adapter, evidence-linked rules, scoring, limitations, and schema validation.
- [ ] Run focused tests to green and commit.

### Task 3: CLI, controlled evidence, and real-capture proof

**Files:**
- Create: `ipsec_sentinel/analyze/{__init__,__main__,cli}.py`
- Create: `docs/evidence/ipsec-analyzer-demo.md`
- Test: `tests/test_analyzer_cli.py`, `tests/test_analyzer_real_pcaps.py`

**Interfaces:** Consumes Task 2 pipeline; provides the public module CLI and optional controlled-lab evidence directory.

- [ ] Add failing CLI tests for text/JSON output and graceful errors, plus gated real-PCAP assertions for all four scenarios and Video/VoIP inference.
- [ ] Run focused tests and confirm failures.
- [ ] Implement CLI rendering and controlled-lab evidence ingestion with explicit source provenance.
- [ ] Analyze existing real captures, document exact evidence/limitations/performance, run all regressions and compile/diff checks, then commit.
