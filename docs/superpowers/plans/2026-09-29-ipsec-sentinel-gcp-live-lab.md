# IPsec Sentinel GCP Live Lab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Connect the existing event-driven Live Lab to four controlled GCP strongSwan responders while preserving the local lifecycle, evidence contracts, Mystery privacy, ML isolation, and exact cleanup guarantees.

**Architecture:** Keep `SecureSession` as the single lifecycle owner and inject cloud-specific topology, IPsec, remote-workload, capture, and evidence adapters. `GcpLabProvider` owns only allowlisted Compute Engine lifecycle; an isolated local namespace reaches a fixed cloud responder over NAT-T, while an authenticated protected service at `10.20.0.1` manages workload endpoints at `10.20.0.2`. The raw session capture remains authoritative for analysis, and only the latest completed workload window is deterministically normalized into native ESP for the unchanged ML pipeline.

**Tech Stack:** Python 3 standard library, Linux namespaces/XFRM, strongSwan/swanctl, tcpdump/tshark, iproute2, nftables or iptables, Google Cloud CLI, systemd, React/Vite, Playwright, unittest.

**Spec:** `docs/superpowers/specs/2026-09-29-ipsec-sentinel-gcp-live-lab-design.md`

## Global Constraints

- Project is fixed to `ipsec-sentinel` (`429285250074`), region `asia-south1`, zone `asia-south1-a`.
- Resources are fixed to VPC `ipsec-sentinel-lab`, subnet `ipsec-sentinel-lab-asia-south1` (`10.70.0.0/24`), and VMs `vpn-secure`, `vpn-aes128`, `vpn-cbc`, `vpn-no-pfs`.
- VMs are Debian 12 `e2-micro`, 10 GB `pd-balanced`, ephemeral public IPv4, no VM service account, and only one may run for a session.
- Permanent ingress is source-`/32` UDP/500 and UDP/4500; source-`/32` TCP/22 exists only during automated provisioning and is deleted afterward. Protocol 50 is not opened.
- The privileged Sentinel Agent remains loopback-only and supports one active session; frontend REST/SSE contracts remain provider-neutral.
- No frontend timer, optimistic transition, or provider cache may fabricate state. Every public event follows a completed command or parsed evidence.
- `SecureSession`, `run_secure_baseline()`, Phase 1/2, Offline PCAP, Guided Demo, and `ipsec-sentinel.analysis/v1` remain backward compatible.
- Capture starts before IKE and runs continuously until analysis seals it or disconnect/failure stops it.
- Raw `full-evidence.pcap` contains real IKE/NAT-T/rekey evidence. `encrypted.pcap` contains only normalized native ESP from the latest completed workload window.
- Mystery scenario, VM name, deployment mapping, configured policy, and provider-private diagnostics stay server-side until explicit reveal.
- Cloud config and credentials stay outside Git; config is strict, owned by the expected account/root, and mode `0600`.
- Ordinary session cleanup may stop an owned VM but never deletes infrastructure. Creation, rollback deletion, or changed resource commands require a separate exact-command preview and approval.
- Implement with focused TDD. Run one cloud E2E, one GitNexus review near the end, and the complete regression suite once as the final gate.
- Do not add SDKs, model training, dataset generation, arbitrary endpoints, new scenarios, native-ESP fallback, autoscaling, or unrelated redesign.

## Review Focus

- A syntactically valid `gcloud` response that describes the wrong project, instance labels, disk, service account, firewall source, or state must block start without repair.
- A local-agent crash while a VM is running must preserve ownership, allow safe recovery, and never stop a pre-existing or unowned VM.
- NAT-T windows containing IKE markers, keepalives, fragments, malformed packets, control traffic, or unexpected peers must fail normalization rather than reach ML.
- Protected control calls must remain outside the workload timestamps; overlap must make the workload artifact invalid.
- Mystery errors, serial output, provider diagnostics, endpoint metadata, and artifact paths must not reveal instance/scenario identity before reveal.

---

## File Structure

### New cloud package

- `ipsec_sentinel/cloud/config.py`: strict local GCP configuration and secure operator/config validation.
- `ipsec_sentinel/cloud/gcloud.py`: fixed-argument non-root `gcloud` execution, JSON parsing, and redacted receipts.
- `ipsec_sentinel/cloud/manifest.py`: immutable approved resource manifest and drift inspection.
- `ipsec_sentinel/cloud/deploy.py`: exact creation/rollback command rendering and serial provisioning journal.
- `ipsec_sentinel/cloud/topology.py`: isolated local client/gateway topology and exact scoped NAT lifecycle.
- `ipsec_sentinel/cloud/ipsec.py`: one-sided local strongSwan client and cloud evidence adapter.
- `ipsec_sentinel/cloud/remote.py`: authenticated protected endpoint client and remote workload runtime.
- `ipsec_sentinel/cloud/endpoint.py`: fixed remote control/evidence server for the VM image.
- `ipsec_sentinel/cloud/natt.py`: strict NAT-T workload parsing and deterministic native-ESP normalization.
- `ipsec_sentinel/cloud/ownership.py`: VM/session ownership journal, watchdog, and recovery decisions.
- `ipsec_sentinel/cloud/__init__.py`: stable public cloud interfaces only.

### New deployment assets

- `config/gcp-lab.example.json`: secret-free exact configuration example.
- `deploy/gcp/bootstrap.sh`: idempotent Debian 12 package/config installation entry point.
- `deploy/gcp/ipsec-sentinel-endpoint.service`: protected endpoint systemd unit.
- `deploy/gcp/ipsec-sentinel-watchdog.service`: bounded self-stop action.
- `deploy/gcp/ipsec-sentinel-watchdog.timer`: cloud-side maximum-runtime timer.
- `scripts/render_gcp_lab_commands.py`: non-mutating command preview.
- `scripts/provision_gcp_lab.py`: separately gated serial provisioning executor.

### Existing files to modify

- `ipsec_sentinel/live/provider.py`: replace the Phase-A GCP stub with the real provider while retaining `LocalLabProvider`.
- `ipsec_sentinel/session.py`: inject narrow backends without changing local defaults.
- `ipsec_sentinel/strongswan.py`: expose reusable single-client operations and evidence collection.
- `ipsec_sentinel/capture.py`: add cloud raw-capture validation without weakening native-ESP validation.
- `ipsec_sentinel/pcap.py`: consume normalized workload artifacts through the existing strict parser.
- `ipsec_sentinel/traffic/base.py` and generator modules: route server-half operations through an injected runtime.
- `ipsec_sentinel/live/orchestrator.py`: provider-neutral connect/traffic/rekey/analyze flow and cloud evidence events.
- `ipsec_sentinel/live/runtime.py`: journal cloud ownership and safely recover stale sessions.
- `ipsec_sentinel/live/api.py`: select a configured provider server-side; do not accept arbitrary provider settings from request bodies.
- `ipsec_sentinel/frontend/__main__.py` and `ipsec_sentinel/frontend/bridge.py`: startup configuration only; preserve frontend API shape.
- `ipsec_sentinel/analyzer/capture.py`, `pipeline.py`, and contract models: retain raw NAT-T evidence and normalized-workload provenance.
- `README.md` and `docs/evidence/gcp-live-lab.md`: operator workflow and final proof.

### New tests

- `tests/test_cloud_config.py`, `test_cloud_gcloud.py`, `test_cloud_manifest.py`, `test_cloud_deploy.py`.
- `tests/test_cloud_provider.py`, `test_cloud_ownership.py`, `test_cloud_topology.py`, `test_cloud_ipsec.py`.
- `tests/test_cloud_remote.py`, `test_cloud_endpoint.py`, `test_cloud_natt.py`.
- `tests/test_cloud_live.py`, `test_cloud_live_integration.py`.

---

### Task 1: Strict cloud configuration and command client

**Files:**
- Create: `ipsec_sentinel/cloud/__init__.py`
- Create: `ipsec_sentinel/cloud/config.py`
- Create: `ipsec_sentinel/cloud/gcloud.py`
- Create: `config/gcp-lab.example.json`
- Test: `tests/test_cloud_config.py`
- Test: `tests/test_cloud_gcloud.py`

**Interfaces:**
- Produces: `GcpLabConfig.load(path: Path, *, account_lookup: AccountLookup = system_account_lookup) -> GcpLabConfig`.
- Produces: `GcloudClient.run(args: Sequence[str], *, timeout: float) -> CommandReceipt` and `run_json(args: Sequence[str], *, timeout: float) -> object`.
- Produces: `CloudConfigurationError`, `GcloudCommandError`, and redacted `CommandReceipt`.
- Consumes: no cloud resources and no mutable GCP calls.

- [ ] **Step 1: Write failing configuration tests** covering exact project/number/region/zone, four scenario mappings, `10.20.0.1` control address, `10.20.0.2` workload address, timeout bounds, mode `0600`, owner/operator identity, unknown keys, and forbidden endpoints.
- [ ] **Step 2: Run** `rtk python3 -m unittest tests.test_cloud_config -v`; expect import/failing validation tests.
- [ ] **Step 3: Implement immutable config models and secure loading** without reading token contents or accepting repository-relative secret paths.
- [ ] **Step 4: Write failing command-client tests** proving fixed `gcloud --project ipsec-sentinel --format=json` construction, `runuser` execution under the configured non-root account, timeout/error behavior, JSON rejection, and secret redaction.
- [ ] **Step 5: Implement the injected subprocess client** using argument arrays only; reject shell fragments, extra filters, arbitrary projects/resources, and mismatched account home/Cloud SDK ownership.
- [ ] **Step 6: Run** `rtk python3 -m unittest tests.test_cloud_config tests.test_cloud_gcloud -v`; expect PASS.
- [ ] **Step 7: Commit** with `rtk git add ... && rtk git commit -m "feat: add strict GCP configuration and command client"`.

### Task 2: Approved manifest, drift inspection, and dry-run commands

**Files:**
- Create: `ipsec_sentinel/cloud/manifest.py`
- Create: `ipsec_sentinel/cloud/deploy.py`
- Create: `scripts/render_gcp_lab_commands.py`
- Test: `tests/test_cloud_manifest.py`
- Test: `tests/test_cloud_deploy.py`

**Interfaces:**
- Consumes: `GcpLabConfig`, `GcloudClient`.
- Produces: `GcpDeploymentManifest.approved() -> GcpDeploymentManifest`.
- Produces: `inspect_deployment(client, manifest, source_cidr) -> DeploymentInspection`.
- Produces: `render_creation_commands(manifest, source_cidr) -> tuple[CloudCommand, ...]` and `render_rollback_commands(...)`.

- [ ] **Step 1: Write failing manifest tests** for all approved names, labels, tags, Debian 12 image family/project, `e2-micro`, 10 GB `pd-balanced`, `canIpForward`, no service account, VPC/subnet, source `/32`, UDP/500+4500, and temporary TCP/22.
- [ ] **Step 2: Write failing review-focus drift tests** where otherwise valid JSON reports a wrong project number, instance label, disk type/size, service account, source range, port, or running-state ownership; assert a stable blocking diagnostic and zero repair commands.
- [ ] **Step 3: Implement the immutable manifest and read-only inspector** with deterministic issue ordering.
- [ ] **Step 4: Write failing renderer tests** asserting the complete ordered command list and reverse rollback list, with no execution side effect and no protocol-50 rule.
- [ ] **Step 5: Implement exact command rendering and the preview CLI**; default behavior must be render-only and must have no implicit apply path.
- [ ] **Step 6: Run** `rtk python3 -m unittest tests.test_cloud_manifest tests.test_cloud_deploy -v`; expect PASS.
- [ ] **Step 7: Commit** with `rtk git add ... && rtk git commit -m "feat: define approved GCP lab manifest"`.

### Task 3: GCP provider lifecycle

**Files:**
- Modify: `ipsec_sentinel/live/provider.py`
- Create: `tests/test_cloud_provider.py`
- Modify: `tests/test_live_provider.py`

**Interfaces:**
- Consumes: `GcloudClient`, `GcpDeploymentManifest`, `DeploymentInspection`, `CloudOwnershipStore` from Task 10 through an initially defined protocol.
- Produces: existing `LabProvider` methods on `GcpLabProvider` and public `ProviderEndpoint(provider, display_name, address, transport, scenario_id, private)`.
- Produces: `CloudProviderError(code: str, public_message: str, diagnostics: Mapping[str, object])`.
- Produces: `ProviderOwnershipStore` protocol with `acquire(...)`, `read()`, `record_endpoint(...)`, `record_stop_failure(...)`, and `release()`; Task 10 supplies its persistent implementation.

- [ ] **Step 1: Write failing provider tests** for allowlist resolution, stopped-to-running transitions, bounded polling, neutral readiness marker, public endpoint projection, fresh health, stop/wait/address release, and idempotent stop.
- [ ] **Step 2: Add failure tests** for drift, an already-running unowned VM, wrong instance, timeout, stale cached health, malformed serial output, and stop failure preserving diagnostics.
- [ ] **Step 3: Implement `GcpLabProvider`** with injected clock/sleeper/client and no local namespace, capture, traffic, rekey, or analysis ownership.
- [ ] **Step 4: Verify LocalLabProvider compatibility** with the existing tests and ensure `to_public_dict()` cannot expose private provider data.
- [ ] **Step 5: Run** `rtk python3 -m unittest tests.test_cloud_provider tests.test_live_provider -v`; expect PASS.
- [ ] **Step 6: Commit** with `rtk git add ... && rtk git commit -m "feat: implement allowlisted GCP lab provider"`.

### Task 4: Isolated cloud-client topology

**Files:**
- Create: `ipsec_sentinel/cloud/topology.py`
- Create: `tests/test_cloud_topology.py`

**Interfaces:**
- Produces: `CloudClientTopology.setup(endpoint: IPv4Address)`, `verify() -> TopologyEvidence`, `snapshot() -> Mapping[str, object]`, and idempotent `reset()`.
- Produces: `NatRuleIdentity(backend, table, chain, handle_or_spec, source_cidr, output_interface)`.
- Consumes: existing command-runner conventions and the ownership recorder.

- [ ] **Step 1: Write failing command-plan tests** for `ips-client`/`ips-gwa`, `10.10.0.2/24`, `10.10.0.1/24`, `172.31.254.2/30`, `172.31.254.1/30`, protected route, forwarding, rp_filter, and scoped host NAT.
- [ ] **Step 2: Add safety tests** proving host default routes are never changed, broad MASQUERADE/flush commands are rejected, conflicts fail before mutation, and reset removes only the recorded rule/interface/namespaces.
- [ ] **Step 3: Implement topology planning, journaling-before-mutation, verification, snapshot, and reverse idempotent cleanup** with an injected command runner.
- [ ] **Step 4: Run** `rtk python3 -m unittest tests.test_cloud_topology -v`; expect PASS.
- [ ] **Step 5: Commit** with `rtk git add ... && rtk git commit -m "feat: add isolated cloud client topology"`.

### Task 5: Reusable SecureSession and single-client IPsec adapters

**Files:**
- Modify: `ipsec_sentinel/session.py`
- Modify: `ipsec_sentinel/strongswan.py`
- Create: `ipsec_sentinel/cloud/ipsec.py`
- Modify: `tests/test_session.py`
- Modify: `tests/test_strongswan.py`
- Create: `tests/test_cloud_ipsec.py`

**Interfaces:**
- Produces: protocols `SessionTopology`, `SessionIpsec`, `SessionCapture`, and `SessionEvidenceCollector` with the operations already sequenced by `SecureSession`.
- Produces: `CloudStrongSwanClient` for one local daemon and `CloudEvidenceCollector` translating protected remote evidence into existing gateway-a/gateway-b structures.
- Preserves: every existing `SecureSession(...)` call and `run_secure_baseline()` default.

- [ ] **Step 1: Write failing compatibility tests** that instantiate `SecureSession` exactly as Phase 1 does and compare the existing command/evidence/cleanup ordering.
- [ ] **Step 2: Write failing cloud-adapter tests** for a single local strongSwan runtime, endpoint-derived NAT-T config, local/remote SA and XFRM pairing, rekey before/after snapshots, configured-versus-observed provenance, and no-PFS semantics.
- [ ] **Step 3: Extract only the narrow backend protocols and inject optional defaults**; keep the local `Topology`/`StrongSwanPair` path unchanged.
- [ ] **Step 4: Implement the one-sided cloud client/evidence adapter** using separate runtime/VICI/config paths and the existing tunnel/PFS evaluators without weakening them.
- [ ] **Step 5: Run focused compatibility tests**: `rtk python3 -m unittest tests.test_session tests.test_strongswan tests.test_cloud_ipsec -v`; expect PASS.
- [ ] **Step 6: Commit** with `rtk git add ... && rtk git commit -m "refactor: inject secure session backends"`.

### Task 6: Protected VM endpoint and image assets

**Files:**
- Create: `ipsec_sentinel/cloud/endpoint.py`
- Create: `deploy/gcp/bootstrap.sh`
- Create: `deploy/gcp/ipsec-sentinel-endpoint.service`
- Create: `deploy/gcp/ipsec-sentinel-watchdog.service`
- Create: `deploy/gcp/ipsec-sentinel-watchdog.timer`
- Create: `tests/test_cloud_endpoint.py`

**Interfaces:**
- Produces versioned HTTPS routes for health, workload prepare/receipt/cleanup, and allowlisted strongSwan/XFRM/log evidence.
- Consumes: deployment token, session nonce, fixed scenario manifest, and protected bind address `10.20.0.1`.
- Workload processes execute only inside the server namespace with address `10.20.0.2`.

- [ ] **Step 1: Write failing protocol tests** for TLS-only protected binding, constant-time token validation, nonce scoping, size/time bounds, strict schemas, one workload at a time, and absence of shell/path/upload primitives.
- [ ] **Step 2: Add endpoint tests** for health/version, allowlisted evidence fields, workload lifecycle, cleanup idempotency, sanitized logs, and rejection before tunnel reachability.
- [ ] **Step 3: Implement the minimal standard-library endpoint service** and handlers; keep raw credentials, commands, and filesystem paths out of responses.
- [ ] **Step 4: Write asset tests** asserting root ownership/modes, namespace/routes, forwarding/rp_filter checks, exact scenario install, neutral boot marker, bounded systemd restart, and watchdog self-stop.
- [ ] **Step 5: Implement the idempotent bootstrap and units** without startup-metadata secrets or mutable runtime downloads.
- [ ] **Step 6: Run** `rtk python3 -m unittest tests.test_cloud_endpoint -v`; expect PASS.
- [ ] **Step 7: Commit** with `rtk git add ... && rtk git commit -m "feat: add protected cloud responder endpoint"`.

### Task 7: Remote workload runtime for all seven generators

**Files:**
- Modify: `ipsec_sentinel/traffic/base.py`
- Modify: `ipsec_sentinel/traffic/web.py`
- Modify: `ipsec_sentinel/traffic/video.py`
- Modify: `ipsec_sentinel/traffic/voip.py`
- Modify: `ipsec_sentinel/traffic/email.py`
- Modify: `ipsec_sentinel/traffic/messaging.py`
- Modify: `ipsec_sentinel/traffic/file_transfer.py`
- Create: `ipsec_sentinel/cloud/remote.py`
- Create: `tests/test_cloud_remote.py`
- Modify: `tests/test_traffic_contract.py`

**Interfaces:**
- Produces: `TrafficServerRuntime.prepare(request: ServerWorkloadRequest) -> ServerWorkloadReceipt`, `receipt(workload_id)`, and `cleanup(workload_id)`.
- Produces: `LocalTrafficServerRuntime` preserving current subprocess behavior and `RemoteTrafficServerRuntime` calling the protected endpoint.
- Preserves: generator `prepare/run/validate/cleanup/metadata` semantics and seeded plans.

- [ ] **Step 1: Write failing contract tests** proving the same seed/scenario/version produces the same server plan under local and remote runtimes for ICMP, Web, Video, VoIP, Email, Messaging, and File Transfer.
- [ ] **Step 2: Add validation tests** for server receipt/byte/checksum/message/direction evidence, unsupported workload rejection, only one prepared workload, bounded cleanup, and sensitive-field redaction.
- [ ] **Step 3: Extract the server runtime interface and local default** without changing existing generator call sites or metadata.
- [ ] **Step 4: Implement the remote runtime and endpoint handlers** so control prepare completes before `workload_started_ns` and receipt/cleanup begins after `workload_ended_ns`.
- [ ] **Step 5: Run** `rtk python3 -m unittest tests.test_traffic_contract tests.test_cloud_remote tests.test_traffic_icmp tests.test_traffic_web tests.test_traffic_video tests.test_traffic_voip tests.test_traffic_email tests.test_traffic_messaging tests.test_traffic_file_transfer -v`; expect PASS.
- [ ] **Step 6: Commit** with `rtk git add ... && rtk git commit -m "refactor: support remote workload servers"`.

### Task 8: Strict NAT-T evidence and workload normalization

**Files:**
- Create: `ipsec_sentinel/cloud/natt.py`
- Modify: `ipsec_sentinel/capture.py`
- Modify: `ipsec_sentinel/pcap.py`
- Modify: `ipsec_sentinel/analyzer/capture.py`
- Modify: `ipsec_sentinel/analyzer/pipeline.py`
- Modify: `ipsec_sentinel/analyzer/models.py`
- Create: `tests/test_cloud_natt.py`
- Modify: `tests/test_capture.py`
- Modify: `tests/test_analyzer_capture.py`
- Modify: `tests/test_analyzer_contract.py`

**Interfaces:**
- Produces: `validate_cloud_full_capture(path, expected_peers) -> CloudCaptureEvidence`.
- Produces: `normalize_natt_workload(source, destination, expected_peers, started_ns, ended_ns) -> NattNormalizationReceipt`.
- Adds provenance value `NATT_NORMALIZED_WORKLOAD_WINDOW` without changing the analysis contract version.

- [ ] **Step 1: Add packet fixtures and failing positive tests** proving UDP/500 plus UDP/4500 remains in raw evidence, valid ESP-in-UDP is converted to native ESP, timestamps/directions/SPI/sequence/payload are preserved, IPv4 length/checksum is rebuilt, and hashes/version/counts are recorded.
- [ ] **Step 2: Add review-focus rejection tests** for non-ESP-marker IKE, keepalive, fragment, malformed/truncated payload, unexpected peer/protocol/timestamp, empty output, and any control-channel timestamp overlap.
- [ ] **Step 3: Implement strict NAT-T parsing and deterministic normalization** without teaching the existing ML parser to accept UDP.
- [ ] **Step 4: Integrate raw-vs-normalized analyzer provenance** so security/protocol analysis uses `full-evidence.pcap` and ML/X-Ray use only validated `encrypted.pcap`.
- [ ] **Step 5: Run** `rtk python3 -m unittest tests.test_cloud_natt tests.test_capture tests.test_pcap_workload tests.test_analyzer_capture tests.test_analyzer_contract -v`; expect PASS.
- [ ] **Step 6: Commit** with `rtk git add ... && rtk git commit -m "feat: normalize NAT-T workload evidence"`.

### Task 9: Provider-neutral Live Lab orchestration

**Files:**
- Modify: `ipsec_sentinel/live/orchestrator.py`
- Modify: `ipsec_sentinel/live/api.py`
- Modify: `ipsec_sentinel/frontend/__main__.py`
- Modify: `ipsec_sentinel/frontend/bridge.py`
- Create: `tests/test_cloud_live.py`
- Modify: `tests/test_live_orchestrator.py`
- Modify: `tests/test_live_api.py`
- Modify: `tests/test_frontend_bridge.py`

**Interfaces:**
- Consumes: configured `LabProvider`, injected `SecureSession` backends, remote runtime, and normalizer.
- Produces: the existing REST actions and ordered/persisted/replayable SSE schema; no request may provide project, VM, endpoint, credentials, or provider command arguments.

- [ ] **Step 1: Write failing orchestration tests** for cloud connect order, real readiness/IKE/CHILD/XFRM/ESP events, ICMP and Video windows, latest-window ML, rekey evidence, analysis sealing, disconnect, and primary-vs-cleanup failure separation.
- [ ] **Step 2: Write API/startup tests** proving provider selection comes only from secure process configuration, invalid commands retain existing state-machine rejection, `Last-Event-ID` replay reconstructs the provider-neutral session after reconnect, and REST/SSE payload shapes remain frontend-compatible.
- [ ] **Step 3: Implement provider/session factories and cloud orchestration** without a parallel lifecycle or frontend cloud branches.
- [ ] **Step 4: Ensure event emission follows completed actions or parsed evidence only** and retain continuous capture across connect, multiple traffic actions, rekey, and analysis.
- [ ] **Step 5: Run** `rtk python3 -m unittest tests.test_cloud_live tests.test_live_orchestrator tests.test_live_api tests.test_frontend_bridge -v`; expect PASS.
- [ ] **Step 6: Commit** with `rtk git add ... && rtk git commit -m "feat: wire GCP into Live Lab orchestration"`.

### Task 10: Cloud ownership, recovery, watchdog, and Mystery redaction

**Files:**
- Create: `ipsec_sentinel/cloud/ownership.py`
- Modify: `ipsec_sentinel/live/runtime.py`
- Modify: `ipsec_sentinel/live/provider.py`
- Modify: `ipsec_sentinel/live/models.py`
- Create: `tests/test_cloud_ownership.py`
- Modify: `tests/test_live_runtime.py`
- Modify: `tests/test_live_models.py`

**Interfaces:**
- Produces: `CloudOwnership(project, zone, instance, scenario_id, acquired_state, acquired_at, deployment_id)` and atomic `CloudOwnershipStore` operations.
- Produces: `recover_cloud_ownership(record, manifest, client) -> CloudRecoveryReport`.
- Produces: centralized `redact_provider_payload(payload, *, revealed: bool) -> dict[str, object]`.

- [ ] **Step 1: Write failing ownership tests** for journal-before-wait, exact project/zone/instance/deployment matching, pre-existing-running refusal, owned stop, stop-failure retention, and idempotent recovery.
- [ ] **Step 2: Add crash/review-focus tests** proving a stale local PID may stop only the journaled owned VM, identity drift blocks recovery, an unowned VM is never stopped, and the safe operator command is preserved when cleanup fails.
- [ ] **Step 3: Implement atomic ownership and recovery** and extend startup recovery without weakening namespace/process/path identity checks.
- [ ] **Step 4: Add Mystery leakage tests** covering errors, serial text, instance labels/names, scenario IDs, addresses where hidden, paths, remote responses, and diagnostics before reveal; assert observed cryptographic evidence remains visible.
- [ ] **Step 5: Implement the single redaction boundary** used before persistence to public snapshots/events and before API serialization.
- [ ] **Step 6: Run** `rtk python3 -m unittest tests.test_cloud_ownership tests.test_live_runtime tests.test_live_models tests.test_cloud_provider -v`; expect PASS.
- [ ] **Step 7: Commit** with `rtk git add ... && rtk git commit -m "feat: recover owned cloud sessions safely"`.

### Task 11: Serial provisioning executor and operator documentation

**Files:**
- Modify: `ipsec_sentinel/cloud/deploy.py`
- Create: `scripts/provision_gcp_lab.py`
- Modify: `README.md`
- Create: `docs/evidence/gcp-live-lab.md`
- Modify: `tests/test_cloud_deploy.py`

**Interfaces:**
- Produces: `ProvisioningJournal`, `ProvisioningExecutor.preview()`, and explicitly gated `apply(approval_digest: str)`.
- Consumes: the exact rendered command set whose digest was separately approved.

- [ ] **Step 1: Write failing executor tests** for render-only default, digest mismatch, sequential execution, journal-after-success, failure halt, reverse rollback plan, no automatic destructive rollback, temporary SSH-rule removal, and final drift check.
- [ ] **Step 2: Implement the executor CLI** so `--apply` still requires the exact preview digest and never infers approval from spec/plan approval.
- [ ] **Step 3: Document authentication, secure config creation, WSL operator identity, preview, approval gate, provisioning, start/stop, logs, watchdog, and explicit teardown commands** without embedding credentials.
- [ ] **Step 4: Run** `rtk python3 -m unittest tests.test_cloud_deploy -v`; expect PASS.
- [ ] **Step 5: Run a non-mutating CLI smoke** with a temporary test config and fake client; verify no `networks create`, `firewall-rules create`, `disks create`, or `instances create` command executes.
- [ ] **Step 6: Commit** with `rtk git add ... && rtk git commit -m "feat: add gated GCP lab deployment workflow"`.

### Task 12: Targeted local privileged boundary proof

**Files:**
- Create: `tests/test_cloud_live_integration.py`
- Modify: `docs/evidence/gcp-live-lab.md`

**Interfaces:**
- Consumes: Tasks 4, 5, 7, and 8 with no GCP resources.
- Produces: evidence that the cloud-client topology, NAT cleanup, local single-client lifecycle, and NAT-T normalizer work under real Linux privileges.

- [ ] **Step 1: Add an opt-in privileged integration test** gated by `IPSEC_SENTINEL_CLOUD_LOCAL_INTEGRATION=1`; it must skip cleanly elsewhere.
- [ ] **Step 2: Run the test before final wiring** using `rtk sudo env IPSEC_SENTINEL_CLOUD_LOCAL_INTEGRATION=1 /home/black/.venvs/ipsec-sentinel-ml/bin/python -m unittest tests.test_cloud_live_integration -v`; expect a precise failing boundary.
- [ ] **Step 3: Fix only the discovered local boundary defects** with focused regression tests; do not redesign the working Phase 1 topology.
- [ ] **Step 4: Re-run the targeted privileged test**; expect PASS and verify host default route unchanged, exact NAT rule absent afterward, namespaces/processes removed, raw NAT-T fixture accepted, and normalized PCAP is ESP-only.
- [ ] **Step 5: Record hashes, packet proof, cleanup output, and commands** in `docs/evidence/gcp-live-lab.md`.
- [ ] **Step 6: Commit** with `rtk git add ... && rtk git commit -m "test: prove local GCP integration boundaries"`.

### Task 13: Mandatory exact resource-command preview checkpoint

**Files:**
- Modify: `docs/evidence/gcp-live-lab.md`

**Interfaces:**
- Consumes: authenticated read-only `gcloud`, approved manifest, detected operator public `/32`.
- Produces: the exact creation and rollback command report plus digest. This task does not mutate GCP.

- [ ] **Step 1: Run read-only identity/API/resource inspection** for active account, project ID/number, region/zone, Compute API state, source public `/32`, and collisions under every approved resource name.
- [ ] **Step 2: Render every exact creation command in execution order** for VPC, subnet, UDP firewall, temporary SSH firewall, and four stopped-capable VMs, including image, disk, labels, tags, no service account, and `canIpForward`.
- [ ] **Step 3: Render exact stop and destructive rollback commands separately**, clearly labeling which actions are ordinary cleanup and which require later destructive approval.
- [ ] **Step 4: Report estimated running and stopped cost, APIs, security implications, resource absence/drift, and preview digest** to the user.
- [ ] **Step 5: STOP and wait for explicit approval of this exact command set.** Specification, plan, implementation, or generic continuation approval is insufficient.

### Task 14: Approved resource creation and responder provisioning

**Files:**
- Modify: `docs/evidence/gcp-live-lab.md`

**Interfaces:**
- Consumes: the exact approval digest from Task 13.
- Produces: four provisioned, validated, stopped responder VMs and retained command/provisioning evidence.

- [ ] **Step 1: Re-render commands and verify the digest still matches** immediately before the first mutation; stop if any argument, source CIDR, resource state, or cost assumption changed.
- [ ] **Step 2: Execute approved creation commands serially** and journal each successfully created resource; do not create unapproved replacements.
- [ ] **Step 3: Enable temporary source-`/32` TCP/22 only for automated provisioning**, install fixed assets/config/credentials, and run scenario-neutral health validation for one VM at a time.
- [ ] **Step 4: Remove the TCP/22 rule and independently verify it is absent** before any Live Lab smoke.
- [ ] **Step 5: Perform one minimal readiness start/health/stop check per VM**, confirm scenario proposal/XFRM prerequisites locally on each responder, and leave all four `TERMINATED`.
- [ ] **Step 6: On failure, stop newly started VMs, preserve the journal, show exact reverse rollback actions, and request approval before destructive deletion.**
- [ ] **Step 7: Commit only non-secret evidence/documentation** with `rtk git add docs/evidence/gcp-live-lab.md && rtk git commit -m "docs: record GCP responder deployment"`.

### Task 15: One end-to-end cloud Live Lab verification

**Files:**
- Modify: `tests/test_cloud_live_integration.py`
- Modify: `docs/evidence/gcp-live-lab.md`

**Interfaces:**
- Consumes: fully deployed stopped responders and secure local config.
- Produces: one retained real cloud session proving the complete user flow.

- [ ] **Step 1: Add the opt-in cloud E2E** gated by `IPSEC_SENTINEL_GCP_INTEGRATION=1`; it selects one controlled Mystery scenario server-side and records the session ID.
- [ ] **Step 2: Run exactly one cloud session**: start VM, wait for real readiness, start capture before IKE, establish NAT-T IPsec, verify local+remote SA/XFRM, run ICMP, run Video, infer only from Video's completed window, trigger CHILD rekey, evaluate PFS, analyze raw evidence, replay SSE from a mid-session event ID, reveal Mystery ground truth, disconnect, and stop VM.
- [ ] **Step 3: Assert evidence quality**: raw PCAP has UDP/500, UDP/4500, workload, and rekey; normalized PCAP is non-empty native ESP only; no IKE/UDP/control/rekey leakage enters ML; model result is present; security provenance distinguishes configured/observed/derived/AI/ground truth.
- [ ] **Step 4: Assert complete cleanup**: provider VM `TERMINATED`, ephemeral address released, no namespaces/veth/routes/NAT rules/charon/tcpdump/locks/runtime residue, and watchdog evidence retained.
- [ ] **Step 5: Record actual packet counts, byte counts, hashes, ML result, rekey/PFS evidence, SSE replay, runtime, stopped/running cost estimate, and cleanup** without secrets or hidden Mystery identity before the reveal entry.
- [ ] **Step 6: If a layer fails, fix and rerun only that targeted layer; repeat the full cloud session only when necessary to prove the corrected boundary.**
- [ ] **Step 7: Commit** with `rtk git add ... && rtk git commit -m "test: verify GCP Live Lab end to end"`.

### Task 16: Final review and single regression gate

**Files:**
- Modify as required by review findings.
- Modify: `docs/evidence/gcp-live-lab.md`

**Interfaces:**
- Consumes: the complete branch diff and retained local/cloud evidence.
- Produces: reviewed, regression-tested Phase B commit with a clean worktree and no merge/push.

- [ ] **Step 1: Run GitNexus once on the completed branch** and review impact across `SecureSession`, strongSwan, traffic generators, analyzer, Live Lab state/event/API contracts, runtime recovery, and frontend bridge.
- [ ] **Step 2: Perform one focused fix pass** for findings, adding the smallest regression test for each accepted issue; do not rerun GitNexus unless the review itself was unusable.
- [ ] **Step 3: Recheck the five Review Focus cases** and audit command injection, credential/log leakage, Mystery leakage, unowned-resource cleanup, model-window contamination, and host-route/NAT safety.
- [ ] **Step 4: Run the complete Python suite once**: `rtk /home/black/.venvs/ipsec-sentinel-ml/bin/python -m unittest discover -s tests -v`; record pass/fail/skip counts.
- [ ] **Step 5: Run the final privileged regressions once** for Phase 1 secure baseline, Phase 2 dataset integrations, Phase A Live Lab, and the targeted cloud boundary using their documented opt-in environment variables; record every command/result.
- [ ] **Step 6: Run frontend unit/build/accessibility checks and Playwright** for Offline PCAP, Guided Demo, local Live Lab connect/traffic/rekey/analyze/disconnect, SSE replay, failure cleanup, and provider-neutral UI; expect all PASS.
- [ ] **Step 7: Verify all four cloud VMs are `TERMINATED`, TCP/22 rule is absent, no unexpected billable resources exist, and the local worktree contains no secret/config/runtime artifact.**
- [ ] **Step 8: Update final evidence and commit** with `rtk git add ... && rtk git commit -m "feat: complete GCP Live Lab integration"`.
- [ ] **Step 9: Report branch, commit SHA, architecture, resource inventory, tests, cloud E2E, capture/ML/PFS/security proof, cleanup, costs, limitations, and worktree status. Do not merge or push.**
