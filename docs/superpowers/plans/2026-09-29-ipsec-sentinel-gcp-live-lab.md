# IPsec Sentinel GCP Live Lab Prototype Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the minimum real GCP Live Lab flow from VM start through NAT-T IPsec, ICMP/Video analysis, rekey/PFS, live UI evidence, disconnect, and VM stop.

**Architecture:** Retain `SecureSession` as lifecycle owner, implement a narrow `GcpLabProvider`, and add only the cloud adapters required by ICMP and Video. A local isolated namespace connects to one of four fixed strongSwan VMs over NAT-T; the full wire capture feeds protocol/security analysis while the latest completed workload window is normalized into the existing ESP-only ML format. The existing REST/SSE/frontend contract remains provider-neutral and Mystery data stays server-side.

**Tech Stack:** Python 3 standard library, Linux namespaces/XFRM, strongSwan/swanctl, tcpdump/tshark, iproute2, nftables or iptables, Google Cloud CLI, systemd, React/Vite, Playwright, unittest.

**Spec:** `docs/superpowers/specs/2026-09-29-ipsec-sentinel-gcp-live-lab-design.md`, with the prototype scope override recorded below.

## Global Constraints

- Project is fixed to `ipsec-sentinel` (`429285250074`), region `asia-south1`, zone `asia-south1-a`.
- Resources are fixed to VPC `ipsec-sentinel-lab`, subnet `ipsec-sentinel-lab-asia-south1` (`10.70.0.0/24`), and four VMs: `vpn-secure`, `vpn-aes128`, `vpn-cbc`, `vpn-no-pfs`.
- Primary cloud transport is NAT-T on UDP/500 and UDP/4500; no protocol-50 firewall rule or native-ESP fallback is added.
- The Sentinel Agent remains loopback-only, supports one active session, and keeps the existing REST/SSE schema.
- Capture begins before IKE and remains continuous until analysis seals it or disconnect/failure stops it.
- `full-evidence.pcap` retains raw IKE/NAT-T/rekey evidence. `encrypted.pcap` is derived only from the latest completed workload window and must pass the existing native-ESP-only parser.
- `SecureSession`, `run_secure_baseline()`, local Phase A, Offline PCAP, Guided Demo, and `ipsec-sentinel.analysis/v1` remain backward compatible.
- Mystery scenario, instance identity, configured policy, and provider diagnostics remain server-side until reveal.
- Ordinary cleanup may stop only the owned VM; it never deletes cloud infrastructure.
- No network, firewall, disk, or VM creation command runs before the exact command set is shown and separately approved.
- Implementation uses syntax/import checks and tiny targeted smokes only. There are no per-component suite runs and no Phase A suite reruns during development.
- Verification order is exactly: one cloud E2E, targeted fixes, one GitNexus review, targeted fixes, then one complete regression gate.
- Do not merge or push automatically.

## Prototype Scope Override

Cloud mode in this milestone supports only:

- ICMP;
- Video;
- the four already validated IPsec scenarios;
- rekey/PFS, analyzer/security, ML, SSE/frontend, Mystery reveal, and cleanup.

Deferred without modifying their proven local implementations:

- cloud Web, VoIP, Email, Messaging, and File Transfer;
- a generalized remote workload runtime;
- nonessential framework abstractions and exhaustive infrastructure edge-case machinery;
- new scenarios, dataset/model work, and native-ESP cloud fallback.

## Review Focus

- Resource drift or a pre-existing unowned running VM must block start, not be repaired or stopped.
- NAT-T normalization must reject IKE markers, keepalives, malformed/fragments, unexpected peers, control traffic, and packets outside the latest workload window.
- Local setup and cleanup must never alter the host default route or flush shared firewall state.
- Mystery API/SSE/errors must not expose instance or scenario identity before reveal.
- Disconnect, failure, or process recovery must stop only the recorded owned VM and remove the exact local namespaces, veth, routes, NAT rule, strongSwan, tcpdump, lock, and runtime state.

---

## Minimal File Map

### Add

- `ipsec_sentinel/cloud/config.py`: fixed project/scenario/operator configuration.
- `ipsec_sentinel/cloud/gcloud.py`: allowlisted non-root `gcloud` command execution and JSON parsing.
- `ipsec_sentinel/cloud/manifest.py`: approved resource description, read-only drift validation, and exact command rendering.
- `ipsec_sentinel/cloud/topology.py`: isolated client/gateway namespace and exact scoped NAT cleanup.
- `ipsec_sentinel/cloud/ipsec.py`: single local strongSwan client plus protected remote evidence calls.
- `ipsec_sentinel/cloud/endpoint.py`: small protected VM service for health, evidence, and Video server control.
- `ipsec_sentinel/cloud/natt.py`: strict ESP-in-UDP slicing and native-ESP normalization.
- `ipsec_sentinel/cloud/__init__.py`: public cloud types.
- `deploy/gcp/bootstrap.sh`: reproducible responder provisioning for the four scenarios.
- `deploy/gcp/ipsec-sentinel-endpoint.service`: protected endpoint service.
- `deploy/gcp/ipsec-sentinel-watchdog.service` and `.timer`: bounded VM self-shutdown.
- `scripts/render_gcp_lab_commands.py`: non-mutating exact command preview.
- `scripts/provision_gcp_lab.py`: approved command execution and responder provisioning.
- `tests/test_gcp_prototype.py`: compact targeted checks for command safety, normalization, Mystery redaction, and cleanup planning.
- `tests/test_gcp_live_integration.py`: opt-in single real cloud E2E.
- `docs/evidence/gcp-live-lab.md`: retained preview, deployment, E2E, and final verification evidence.

### Modify only where required

- `ipsec_sentinel/live/provider.py`: implement `GcpLabProvider`; preserve `LocalLabProvider`.
- `ipsec_sentinel/session.py` and `ipsec_sentinel/strongswan.py`: inject the minimum cloud topology/IPsec/evidence seams while retaining local defaults.
- `ipsec_sentinel/capture.py`, `ipsec_sentinel/pcap.py`, and analyzer capture/pipeline models: raw NAT-T evidence plus normalized ML provenance.
- `ipsec_sentinel/traffic/video.py`: permit a narrow protected remote Video server controller; ICMP needs no remote server process.
- `ipsec_sentinel/live/orchestrator.py`, `runtime.py`, `api.py`, and frontend bridge/startup: provider selection, ownership, real events, Mystery redaction, and cleanup.
- Existing React UI only if provider-neutral events expose a missing state; do not redesign it.
- `README.md`: concise GCP operator workflow.

---

### Stage 1: Build the complete local/cloud integration path

**Produces:** A code-complete but not yet provisioned GCP path from provider selection through cleanup.

- [ ] Implement strict `GcpLabConfig` and an argument-array-only `GcloudClient`; accept only the fixed project, zone, scenario mapping, operator identity, secure credential paths, and bounded timeouts.
- [ ] Implement the approved manifest and read-only validation for project number, VPC/subnet, UDP firewall source `/32`, instance names/zone/status, machine type, disk, labels/tags, `canIpForward`, and service-account absence.
- [ ] Implement `GcpLabProvider.start_scenario()`, `wait_until_ready()`, `endpoint()`, `health()`, and idempotent `stop_scenario()` with a small atomic ownership record. Refuse an already-running unowned VM.
- [ ] Implement the isolated `ips-client`/`ips-gwa` cloud topology using `10.10.0.0/24` and `172.31.254.0/30`, a protected route to `10.20.0.0/24`, and an exact scoped host MASQUERADE rule. Never change the host default route.
- [ ] Add the smallest optional seams to `SecureSession` for cloud topology, one-sided strongSwan, raw capture peer/interface, and remote evidence. Existing constructors and local defaults must remain unchanged.
- [ ] Implement the local cloud strongSwan client for the four allowlisted proposals and NAT-T, with independent runtime/config/VICI paths and the existing SA/XFRM/rekey/PFS evaluators.
- [ ] Implement the protected responder service at `10.20.0.1` for health, sanitized strongSwan/XFRM evidence, and allowlisted Video prepare/receipt/cleanup. Video data terminates at `10.20.0.2`; ICMP targets `10.20.0.2` directly.
- [ ] Implement responder bootstrap/systemd/watchdog assets for the four exact scenarios. Do not build a generalized workload RPC framework.
- [ ] Implement continuous raw transit capture and strict normalization of only valid UDP/4500 ESP-in-UDP packets from the latest completed workload window into the existing native-ESP PCAP format.
- [ ] Wire provider-neutral orchestration for connect, ICMP, Video, ML, rekey, analysis, SSE replay, Mystery reveal, disconnect, and exact local/cloud cleanup.
- [ ] Preserve public REST/SSE shapes and ensure events are emitted only after completed actions or parsed evidence.
- [ ] Add only compact targeted checks in `tests/test_gcp_prototype.py` for fixed command/resource allowlists, unowned-VM refusal, normalization rejection, latest-window isolation, Mystery redaction, and exact cleanup plans.
- [ ] During this stage run only `rtk python3 -m compileall ipsec_sentinel scripts` plus individual import or single-test-method checks when needed to unblock implementation. Do not run subsystem or full suites.
- [ ] Commit the integrated code once it is coherent with `rtk git commit -m "feat: add GCP Live Lab prototype"`.

### Stage 2: Non-mutating local readiness and exact cloud command preview

**Produces:** Evidence that code imports, the fixed command plan is safe, and the exact resource mutations are ready for separate approval.

- [ ] Run the compact targeted checks once: `rtk python3 -m unittest tests.test_gcp_prototype -v`. Fix only failing boundaries and rerun only the failed method until green.
- [ ] Run read-only `gcloud` inspection for active account, project ID/number, Compute API state, region/zone, source public `/32`, and collisions/drift under every approved resource name.
- [ ] Render the exact ordered commands for VPC, subnet, UDP firewall, temporary provisioning SSH firewall, and four Debian 12 `e2-micro`/10 GB `pd-balanced` VMs with ephemeral IPv4, `canIpForward`, and no service account.
- [ ] Render stop commands and destructive rollback commands separately, compute a preview digest, and record estimated running/stopped cost and security implications.
- [ ] STOP and show the exact commands to the user. Wait for explicit approval of that exact digest before creating any network, firewall, disk, or VM resource.

### Stage 3: Provision the approved responders

**Produces:** Four reproducibly configured, validated, stopped scenario VMs.

- [ ] Immediately re-render and compare the approved digest; stop if any command, CIDR, source address, image, disk, machine type, resource state, or price assumption changed.
- [ ] Execute only the approved creation commands serially and journal each resource created.
- [ ] Temporarily enable source-`/32` TCP/22, provision one VM at a time with the fixed strongSwan scenario, protected namespace/service, credentials, health checks, and self-shutdown timer, then stop it.
- [ ] Delete the temporary SSH firewall rule and verify it is absent.
- [ ] Perform only a minimal start/readiness/stop smoke for each scenario and leave all four VMs `TERMINATED`.
- [ ] On failure, stop any started VM and preserve diagnostics. Show destructive rollback commands and wait for approval before deleting resources.

### Stage 4: Run one real cloud end-to-end session

**Produces:** One retained session proving the complete product flow.

- [ ] Run `tests.test_gcp_live_integration` once with the secure local config and model path.
- [ ] The test must start one server-selected Mystery scenario, discover its endpoint, create the isolated local client, start capture before IKE, establish IKEv2/NAT-T, verify local and remote SA/XFRM, and emit evidence-backed SSE transitions to `TUNNEL_ACTIVE`.
- [ ] Run real ICMP and then real Video through the protected path. Derive ML input only from Video's completed window and require a model inference.
- [ ] Trigger a genuine CHILD_SA rekey, retain before/after SPI evidence, and evaluate PFS using the existing provenance rules.
- [ ] Analyze raw full-session evidence, update security results, reconnect SSE using `Last-Event-ID`, verify state reconstruction, reveal Mystery ground truth, then disconnect.
- [ ] Require VM `TERMINATED`, ephemeral address released, and exact removal of namespaces, veth, routes, NAT rule, strongSwan, tcpdump, locks, and temporary runtime state.
- [ ] Record raw/normalized capture hashes, packet/byte counts, absence of IKE/UDP/control/rekey data in `encrypted.pcap`, ML result, rekey/PFS evidence, analysis result, event replay, runtime, cost, and cleanup.
- [ ] If the E2E fails, diagnose the failing layer and use only syntax/import checks or the narrowest relevant test method. Repeat the full cloud E2E only when necessary to prove the corrected real boundary.

### Stage 5: One GitNexus review and targeted fixes

**Produces:** One whole-branch impact/security review with accepted findings fixed.

- [ ] Run GitNexus once against the completed branch, focusing on `SecureSession` compatibility, resource ownership, command injection, NAT/firewall safety, credential leakage, Mystery leakage, NAT-T ML contamination, cleanup, and frontend event compatibility.
- [ ] Evaluate each finding against real code and evidence; fix accepted findings only.
- [ ] Validate fixes with compile/import checks or the smallest relevant test method. Do not run GitNexus or any complete suite again unless the review output itself was unusable.

### Stage 6: Single final regression gate and handoff

**Produces:** Final verified commit, evidence report, and clean stopped environment.

- [ ] Run the complete Python test discovery exactly once and record pass/fail/skip counts.
- [ ] In the same final gate, run the documented privileged Phase 1 baseline, Phase 2 integrations, Phase A Live Lab, and GCP boundary/E2E checks exactly once where not already covered by discovery.
- [ ] Run frontend unit/build/accessibility checks and Playwright once for Offline PCAP, Guided Demo, local Live Lab, SSE replay, failure cleanup, and the provider-neutral cloud result flow.
- [ ] If the final gate exposes a regression, fix it with a targeted check; rerun only the failed final command needed to establish a green gate, not every earlier suite.
- [ ] Verify all four VMs are `TERMINATED`, TCP/22 is absent, no unexpected billable resource exists, no local session resource remains, no secret/runtime config is tracked, and the worktree is clean apart from intended evidence/code.
- [ ] Commit final fixes/evidence with `rtk git commit -m "feat: complete GCP Live Lab prototype"`.
- [ ] Report branch/commit, resources, real E2E evidence, capture normalization proof, ML result, rekey/PFS/security evidence, SSE/Mystery behavior, cleanup, test results, cost, limitations, and worktree status. Do not merge or push. STOP.
