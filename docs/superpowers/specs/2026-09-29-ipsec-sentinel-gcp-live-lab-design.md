# IPsec Sentinel GCP Live Lab Design Specification

**Date:** 2026-09-29  
**Status:** Proposed for review  
**Target branch:** `feat/ipsec-sentinel-gcp-live-lab`  
**Stacked base:** `feat/ipsec-sentinel-live-lab` at `0083fc80d46947952c946dc143d527d46c5bd162`  
**Google Cloud project:** `ipsec-sentinel` (`429285250074`)

## 1. Purpose

Phase B connects the validated Live Lab product to four controlled Google Cloud
strongSwan responders without changing its frontend, REST, SSE, analysis, or
security-provenance contracts. A user selects a known or Mystery VPN, the local
Sentinel Agent starts the corresponding stopped VM, creates only an isolated
client sandbox, establishes a genuine IKEv2/IPsec tunnel over NAT-T, runs the
existing interactive workloads through that tunnel, verifies rekey/PFS and
XFRM evidence, analyzes the session, and stops the VM after disconnect.

The cloud integration is an adapter around the existing Live Lab. It must not
introduce a second product lifecycle, route the host through the VPN, expose
the privileged local agent, or allow arbitrary cloud projects, instances,
endpoints, commands, paths, or traffic targets.

## 2. Approved infrastructure shape

The deployment is intentionally fixed and small:

- project `ipsec-sentinel`;
- region `asia-south1`, zone `asia-south1-a`;
- custom VPC `ipsec-sentinel-lab`;
- subnet `ipsec-sentinel-lab-asia-south1`, CIDR `10.70.0.0/24`;
- four pre-created Debian 12 `e2-micro` VMs with 10 GB `pd-balanced` boot
  disks and ephemeral public IPv4 addresses;
- VM names `vpn-secure`, `vpn-aes128`, `vpn-cbc`, and `vpn-no-pfs`;
- one permanent source-restricted firewall rule for UDP/500 and UDP/4500;
- one source-restricted TCP/22 rule used only during automated initial
  provisioning and deleted before demo operation;
- no load balancer, Cloud NAT, static address, managed instance group,
  database, Kubernetes cluster, GPU, or VM service account.

Only one scenario VM may run for a Live Lab session. All four VMs remain
stopped outside an active session or explicit cloud verification.

The primary transport is IKE over UDP/500 followed by NAT-T on UDP/4500.
Native ESP protocol 50 is not required. Adding an ESP firewall rule or
changing the topology requires a separately reviewed change based on observed
cloud evidence.

## 3. Non-negotiable inherited invariants

Phase B preserves the Phase A specification and these behaviors:

1. The Sentinel Agent binds only to `127.0.0.1` and accepts one active session.
2. REST accepts actions; persisted, ordered SSE drives product state.
3. No frontend timer or optimistic state may fabricate cloud, IKE, tunnel,
   workload, ESP, rekey, analysis, or cleanup progress.
4. `SecureSession` remains the lifecycle owner. Cloud support introduces
   injected topology/IPsec/remote-workload adapters rather than a parallel
   orchestration implementation.
5. Capture begins before IKE and remains continuous until analysis seals it or
   disconnect/failure stops it.
6. Full-session evidence and latest-workload ML input remain independent.
7. Mystery scenario identity, VM name, configured proposal, PFS intent, and
   provider-private data remain server-side until explicit reveal.
8. Cleanup remains idempotent, exact-resource scoped, and preserves the
   primary failure separately from cleanup outcome.
9. Offline PCAP and Guided Demo behavior remain unchanged.
10. Only the four validated IPsec scenarios and seven controlled supervised
    workloads are accepted.

## 4. Cloud configuration and command safety

Cloud configuration is loaded from a strict local file outside the repository,
owned by the invoking user/root and mode `0600`. It contains only:

- exact project, project number, region, and zone;
- exact scenario-to-instance allowlist;
- deployment identifier and protected endpoint address;
- local paths to root-readable IKE and control credentials;
- bounded startup, health, and stop timeouts.

Unknown fields, project mismatches, instance names outside the fixed allowlist,
non-Mumbai zones, non-HTTPS/non-protected control endpoints, or permissive file
permissions fail before a cloud command runs.

The implementation shells out to the authenticated WSL `gcloud` CLI through a
small injected command client. The root Sentinel Agent launches each fixed
cloud command as the configured non-root operator account, using that account's
existing Google Cloud CLI configuration; it neither copies credentials into
root's home nor reads token files itself. The configured operator UID, home,
and Cloud SDK directory must agree with the local account database and secure
ownership checks. Windows-only CLI authentication is not implicitly imported
into WSL.

This adds no Google SDK dependency. Every command is constructed from fixed
verbs and validated values; no shell string, user supplied extra argument,
arbitrary filter, or arbitrary resource name is accepted. JSON output is
requested and parsed strictly.

Read-only preflight verifies:

- active account and project match the configured project;
- project number is `429285250074`;
- Compute Engine API is enabled;
- the four instances exist in the configured zone;
- labels, tags, machine types, disks, service-account absence, and stopped or
  expected running state match the deployment manifest;
- the permanent firewall rule has only the approved source CIDR and UDP ports.

Read-only preflight never repairs drift automatically. Drift produces a stable
diagnostic and blocks the session.

## 5. Provider implementation

`GcpLabProvider` implements the existing `LabProvider` contract:

```python
start_scenario(scenario_id) -> ProviderEndpoint
wait_until_ready() -> ProviderEndpoint
endpoint() -> ProviderEndpoint
health() -> dict[str, object]
stop_scenario() -> None
```

It owns only cloud instance lifecycle and remote endpoint readiness. It does
not own local namespaces, strongSwan, capture, traffic generation, rekey, or
analysis.

`start_scenario()`:

1. resolves the allowlisted instance server-side;
2. verifies deployment drift and acquires the existing one-session lock;
3. starts only that instance if it is stopped;
4. records cloud ownership before waiting;
5. emits no ready event until Compute Engine reports `RUNNING`.

`wait_until_ready()` additionally requires a scenario-neutral serial-console
boot marker and a successful bounded IKE endpoint probe. It returns a public
endpoint projection containing only provider, neutral display name, public
address, and `natt`; the instance and scenario mapping remain private.

`health()` combines current Compute state, endpoint identity, and the protected
remote agent health after the tunnel is active. Cached success cannot outlive
the configured polling interval.

`stop_scenario()` is idempotent. It stops only the recorded allowlisted
instance, waits for `TERMINATED`, confirms the ephemeral address is released,
and retains provider logs. It never deletes a VM, disk, firewall, subnet, or
network during an ordinary session.

If the VM was already running before the provider acquired it, the provider
does not claim ownership or stop it automatically; the session fails closed
with an operator-facing ownership diagnostic.

## 6. Cloud responder image and startup

Each VM is provisioned once, validated, and stopped. On boot it uses a
scenario-specific root-owned configuration installed during provisioning; it
does not download mutable application code during a judge session.

The responder contains:

- strongSwan and required kernel/XFRM tooling;
- the exact allowlisted scenario configuration;
- a protected server namespace at `10.20.0.2/24` behind a gateway address
  `10.20.0.1/24`;
- IPv4 forwarding enabled and reverse-path filtering disabled on the required
  interfaces;
- an allowlisted remote workload service bound only to `10.20.0.2`;
- an allowlisted evidence service reachable only through the protected subnet;
- systemd units with bounded restart behavior and journald logs;
- a boot health script that verifies strongSwan, namespaces, routes, XFRM
  capability, forwarding, rp_filter, workload service, and scenario manifest
  before printing the scenario-neutral readiness marker.

The VPC-facing VM interface is the strongSwan gateway. Compute Engine
`canIpForward` and guest `net.ipv4.ip_forward=1` are both enabled. The remote
server namespace has an explicit route back to `10.10.0.0/24` through the VM
gateway.

Provisioning installs credentials through the temporary source-restricted
setup channel. Private keys, PSKs, control tokens, and local credential
material are never committed, placed in startup metadata, returned by the
frontend, or written to user-visible events. The TCP/22 rule is deleted after
provisioning and verified absent before cloud smoke testing.

## 7. Isolated local cloud-client topology

The cloud session creates only local controlled namespaces and interfaces; it
never changes the host's default route.

```text
ips-client (10.10.0.2/24)
        |
ips-gwa lan0 (10.10.0.1/24)
ips-gwa wan0 (172.31.254.2/30)
        |
host veth (172.31.254.1/30)
        |
WSL host egress, scoped MASQUERADE
        |
UDP/500 -> UDP/4500
        |
GCP strongSwan gateway
        |
remote server namespace (10.20.0.2/24)
```

The local topology adapter owns exact namespace, veth, route, sysctl, nftables
or iptables rule, and process identities. The NAT rule matches only the cloud
gateway namespace source CIDR and the selected host egress interface. Cleanup
deletes the exact rule by recorded handle/specification; it never flushes a
host table or chain.

Setup verifies the protected route, host-side transit route, forwarding,
rp_filter, NAT rule, and absence of conflicting resources before returning.
Startup recovery journals these resources before mutation and removes only
matching stale ownership.

## 8. Reusable secure-session backends

`SecureSession` gains narrow injected interfaces for topology, IPsec endpoint,
capture layout, peer addresses, and evidence collection. Existing constructors
and `run_secure_baseline()` retain their current defaults and behavior.

The local backend continues using `Topology` and `StrongSwanPair`. The cloud
backend uses the isolated client topology and a single local strongSwan client,
while the protected remote service returns allowlisted responder evidence.

Shared `SecureSession` methods continue to own:

- preflight and reset;
- topology setup/verification;
- daemon start/stop;
- capture start/snapshot/stop;
- configuration load and initiation;
- SA waiting and refresh;
- local and remote XFRM collection;
- rekey evidence and PFS evaluation;
- evidence assembly, diagnostics, and cleanup ordering.

Cloud-specific adapters may translate evidence into the existing gateway-a /
gateway-b keyed structures, but may not weaken `evaluate_tunnel()` or
`evaluate_pfs()`. Every configured-versus-observed value retains its original
provenance.

## 9. Protected remote workload control

The remote workload service is reachable only at `10.20.0.2` after IPsec is
active. It accepts a fixed versioned JSON protocol over HTTPS, authenticates a
high-entropy deployment token, validates a session nonce, and exposes only:

- health and version;
- prepare an allowlisted workload from a validated seeded plan;
- query receipt/validation evidence;
- stop/cleanup the active workload;
- collect allowlisted strongSwan/XFRM/log evidence.

It exposes no shell, path, package, upload, or arbitrary process interface.
Only one workload may be prepared at a time. Request bodies have strict size
limits, schemas, and timeouts.

Existing traffic generators retain responsibility for seeded planning,
client-side execution, validation semantics, metadata, and cleanup. A remote
server runtime adapter performs only the server half that the same generator
would otherwise start in `ips-server`. Same seed, scenario, and generator
version produce the same planned parameters in local and cloud modes.

Remote control requests occur before the workload start timestamp or after the
workload end timestamp. They are therefore excluded from the derived ML
window. Validation checks explicitly reject workload captures containing the
control channel's packet pattern or timestamps.

## 10. NAT-T capture and ML normalization

The authoritative cloud `full-evidence.pcap` is captured on the local
host/gateway transit veth before IKE begins. It retains real wire packets:

- UDP/500 establishment;
- UDP/4500 NAT-T negotiation and keepalives;
- ESP-in-UDP workload traffic;
- rekey chronology;
- no unrelated host traffic because the capture interface is session-owned.

The analyzer records transport as NAT-T and parses the minimum required
non-ESP-marker IKE and ESP-in-UDP structure without claiming decryption.

The latest successful workload window is first sliced by recorded timestamps.
A deterministic normalizer then converts only valid UDP/4500 ESP-in-UDP data
packets between the expected peers into a synthetic native-ESP PCAP for the
existing feature extractor. It removes the UDP header, preserves direction,
timestamp, ESP SPI/sequence/payload bytes, reconstructs the outer IPv4 length
and checksum, and records source/destination artifact hashes and normalizer
version.

The normalizer rejects:

- UDP/500;
- UDP/4500 IKE packets with the non-ESP marker;
- NAT-T keepalives;
- malformed or truncated ESP-in-UDP;
- unexpected peers, protocols, fragments, or timestamps;
- empty output.

The resulting `encrypted.pcap` must pass the existing strict native-ESP parser:
ESP only, expected peers only, no UDP/500, no UDP/4500, and no plaintext. The
existing model and feature schema remain unchanged. The UI and analysis
contract disclose that cloud inference used a `NATT_NORMALIZED_WORKLOAD_WINDOW`
artifact; it is never represented as the raw wire capture.

Protocol/security analysis always uses the raw full-evidence capture plus
local and remote active evidence. Traffic inference and X-Ray use only the
latest normalized workload capture.

## 11. Connect, traffic, rekey, and analysis flow

The existing state machine is unchanged. Provider-neutral reasons replace
hard-coded references to a local endpoint.

Connect proceeds:

1. local/cloud preflight and drift validation;
2. start selected VM and wait for real readiness;
3. create isolated local client topology;
4. start raw transit capture;
5. start/load local strongSwan client;
6. initiate IKE and stream parsed local log observations;
7. verify local SA/XFRM;
8. query protected remote SA/XFRM evidence after the tunnel is reachable;
9. evaluate both sides and observe ESP-in-UDP before `TUNNEL_ACTIVE`.

Traffic retains `prepare -> run -> validate -> cleanup`, with protected remote
prepare/receipt calls outside the captured workload timestamps. At minimum,
the cloud smoke proves ICMP and Video. Unit/service coverage proves all seven
allowlisted generator plans and remote server handlers.

Rekey invokes a genuine local CHILD_SA rekey and collects before/after local
and remote SA/XFRM/log evidence. PFS-enabled and no-PFS semantics continue to
use the existing evaluator. NAT-T packet chronology alone is never promoted to
PFS proof.

Analysis seals the raw capture, derives and validates the latest workload
artifact, runs the existing analyzer/model/security rules, persists the result,
and leaves the tunnel coherent until disconnect.

## 12. Mystery mode

Mystery selection remains entirely inside the Sentinel Agent. Provider-private
state contains the selected instance, scenario, configured policy, and cloud
ground truth. Before reveal, public snapshots and events use a neutral endpoint
display and may expose only values independently observed by Sentinel.

Cloud instance name, labels, serial readiness text, provider errors, artifact
paths, and remote service responses are passed through the same centralized
redaction boundary. Reveal after `READY` compares observed/derived/AI-inferred
results with the protected deployment manifest.

## 13. Failure handling and cleanup

Cloud failure cleanup attempts every owned layer even if an earlier step fails:

1. stop/cleanup active remote workload when reachable;
2. stop captures and preserve partial PCAP/log evidence;
3. terminate the local strongSwan client;
4. remove local XFRM state/policy, namespaces, veths, routes, and exact NAT rule;
5. stop only the provider-owned VM and wait for `TERMINATED`;
6. release session/cloud ownership and local runtime locks.

If cloud stop fails, the primary session failure remains unchanged, cleanup is
`FAILED`, ownership remains journaled, and the UI provides the exact safe
operator stop command. Agent startup retries cleanup only after verifying the
recorded project, zone, instance allowlist, and current ownership marker.

The provider never deletes infrastructure automatically. A process shutdown
hook and explicit disconnect both call the same idempotent cleanup path.

## 14. Deployment and approval gate

Infrastructure commands are represented in a checked-in deployment manifest
and a dry-run command renderer. The renderer produces the exact `gcloud`
network, subnet, firewall, and instance commands without executing them.
Tests compare the rendered command set with the approved resource allowlist.

Before the first mutating command, the agent must report:

- active account, project ID/number, region, and zone;
- detected operator public `/32`;
- every exact creation command in execution order;
- estimated monthly stopped/running cost;
- rollback commands;
- confirmation that no resource currently exists under the selected names.

Execution then stops for explicit user approval. Approval of this specification
or implementation does not approve resource creation. Any changed command,
CIDR, machine type, disk, firewall rule, tag, image, or instance count requires
a new command preview and approval.

Provisioning runs serially and records created resources after each successful
command. A failure rolls back only resources created by that attempt, in reverse
order, after showing the rollback actions. Destructive rollback or final
deletion still requires explicit approval; stopping a newly started VM is
allowed as ordinary failure cleanup.

## 15. Cost controls

- Infrastructure is pre-created once and stopped outside active use.
- The provider starts one VM only and always attempts stop on disconnect,
  failure, agent shutdown, and test completion.
- Ephemeral public addresses are used so stopped instances retain no public-IP
  charge.
- No background soak test, bulk workload matrix, autoscaler, or repeated cloud
  session is run during implementation.
- The single final cloud verification uses one scenario, ICMP, Video, one
  rekey, one analysis, and disconnect unless a failed layer requires a targeted
  retry.
- A cloud-side systemd self-shutdown timer bounds VM runtime even if the local
  agent or machine disappears; the local provider also enforces its own
  shorter maximum-running-duration stop attempt.

## 16. Observability and evidence

All local events, provider commands with secrets redacted, Compute state
transitions, serial readiness observations, local/remote strongSwan logs,
SA/XFRM snapshots, workload receipts, capture hashes, normalization receipts,
analysis results, cleanup steps, and VM stop confirmation are retained beneath
the session ID.

The UI receives curated evidence-backed events, not raw cloud logs. Provider
errors use stable public codes while full diagnostics remain local. Secret
values are redacted before log persistence.

The final cloud evidence report records actual resource identifiers, runtime,
cost estimate, packet counts, NAT-T parsing, normalized ESP-only proof, ML
result, rekey/PFS result, security analysis, SSE replay, Mystery redaction, and
complete local/cloud cleanup.

## 17. Testing and credit-efficient execution

Implementation uses TDD and this order:

1. strict cloud configuration, command construction, JSON parsing, and drift
   checks with fake command results;
2. provider ownership, start/readiness/health/stop, failure, and idempotency;
3. isolated client topology and exact NAT cleanup using command-plan tests;
4. single-client strongSwan and remote-evidence adapters;
5. remote workload protocol and generator runtime adaptation;
6. NAT-T parsing, deterministic normalization, provenance, and strict rejection;
7. orchestrator/provider-neutral events, Mystery redaction, recovery, and UI
   compatibility;
8. deployment dry-run and rollback-plan tests;
9. targeted local privileged smoke for the new topology/normalizer only;
10. exact resource-command preview and explicit approval gate;
11. resource deployment and one minimal readiness check per created VM;
12. one end-to-end cloud session: connect, ICMP, Video, ML, rekey/PFS,
    analysis, SSE replay, Mystery-safe output, disconnect, VM stop, cleanup;
13. one GitNexus analysis/review near the end;
14. one final complete backend/frontend/privileged/Playwright regression gate.

During development, only focused tests for the changed boundary run. The full
regression suite runs once, after the cloud end-to-end proof and final review.
No bulk captures or repeated cloud matrix are generated.

## 18. Acceptance criteria

Phase B is complete only when:

- all infrastructure matches the approved fixed manifest;
- no creation command ran before its exact preview was approved;
- the provider starts/stops only an allowlisted VM and detects drift;
- the local sandbox reaches GCP without changing the host default route;
- real IKEv2 establishes over UDP/500 and NAT-T uses UDP/4500;
- local and remote SA/XFRM evidence independently validate the CHILD SA;
- ICMP and Video traverse the cloud tunnel;
- live SSE events reflect real cloud, IKE, ESP-in-UDP, workload, and rekey
  evidence;
- the raw full capture retains IKE/NAT-T/rekey evidence;
- the latest workload ML capture is deterministically normalized ESP only and
  excludes IKE, keepalives, rekey, control traffic, and plaintext;
- the existing model produces an inference from that workload artifact;
- a genuine CHILD-SA rekey updates SPI and PFS evidence correctly;
- analyzer/security results retain configured-versus-observed provenance;
- Mystery ground truth does not leak before reveal;
- disconnect stops the VM and removes all local session resources;
- failure cleanup is idempotent and preserves diagnostics;
- Phase 1, Phase 2, Phase A Live Lab, analyzer, frontend, and browser
  regressions pass at the final gate;
- actual cloud resource and stopped-state costs are documented;
- no feature extraction, model retraining, arbitrary scanning, extra protocol,
  autoscaling, or additional IPsec scenario work is introduced.

## 19. Out of scope

- Cloud HA, autoscaling, multi-region failover, load balancing, or production
  multi-tenancy;
- arbitrary user projects, endpoints, instance names, or VPN servers;
- permanent SSH exposure or manual SSH steps during a demo;
- static public IPs, Cloud VPN gateways, Kubernetes, Cloud SQL, or Secret
  Manager;
- new ML training, dataset generation, feature schemas, or model calibration;
- native-ESP cloud fallback unless NAT-T fails for a demonstrated reason and a
  new design is approved;
- automatic infrastructure deletion.
