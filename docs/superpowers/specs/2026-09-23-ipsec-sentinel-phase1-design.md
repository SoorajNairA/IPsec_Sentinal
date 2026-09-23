# IPsec Sentinel Phase 1 Design

## Purpose

IPsec Sentinel Phase 1 builds a Linux-first testbed that creates one genuine IKEv2 site-to-site IPsec tunnel, sends ICMP traffic through it, captures the resulting IKE and native ESP packets, and records independently verified evidence. It establishes a trustworthy base for later dataset-generation work without implementing AI, ML, frontend, reporting, vulnerability exploitation, cloud deployment, or a scenario matrix.

Correctness is defined by observed networking behavior, not generated configuration files. Automation must not begin until one secure baseline has been proven manually or semi-automatically.

## Environment and Preconditions

The initial implementation targets the existing Ubuntu 26.04 LTS WSL2 distribution on kernel `6.18.33.2-microsoft-standard-WSL2`. Commands that create namespaces, configure XFRM, or launch network daemons run as root inside WSL2.

The preflight probe established that:

- privileged `ip xfrm state` and `ip xfrm policy` queries succeed;
- `/proc/net/xfrm_stat` exposes the kernel XFRM subsystem; and
- `/proc/crypto` provides `rfc4106(gcm(aes))` through AES-NI drivers.

The implementation must stop and report a preflight failure if these capabilities are absent on a future host. It must not silently switch to Docker or another topology.

The required userspace dependencies are strongSwan with `swanctl`/VICI support, `iproute2`, `tcpdump`, a PCAP inspection tool such as `tshark`, and Python 3. Exact strongSwan binary paths, version, loaded plugins, and proposal support must be inspected after installation rather than assumed.

## Delivery Order

Work proceeds through strict gates:

1. Verify host and kernel prerequisites.
2. Install and inspect the minimal Linux dependencies.
3. Construct one four-namespace topology.
4. Establish one IKEv2/CHILD_SA pair.
5. Prove client-to-server ICMP succeeds through the tunnel.
6. Independently prove strongSwan SA state, XFRM state/policy, and genuine IKE/ESP capture evidence.
7. Only then implement the secure-baseline automation.
8. Only then add the minimal scenario representation, structured artifacts, focused tests, and accurate documentation.

A failure at any gate stops progress at that layer. Configuration generation or daemon startup alone is never evidence that the tunnel works.

## Topology

The testbed uses four Linux network namespaces and three veth pairs:

```text
client                 gateway-a             gateway-b                 server
10.10.0.2/24 -- veth -- 10.10.0.1/24     10.20.0.1/24 -- veth -- 10.20.0.2/24
                         192.0.2.1/30 ===== 192.0.2.2/30
                               IKEv2 + native ESP
```

The protected networks are `10.10.0.0/24` and `10.20.0.0/24`. The gateway transit network is `192.0.2.0/30`.

The client has an explicit route for `10.20.0.0/24` via `10.10.0.1`. The server has an explicit route for `10.10.0.0/24` via `10.20.0.1`. Both gateways have IPv4 forwarding enabled. Reverse-path filtering is disabled and read back for `all`, `default`, and each relevant gateway interface so it cannot silently discard forwarded IPsec traffic.

The topology has no NAT rules. MOBIKE is disabled and UDP encapsulation is not forced, keeping IKE on UDP/500 and data traffic as native IP protocol 50 ESP. Packet capture runs on the transit veth before IKE initiation so a single PCAP includes both negotiation and encrypted traffic.

## strongSwan Isolation and Configuration

Each gateway runs its own strongSwan daemon inside its gateway network namespace. Because network namespaces do not isolate filesystem paths or Unix sockets, each daemon receives separate:

- strongSwan configuration;
- swanctl configuration and credentials;
- runtime directory;
- PID file;
- VICI Unix socket; and
- log file.

The global strongSwan system service is not used for the lab. Daemons are launched directly in their namespaces with per-process configuration, and each `swanctl` command targets the corresponding VICI socket explicitly.

The baseline uses IKEv2 tunnel mode, PSK authentication, IPv4 selectors for the two protected subnets, AES-256-GCM, a modern DH group supported by the installed strongSwan build, and a CHILD_SA proposal containing a DH group for PFS policy. The exact proposal strings are selected only after inspecting the installed version and plugins. Both gateways use explicit proposals rather than broad defaults.

## Manual Proof Sequence

The first tunnel is established with direct, observable commands before a general runner exists:

1. Reset only known lab-owned resources from an earlier attempt.
2. Create namespaces, veth pairs, addresses, links, routes, forwarding settings, and reverse-path-filter settings.
3. Read back routes, forwarding values, reverse-path-filter values, and the absence of lab NAT rules.
4. Write the two minimal strongSwan configurations with isolated paths.
5. Start both daemons and confirm both VICI sockets respond.
6. Load the two configurations and credentials.
7. Start tcpdump on the `192.0.2.x` transit veth with UDP/500 and protocol-50 ESP visible.
8. Initiate the connection from gateway A.
9. Confirm IKE_SA and CHILD_SA state through both gateways' `swanctl --list-sas` output.
10. Confirm matching XFRM states and policies inside both gateway namespaces.
11. Send ICMP from `10.10.0.2` to `10.20.0.2` and require successful replies.
12. Stop capture cleanly and validate that the PCAP contains peer-matched UDP/500 IKE packets and native ESP packets within the run window.
13. Preserve the commands, logs, SA output, XFRM snapshots, ICMP result, and PCAP as milestone evidence.

If ESP is missing, investigation remains focused on policy selection, routes, forwarding, reverse-path filtering, and capture placement. Automation does not begin until all checks pass together.

## Automation Boundary

After the manual proof, `python3 run_scenario.py secure-baseline` becomes the supported Linux entry point. It performs dependency validation, stale-resource cleanup, topology setup, strongSwan startup, capture-before-initiation, SA initiation, bounded waits, ICMP generation, independent evidence collection, PCAP validation, artifact writing, status calculation, and safe cleanup.

The first automation supports only the secure baseline. It does not introduce a generalized protocol matrix or unused configuration fields. Internal responsibilities remain separated only where needed for topology lifecycle, strongSwan control, capture/evidence parsing, and artifact serialization.

Every external command has a timeout and belongs to a named stage. A failed stage records its command, exit code, output, and error; returns a nonzero process exit; never emits a misleading `PASS`; and triggers cleanup of lab-owned namespaces, daemon processes, capture processes, veths, and runtime paths. Evidence already copied into a completed run directory is retained.

## Evidence and Status Rules

Evidence is independent and conjunctive. A successful run requires all of the following:

- client-to-server ICMP replies;
- an established IKE_SA reported by both strongSwan instances;
- an installed CHILD_SA reported by both strongSwan instances;
- matching XFRM state in both gateway namespaces;
- matching inbound, outbound, and forwarding XFRM policies;
- a nonempty PCAP containing UDP/500 traffic between `192.0.2.1` and `192.0.2.2` in the run window; and
- native protocol-50 ESP packets between the same peers after CHILD_SA establishment.

An empty capture, an IKE-only capture, an ESP-only capture, a selector mismatch, or successful ping without the required independent SA/XFRM evidence makes the run fail.

## PFS Semantics

PFS configuration and behavioral verification are different facts.

For the initial CHILD_SA:

- `configured.pfs` is `true` because the CHILD proposal contains an explicit DH group;
- `observed.pfs.status` is `NOT_TESTED`; and
- no claim is made that PFS was behaviorally proven.

The initial CHILD_SA created during IKE_AUTH does not independently prove a fresh CHILD_SA DH exchange. After the core secure-baseline automation is reliable, a focused CHILD_SA rekey check will force or await rekey, collect fresh negotiation evidence, and set `observed.pfs.status` to `VERIFIED` only when the rekey demonstrates the configured DH exchange. Failed or absent rekey evidence leaves the status unverified and cannot be represented as success.

## Run Artifacts and Ground Truth

Each automated execution creates an immutable run directory:

```text
runs/run_<timestamp_or_id>/
  encrypted.pcap
  ground_truth.json
  verification.json
  run.log
  scenario.yaml
  strongswan-gateway-a.log
  strongswan-gateway-b.log
  swanctl-gateway-a.txt
  swanctl-gateway-b.txt
  xfrm-gateway-a.txt
  xfrm-gateway-b.txt
```

`ground_truth.json` separates requested policy from observed behavior. Its configured section contains the exact proposal strings, IKE version, mode, protected networks, peer addresses, PFS policy, and IP version. Its observed section contains parsed IKE and CHILD algorithms, traffic selectors, SA state, peer identities, and PFS verification status. Capture counts, ICMP outcome, run timestamps, and overall status are separate fields.

`verification.json` records stage-level checks and the source evidence used for each verdict. Raw command outputs are retained in their dedicated files and log. Packet counts are derived from the saved PCAP, not from tcpdump's console summary alone.

The run status is `PASS` only when every required baseline check succeeds. PFS rekey verification is recorded independently until the rekey check becomes an explicit required stage.

## Testing Strategy

Tests are added only after the real tunnel is proven. Focused unit tests cover scenario parsing, configured-versus-observed serialization, strongSwan and XFRM output parsing, PCAP summary validation, run-directory creation, invalid configuration, timeout handling, and failure status calculation.

Privileged networking tests are marked as integration tests and run only inside a compatible Linux environment as root. The complete secure baseline is executed repeatedly from a clean state to validate resource cleanup and deterministic behavior. A test run must include fresh evidence; prior PCAPs, sockets, PID files, or SA output cannot satisfy a later run.

## Documentation and Operating Constraints

The README will state the exact Ubuntu/WSL2 environment, package installation commands, privilege requirements, topology, launch command, expected evidence, PCAP inspection commands, artifact locations, cleanup behavior, troubleshooting steps, and known WSL2/kernel limitations.

Phase 1 stops after the secure baseline is automated, repeatably verified, tested, and documented. Phase 2 dataset generation and all AI/ML or UI work remain out of scope until explicitly requested.
