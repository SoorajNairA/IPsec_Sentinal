# IPsec Sentinel Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and repeatedly verify one genuine IKEv2 AES-256-GCM site-to-site tunnel, then automate it as `python3 run_scenario.py secure-baseline` with trustworthy PCAP and JSON evidence.

**Architecture:** Four Linux network namespaces form client, gateway A, gateway B, and server nodes. Two isolated `charon-systemd` processes negotiate across `192.0.2.0/30`; Linux XFRM protects traffic between `10.10.0.0/24` and `10.20.0.0/24`. Direct commands prove the tunnel before a small Python orchestration package is introduced.

**Tech Stack:** Ubuntu 26.04 WSL2, Linux network namespaces/veth/XFRM, strongSwan 6.0.4 `charon-systemd` and `swanctl`, tcpdump, Python 3.14 standard library, PyYAML, `unittest`.

**Spec:** `docs/superpowers/specs/2026-09-23-ipsec-sentinel-phase1-design.md`

## Global Constraints

- Run networking commands as root inside the existing Ubuntu WSL2 distribution.
- Stop if privileged XFRM queries, `/proc/net/xfrm_stat`, or RFC 4106 AES-GCM kernel support are absent.
- Do not start automation work until manual client-to-server ICMP, both `swanctl` views, both XFRM views, UDP/500 IKE, and native ESP have all been observed together.
- Use protected networks `10.10.0.0/24` and `10.20.0.0/24`; use transit network `192.0.2.0/30`.
- Do not add NAT, UDP encapsulation, MOBIKE, a generalized scenario matrix, AI/ML, UI, reporting, or Phase 2 dataset generation.
- Treat PFS as configured policy until a separate CHILD_SA rekey produces fresh-DH evidence.
- Capture starts before IKE initiation and must contain no UDP/4500 or cleartext protected ICMP on the transit veth.
- Every automated external command has a timeout; every failure returns nonzero, records its stage, and cannot produce `PASS`.

## Review Focus

- A stale namespace or daemon from an interrupted run must be removed without killing unrelated processes; Task 8 adds the repeated-run integration check.
- A PCAP containing IKE but no ESP, or ESP but no IKE, must fail; Task 6 tests both cases.
- Successful ping with missing/mismatched XFRM evidence must fail; Task 7 tests conjunctive verdict calculation.
- Initial CHILD_SA establishment must leave PFS `NOT_TESTED`; Task 4 tests serialization and Task 9 tests rekey promotion to `VERIFIED`.
- A route, forwarding, or `rp_filter` readback mismatch must stop before IKE initiation; Task 5 tests topology validation and Task 8 exercises it end to end.

## Planned File Structure

- `lab/manual/gateway-a/strongswan.conf` and `swanctl.conf`: minimal proven gateway A configuration.
- `lab/manual/gateway-b/strongswan.conf` and `swanctl.conf`: minimal proven gateway B configuration.
- `docs/evidence/secure-baseline-manual.md`: exact environment, commands, output summaries, counts, and hashes from the first proof.
- `run_scenario.py`: minimal CLI entry point.
- `scenarios/secure-baseline.yaml`: only fields required by the proven baseline.
- `ipsec_sentinel/command.py`: checked subprocess execution and timeout handling.
- `ipsec_sentinel/scenario.py`: strict baseline scenario loading.
- `ipsec_sentinel/models.py`: configured/observed/verification result types.
- `ipsec_sentinel/topology.py`: lab-owned namespace and route lifecycle.
- `ipsec_sentinel/strongswan.py`: isolated configuration rendering, daemon lifecycle, and SA collection.
- `ipsec_sentinel/capture.py`: tcpdump lifecycle and saved-PCAP validation.
- `ipsec_sentinel/evidence.py`: parsers and conjunctive verdict calculation.
- `ipsec_sentinel/artifacts.py`: atomic run-directory and JSON/log writing.
- `ipsec_sentinel/runner.py`: ordered secure-baseline stages and cleanup.
- `tests/`: focused standard-library unit tests plus an opt-in privileged integration test.
- `README.md`: exact operating and troubleshooting instructions.

---

### Task 1: Isolated Workspace and Linux Preflight

**Files:** None.

**Interfaces:**
- Consumes: committed design and implementation plan.
- Produces: isolated Git worktree and a verified Ubuntu userspace capable of running the manual proof.

- [ ] **Step 1: Enter an isolated worktree**

Use `superpowers:using-git-worktrees`. Create branch `feat/ipsec-sentinel-phase1` under an ignored `.worktrees/` directory, then verify `git status --short --branch`.

- [ ] **Step 2: Re-run the kernel gate**

Run inside Ubuntu as root:

```bash
ip xfrm state
ip xfrm policy
test -r /proc/net/xfrm_stat
grep -F 'rfc4106(gcm(aes))' /proc/crypto
ip netns list
```

Expected: both XFRM commands exit 0, the statistics file is readable, RFC 4106 is present, and namespace enumeration succeeds. Stop and report if any check fails.

- [ ] **Step 3: Install only required userspace packages**

```bash
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  charon-systemd strongswan-swanctl libstrongswan-standard-plugins \
  iproute2 iputils-ping iptables tcpdump python3 python3-yaml
```

- [ ] **Step 4: Inspect actual installed capabilities**

```bash
charon-systemd --version
swanctl --version
tcpdump --version
find /usr/lib/ipsec/plugins -maxdepth 1 -type f -printf '%f\n' | sort
```

Require the kernel-netlink, vici, openssl, nonce, random, socket-default, stroke-free swanctl loading path, and GCM functionality. The candidate baseline is `aes256gcm16-prfsha384-ecp384` for IKE and `aes256gcm16-ecp384` for ESP; if the installed daemon rejects either, inspect `swanctl --list-algs` from the running manual daemons and select the strongest supported AES-256-GCM/ECP proposal before editing the four manual configuration files.

### Task 2: Build and Validate the Manual Namespace Topology

**Files:** None.

**Interfaces:**
- Consumes: root shell with `iproute2`, ping, iptables, and tcpdump.
- Produces: four live namespaces with deterministic addressing, explicit routes, forwarding, and reverse-path-filter settings.

- [ ] **Step 1: Remove only known lab namespaces**

```bash
for ns in ips-client ips-gwa ips-gwb ips-server; do
  ip netns del "$ns" 2>/dev/null || true
done
```

- [ ] **Step 2: Create namespaces and veth pairs**

```bash
ip netns add ips-client
ip netns add ips-gwa
ip netns add ips-gwb
ip netns add ips-server
ip link add veth-c type veth peer name veth-a-lan
ip link add veth-a-wan type veth peer name veth-b-wan
ip link add veth-b-lan type veth peer name veth-s
ip link set veth-c netns ips-client
ip link set veth-a-lan netns ips-gwa
ip link set veth-a-wan netns ips-gwa
ip link set veth-b-wan netns ips-gwb
ip link set veth-b-lan netns ips-gwb
ip link set veth-s netns ips-server
```

- [ ] **Step 3: Name, address, and enable every link**

```bash
ip -n ips-client link set veth-c name eth0
ip -n ips-gwa link set veth-a-lan name lan0
ip -n ips-gwa link set veth-a-wan name wan0
ip -n ips-gwb link set veth-b-wan name wan0
ip -n ips-gwb link set veth-b-lan name lan0
ip -n ips-server link set veth-s name eth0
ip -n ips-client addr add 10.10.0.2/24 dev eth0
ip -n ips-gwa addr add 10.10.0.1/24 dev lan0
ip -n ips-gwa addr add 192.0.2.1/30 dev wan0
ip -n ips-gwb addr add 192.0.2.2/30 dev wan0
ip -n ips-gwb addr add 10.20.0.1/24 dev lan0
ip -n ips-server addr add 10.20.0.2/24 dev eth0
for ns in ips-client ips-gwa ips-gwb ips-server; do ip -n "$ns" link set lo up; done
ip -n ips-client link set eth0 up
ip -n ips-gwa link set lan0 up
ip -n ips-gwa link set wan0 up
ip -n ips-gwb link set wan0 up
ip -n ips-gwb link set lan0 up
ip -n ips-server link set eth0 up
```

- [ ] **Step 4: Add protected-network routes and gateway sysctls**

```bash
ip -n ips-client route add 10.20.0.0/24 via 10.10.0.1
ip -n ips-server route add 10.10.0.0/24 via 10.20.0.1
for ns in ips-gwa ips-gwb; do
  ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.default.rp_filter=0
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.lan0.rp_filter=0
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.wan0.rp_filter=0
done
```

- [ ] **Step 5: Read back state before any IKE work**

Run `ip -n <ns> -details addr`, `ip -n <ns> route`, and the five gateway sysctls. Require the two explicit client/server routes, `ip_forward = 1`, every checked `rp_filter = 0`, and empty `iptables -t nat -S` output apart from built-in chains. Ping only adjacent peers (`10.10.0.2↔10.10.0.1`, `192.0.2.1↔192.0.2.2`, and `10.20.0.1↔10.20.0.2`); do not send end-to-end traffic before XFRM policies exist.

### Task 3: Prove the Tunnel Manually

**Files:**
- Create: `lab/manual/gateway-a/strongswan.conf`
- Create: `lab/manual/gateway-a/swanctl.conf`
- Create: `lab/manual/gateway-b/strongswan.conf`
- Create: `lab/manual/gateway-b/swanctl.conf`
- Create after successful proof: `docs/evidence/secure-baseline-manual.md`

**Interfaces:**
- Consumes: Task 2 namespaces and installed strongSwan proposal/plugin evidence.
- Produces: established IKE/CHILD SAs, working protected ICMP, XFRM snapshots, logs, and a validated PCAP.

- [ ] **Step 1: Add isolated daemon configurations**

For gateway A, use the `charon-systemd` section with `load_modular = yes`, include `/etc/strongswan.d/charon/*.conf`, override `plugins.vici.socket` to `unix:///run/ipsec-sentinel/gateway-a/charon.vici`, set `pid_file` and file logging under the same gateway directory, and enable `ike`, `cfg`, `knl`, and `net` log levels sufficient to show selected proposals. Gateway B uses the identical structure under `/run/ipsec-sentinel/gateway-b/`.

The gateway A swanctl connection must contain these exact semantics:

```ini
connections {
  secure-baseline {
    version = 2
    local_addrs = 192.0.2.1
    remote_addrs = 192.0.2.2
    proposals = aes256gcm16-prfsha384-ecp384
    mobike = no
    local { auth = psk; id = gateway-a; }
    remote { auth = psk; id = gateway-b; }
    children {
      protected-nets {
        local_ts = 10.10.0.0/24
        remote_ts = 10.20.0.0/24
        mode = tunnel
        esp_proposals = aes256gcm16-ecp384
        start_action = none
      }
    }
  }
}
secrets {
  ike-baseline {
    id-a = gateway-a
    id-b = gateway-b
    secret = "0x5d2f1fb8d6f16c4c03b43242a236c980fed7f25af725e590eafed2e38178ed50"
  }
}
```

Gateway B reverses addresses, identities, and traffic selectors but uses the same exact proposals and secret.

- [ ] **Step 2: Start two isolated daemons and load configuration**

Create each `/run/ipsec-sentinel/gateway-*` directory with mode 0700. Launch `charon-systemd` through `ip netns exec` with the matching `STRONGSWAN_CONF`, record the actual process PID, and wait up to 10 seconds for its unique VICI socket. Then run:

```bash
swanctl --uri unix:///run/ipsec-sentinel/gateway-a/charon.vici --load-all --file lab/manual/gateway-a/swanctl.conf
swanctl --uri unix:///run/ipsec-sentinel/gateway-b/charon.vici --load-all --file lab/manual/gateway-b/swanctl.conf
```

Use the installed strongSwan 6.0.4 CLI help to confirm the configuration-file option before execution. If `--file` is not supported for `--load-all`, set `SWANCTL_DIR` to the gateway directory containing `swanctl.conf`; do not copy either configuration into the shared `/etc/swanctl` tree.

- [ ] **Step 3: Start capture before initiation**

```bash
ip netns exec ips-gwa tcpdump -U -n -i wan0 -w /tmp/ipsec-sentinel-secure-baseline.pcap \
  'udp port 500 or udp port 4500 or ip proto 50 or icmp'
```

Record tcpdump's PID and require the output file to appear before proceeding.

- [ ] **Step 4: Initiate and prove all live evidence**

Initiate `protected-nets` through gateway A's VICI socket. Save both `swanctl --list-sas --raw` outputs. Save `ip xfrm state` and `ip xfrm policy` from both gateway namespaces. Require established IKE and CHILD states, matching protected selectors, tunnel-mode ESP state, and policies in both directions.

Run `ip netns exec ips-client ping -I 10.10.0.2 -c 5 -W 2 10.20.0.2` and require five replies.

- [ ] **Step 5: Stop and validate the PCAP independently**

Stop tcpdump with SIGINT and wait for it to flush. Use tcpdump read filters against the saved file:

```bash
tcpdump -nn -r /tmp/ipsec-sentinel-secure-baseline.pcap 'udp port 500'
tcpdump -nn -r /tmp/ipsec-sentinel-secure-baseline.pcap 'ip proto 50'
tcpdump -nn -r /tmp/ipsec-sentinel-secure-baseline.pcap 'udp port 4500'
tcpdump -nn -r /tmp/ipsec-sentinel-secure-baseline.pcap 'icmp and (net 10.10.0.0/24 or net 10.20.0.0/24)'
```

Require nonzero UDP/500 and ESP counts, with `192.0.2.1` and `192.0.2.2` as peers. Require zero UDP/4500 and zero protected cleartext ICMP packets on `wan0`.

- [ ] **Step 6: Record and commit the proof**

Write `docs/evidence/secure-baseline-manual.md` with exact package versions, proposal strings, namespace/routes/sysctl readbacks, both SA summaries, both XFRM summaries, ping statistics, PCAP packet counts, PCAP SHA-256, and any WSL-specific behavior. State `configured.pfs = true` and `observed.pfs.status = NOT_TESTED`. Run `git diff --check`, then commit only the four configurations and evidence document; do not commit the PCAP or secrets beyond the lab-only deterministic PSK shown above.

### Task 4: Add Strict Scenario and Result Models

**Files:**
- Create: `.gitignore`
- Create: `scenarios/secure-baseline.yaml`
- Create: `ipsec_sentinel/__init__.py`
- Create: `ipsec_sentinel/scenario.py`
- Create: `ipsec_sentinel/models.py`
- Create: `tests/test_scenario.py`
- Create: `tests/test_models.py`

**Interfaces:**
- Produces: `Scenario.load(path) -> Scenario`, `GroundTruth.to_dict() -> dict[str, object]`, and `Verification.to_dict() -> dict[str, object]`.

- [ ] **Step 1: Write failing strict-scenario tests**

Test exact loading of `secure-baseline`, rejection of an unknown field, rejection of a non-IKEv2 mode, and rejection of altered protected/transit subnets. The valid fixture must require `aes256gcm16-prfsha384-ecp384`, `aes256gcm16-ecp384`, ICMP count 5, and capture enabled.

- [ ] **Step 2: Run tests and verify RED**

Run `python3 -m unittest tests.test_scenario -v`. Expected: import failure because `ipsec_sentinel.scenario` does not exist.

- [ ] **Step 3: Implement the minimal frozen dataclasses and loader**

Use `yaml.safe_load`, compare keys against explicit allowed-key sets, validate exact Phase 1 values, and raise `ScenarioError` containing the failing field. Do not accept any future matrix values yet.

- [ ] **Step 4: Add failing configured-versus-observed serialization tests**

Assert that configured proposals remain distinct from observed proposals and that a newly established baseline serializes PFS as:

```python
{"status": "NOT_TESTED", "rekey_observed": False, "evidence": []}
```

- [ ] **Step 5: Implement result dataclasses and verify GREEN**

Implement JSON-safe dataclasses with explicit `PASS`/`FAIL` status and stage records. Run both test modules and the complete suite. Add `runs/`, `.worktrees/`, `__pycache__/`, and `*.pyc` to `.gitignore`, then commit.

### Task 5: Add Checked Commands and Topology Lifecycle

**Files:**
- Create: `ipsec_sentinel/command.py`
- Create: `ipsec_sentinel/topology.py`
- Create: `tests/test_command.py`
- Create: `tests/test_topology.py`

**Interfaces:**
- Produces: `run_checked(argv: list[str], timeout: float, log: TextIO) -> CommandResult`.
- Produces: `Topology.setup()`, `Topology.verify() -> list[Check]`, `Topology.snapshot() -> dict`, and `Topology.reset()`.

- [ ] **Step 1: Test success, nonzero exit, and timeout behavior**

Use real Python child processes. Require captured stdout/stderr, named command context in `CommandFailure`, and child termination within the timeout bound.

- [ ] **Step 2: Implement and verify the command runner**

Use `subprocess.run(..., text=True, capture_output=True, timeout=timeout, check=False)` and convert `TimeoutExpired` or nonzero return codes into typed failures. Verify RED then GREEN.

- [ ] **Step 3: Test the exact topology command plan**

Test pure command-plan generation for all four namespaces, three veth pairs, six addresses, two explicit routes, forwarding, every `rp_filter` key, and lab-scoped cleanup. The production change that makes each test fail is a missing or altered command in `Topology`.

- [ ] **Step 4: Implement topology setup, readback verification, and cleanup**

Execute the proven Task 2 sequence. `verify()` must parse actual `ip route` and `sysctl -n` outputs and return a failed check for any mismatch. `reset()` enumerates exact namespace names and exact tracked PIDs only; it must never use wildcard process killing.

- [ ] **Step 5: Run the full unit suite and commit**

Run `python3 -m unittest discover -s tests -v`, then commit command and topology lifecycle code.

### Task 6: Add Capture Lifecycle and PCAP Validation

**Files:**
- Create: `ipsec_sentinel/capture.py`
- Create: `tests/fixtures/ike-only.pcap`
- Create: `tests/fixtures/esp-only.pcap`
- Create: `tests/fixtures/ike-esp.pcap`
- Create: `tests/test_capture.py`

**Interfaces:**
- Produces: `CaptureSession.start()`, `CaptureSession.stop()`, and `validate_pcap(path, peers, started_at, ended_at) -> CaptureEvidence`.

- [ ] **Step 1: Derive tiny fixtures from the successful manual PCAP**

Use tcpdump filters to create deterministic IKE-only, ESP-only, and combined fixtures containing only the minimum packets necessary. These are generated from genuine captured packets, not synthetic text.

- [ ] **Step 2: Write failing validation tests**

Require failure for empty, IKE-only, ESP-only, wrong-peer, UDP/4500-present, and out-of-window evidence. Require success only for peer-matched UDP/500 plus native ESP and no protected cleartext ICMP.

- [ ] **Step 3: Implement tcpdump lifecycle and parser**

Launch tcpdump via `subprocess.Popen` in `ips-gwa`, wait for its readiness line or PCAP header, stop with SIGINT, and always wait with a bounded timeout. Count packets by invoking `tcpdump -tt -nn -r <pcap> <filter>` and parsing timestamps/peer addresses; do not trust console summary counts.

- [ ] **Step 4: Verify RED/GREEN and commit**

Run `python3 -m unittest tests.test_capture -v` for each cycle, then the full suite and commit.

### Task 7: Add strongSwan Control, Evidence Parsing, and Verdicts

**Files:**
- Create: `ipsec_sentinel/strongswan.py`
- Create: `ipsec_sentinel/evidence.py`
- Create: `tests/fixtures/swanctl-gateway-a.txt`
- Create: `tests/fixtures/swanctl-gateway-b.txt`
- Create: `tests/fixtures/xfrm-gateway-a.txt`
- Create: `tests/fixtures/xfrm-gateway-b.txt`
- Create: `tests/test_strongswan.py`
- Create: `tests/test_evidence.py`

**Interfaces:**
- Produces: `StrongSwanPair.start(run_dir)`, `load()`, `initiate()`, `list_sas()`, `rekey()`, and `stop()`.
- Produces: `evaluate_baseline(sas, xfrm, ping, capture) -> Verification`.

- [ ] **Step 1: Write failing configuration-rendering tests**

Assert unique VICI/PID/log paths, reversed peer/selector values, exact approved proposals, `mobike = no`, no forced encapsulation, and no shared `/etc/swanctl` writes.

- [ ] **Step 2: Implement isolated daemon configuration and lifecycle**

Render the proven Task 3 files into a run-owned runtime directory, launch one `charon-systemd` process in each gateway namespace, track exact PIDs, wait for each VICI socket, load configurations, and use bounded `swanctl` commands. Stop only tracked processes.

- [ ] **Step 3: Write parser and conjunctive-verdict tests**

Use captured Task 3 outputs. Independently remove or alter the IKE state, CHILD state, selector, XFRM state, XFRM policy, ping success, IKE packet count, and ESP packet count; every mutation must make the verdict fail with the corresponding named check.

- [ ] **Step 4: Implement parsers and verdict calculation**

Parse only fields needed for the baseline: IKE/CHILD status, negotiated proposals, identities, selectors, SPIs, XFRM mode/protocol/peers/selectors, ping counts, and capture counts. Overall status is `PASS` only when `all(check.passed for check in required_checks)`.

- [ ] **Step 5: Run the full unit suite and commit**

Run `python3 -m unittest discover -s tests -v`, verify zero failures, and commit.

### Task 8: Add Artifacts, Ordered Runner, and CLI

**Files:**
- Create: `ipsec_sentinel/artifacts.py`
- Create: `ipsec_sentinel/runner.py`
- Create: `run_scenario.py`
- Create: `tests/test_artifacts.py`
- Create: `tests/test_runner.py`
- Create: `tests/test_secure_baseline_integration.py`

**Interfaces:**
- Produces: `create_run_dir(root, now) -> Path`, atomic JSON/text writes, and `run_secure_baseline(scenario, keep_lab=False) -> int`.
- CLI: `python3 run_scenario.py secure-baseline [--keep-lab]`.

- [ ] **Step 1: Write failing artifact tests**

Test collision-safe run IDs, required filenames, atomic JSON replacement, configured/observed separation, failure-stage retention, and rejection of writing `PASS` when any required check fails.

- [ ] **Step 2: Implement artifact writing and verify GREEN**

Create run directories with mode 0750 and temporary files with `Path.replace()` atomic publication. Write `scenario.yaml`, `run.log`, raw SA/XFRM outputs, `verification.json`, and `ground_truth.json`; move the completed PCAP into the run directory before validation.

- [ ] **Step 3: Write failing runner-order tests**

Assert this exact stage order: preflight, reset, scenario load, topology setup/readback, daemon start, capture start, configuration load, initiate, SA wait, XFRM collection, ICMP, capture stop, PCAP validation, verdict, artifacts, cleanup. Assert capture precedes initiate and cleanup occurs after every injected failure.

- [ ] **Step 4: Implement the runner and CLI**

Use `try/finally` for cleanup, a monotonic deadline per wait, SIGINT handling that records `INTERRUPTED`, and argparse restricted to `secure-baseline`. Require Linux root (`os.geteuid() == 0`) and print the run directory plus the first failed stage.

- [ ] **Step 5: Run the first automated integration test**

Mark the test with an environment guard such as `IPSEC_SENTINEL_INTEGRATION=1`. Run:

```bash
IPSEC_SENTINEL_INTEGRATION=1 python3 -m unittest tests.test_secure_baseline_integration -v
python3 run_scenario.py secure-baseline
```

Inspect every required artifact and independently rerun the saved-PCAP tcpdump filters. Then run the baseline twice more from a clean state to prove deterministic cleanup. Commit only after all three runs pass.

### Task 9: Add Behavioral PFS Rekey Verification

**Files:**
- Modify: `ipsec_sentinel/strongswan.py`
- Modify: `ipsec_sentinel/evidence.py`
- Modify: `ipsec_sentinel/runner.py`
- Modify: `tests/test_strongswan.py`
- Modify: `tests/test_evidence.py`
- Modify: `tests/test_secure_baseline_integration.py`

**Interfaces:**
- Extends: `StrongSwanPair.rekey()` and observed PFS evidence.

- [ ] **Step 1: Write failing rekey-evidence tests**

Require `NOT_TESTED` for initial establishment. Require `VERIFIED` only when an explicit CHILD rekey succeeds, CHILD SPIs change, and post-initiation logs select `ESP:AES_GCM_16_256/ECP_384` (normalized to installed strongSwan output). Once a rekey was attempted, missing DH selection or unchanged SPIs must produce `NOT_VERIFIED`, never `VERIFIED`.

- [ ] **Step 2: Implement explicit CHILD_SA rekey collection**

Snapshot initial SPIs and log offset, execute `swanctl --rekey --child protected-nets` against gateway A's VICI socket, wait for a new installed CHILD_SA, and collect only the new log segment plus before/after SA output.

- [ ] **Step 3: Verify RED/GREEN and run the privileged check**

Run focused unit tests, the full suite, and one fresh integration run. Confirm the saved ground truth contains `observed.pfs.status = VERIFIED` only for the rekey-proven run. Commit.

### Task 10: Documentation and Final Repeated Verification

**Files:**
- Create: `README.md`
- Modify: `docs/evidence/secure-baseline-manual.md`

**Interfaces:**
- Produces: exact operator instructions and final Phase 1 evidence summary.

- [ ] **Step 1: Write the technical README**

Include project scope, ASCII topology, Ubuntu 26.04/WSL2 requirements, exact package/setup commands, root requirement, exact secure-baseline command, successful output shape, PCAP inspection commands, artifact schema/location, cleanup behavior, troubleshooting, environment limitations, and the explicitly deferred Phase 2.

- [ ] **Step 2: Run fresh complete verification**

```bash
python3 -m unittest discover -s tests -v
IPSEC_SENTINEL_INTEGRATION=1 python3 -m unittest tests.test_secure_baseline_integration -v
python3 run_scenario.py secure-baseline
python3 run_scenario.py secure-baseline
```

For both direct runs, independently verify UDP/500 and ESP counts, zero UDP/4500, zero protected cleartext ICMP, successful ping, both SA views, both XFRM views, and ground-truth/verification agreement.

- [ ] **Step 3: Review requirements line by line**

Compare the design spec's delivery order, evidence rules, PFS semantics, artifacts, tests, and documentation requirements against the latest run directory. Record any limitation rather than weakening a check.

- [ ] **Step 4: Commit documentation and stop at Phase 1**

Run `git diff --check` and `git status --short`. Commit the README/evidence updates. Do not start dataset generation or any Phase 2 work.
