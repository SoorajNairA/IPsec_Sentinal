# IPsec Sentinel

IPsec Sentinel is a Linux-first IPsec testbed, evidence verifier, and reproducible encrypted-traffic dataset factory. It creates a genuine IKEv2 site-to-site tunnel with strongSwan, runs a known local workload through Linux XFRM, captures UDP/500 and native protocol-50 ESP, and writes configured-versus-observed evidence. Phase 2 adds dataset generation without changing the Phase 1 `run_secure_baseline()` behavior. It deliberately performs no feature extraction, dataset cleaning for ML, model training, UI work, NAT/NAT-T scenario, or generalized algorithm matrix.

## Topology

```text
ips-client             ips-gwa                   ips-gwb              ips-server
10.10.0.2/24 -- veth -- 10.10.0.1/24       10.20.0.1/24 -- veth -- 10.20.0.2/24
                         192.0.2.1/30 ===== 192.0.2.2/30
                             UDP/500 IKEv2 + native ESP

protected network: 10.10.0.0/24        protected network: 10.20.0.0/24
transit network:                    192.0.2.0/30
```

The client and server receive explicit routes to the opposite protected network. Both gateways enable IPv4 forwarding and disable `rp_filter` on `all`, `default`, `lan0`, and `wan0`. The lab installs no NAT rules, disables MOBIKE, and disables forced UDP encapsulation.

## Tested environment

- Windows host with WSL2
- Ubuntu 26.04 LTS
- `6.18.33.2-microsoft-standard-WSL2` kernel
- strongSwan 6.0.4
- Python 3.14 with PyYAML
- tcpdump 4.99.6 and iproute2 6.19
- Linux root privileges

The runner stops at preflight if privileged XFRM queries, `/proc/net/xfrm_stat`, or RFC 4106 AES-GCM kernel support are unavailable. It does not redesign the topology or fall back to Docker.

## Setup

Run these commands inside Ubuntu WSL2:

```bash
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  charon-systemd strongswan-swanctl libstrongswan-standard-plugins \
  iproute2 iputils-ping iptables tcpdump python3 python3-yaml

sudo ip xfrm state
sudo ip xfrm policy
test -r /proc/net/xfrm_stat
grep -F 'rfc4106(gcm(aes))' /proc/crypto
```

The last four commands are the kernel gate. Do not continue on a host where one fails.

## Run the secure baseline

From the repository root inside WSL2:

```bash
sudo python3 run_scenario.py secure-baseline
```

A successful invocation prints:

```text
run directory: runs/run_<UTC timestamp>
status: PASS
```

The operation order is fixed: preflight, scoped reset, scenario load, topology creation/readback, two isolated daemon starts, capture start, configuration load, initiation, SA wait, XFRM collection, five ICMP exchanges, explicit CHILD_SA rekey, capture stop, PCAP validation, conjunctive verdict, artifact publication, and cleanup. Capture starts before IKE initiation.

`--keep-lab` leaves the four network namespaces in place for inspection, but still stops the tracked tcpdump and strongSwan processes:

```bash
sudo python3 run_scenario.py secure-baseline --keep-lab
```

## Evidence and artifacts

Every run gets a collision-safe directory under `runs/`. A successful run contains:

```text
runs/run_<timestamp>/
  encrypted.pcap
  cleartext-audit-gateway-a.pcap
  cleartext-audit-gateway-b.pcap
  ground_truth.json
  verification.json
  run.log
  scenario.yaml
  strongswan-gateway-a.log
  strongswan-gateway-b.log
  swanctl-gateway-a.txt
  swanctl-gateway-b.txt
  swanctl-before-rekey-gateway-a.txt
  swanctl-before-rekey-gateway-b.txt
  swanctl-after-rekey-gateway-a.txt
  swanctl-after-rekey-gateway-b.txt
  xfrm-gateway-a.txt
  xfrm-gateway-b.txt
  pfs-rekey.log
  tcpdump.log
  tcpdump-audit-gateway-a.log
  tcpdump-audit-gateway-b.log
  runtime/gateway-{a,b}/{strongswan.conf,swanctl.conf,charon-stdout.log}
```

`ground_truth.json` keeps requested policy under `configured` and negotiated behavior under `observed`. The initial CHILD_SA alone is never treated as PFS proof. `observed.pfs.status` becomes `VERIFIED` only after an explicit rekey changes both gateways' CHILD SPIs and the new log segment selects `ESP:AES_GCM_16_256/ECP_384/NO_EXT_SEQ`.

`verification.json` is conjunctive: missing or mismatched IKE, CHILD, identity, proposal, selector, XFRM state, XFRM policy, ICMP, IKE capture, ESP capture, NAT-T exclusion, cleartext exclusion, or PFS rekey evidence makes the run fail. A failed stage returns a nonzero exit and preserves the available log and evidence instead of publishing a misleading pass.

## Inspect the PCAP independently

Set `$RUN` to the directory printed by one completed invocation:

```bash
RUN=runs/run_YYYYMMDDTHHMMSSZ

tcpdump -nn -r "$RUN/encrypted.pcap" 'udp port 500'
tcpdump -nn -r "$RUN/encrypted.pcap" 'ip proto 50'
tcpdump -nn -r "$RUN/encrypted.pcap" 'udp port 4500'
tcpdump -nn -r "$RUN/encrypted.pcap" \
  'icmp and (net 10.10.0.0/24 or net 10.20.0.0/24)'
tcpdump -nn -r "$RUN/cleartext-audit-gateway-a.pcap" \
  'icmp and (net 10.10.0.0/24 or net 10.20.0.0/24)'
tcpdump -nn -r "$RUN/cleartext-audit-gateway-b.pcap" \
  'icmp and (net 10.10.0.0/24 or net 10.20.0.0/24)'
```

The first two commands must show peer-matched traffic between `192.0.2.1` and `192.0.2.2`; UDP/4500 and protected ICMP in the outer-filtered PCAP must print no packets. The expected automated run has 8 UDP/500 packets (initial IKE plus CHILD rekey) and 10 ESP packets for five request/reply exchanges.

The two audit PCAPs deliberately include protected ICMP. On this WSL2 endpoint-veth observation point, gateway A exposes only post-decryption replies and gateway B only post-decryption requests. Each audit must independently contain peer-matched outer IKE and ESP, and all three tcpdump logs must report zero kernel drops. The validator fingerprints source, destination, ICMP type, identifier, and sequence. The same fingerprint on both transit endpoints would prove cleartext crossed the veth and fails the run; correct encrypted traffic has no cross-endpoint match.

Raw independent state is available in the two `swanctl-*.txt` and two `xfrm-*.txt` files. Search `run.log` for the protected ping summary:

```bash
grep -F '5 packets transmitted, 5 received' "$RUN/run.log"
```

## Dataset factory

Phase 2 runs the same tightly coupled secure-session lifecycle once per dataset attempt. Every attempt gets a new topology, strongSwan pair, IKE SA, CHILD SA, capture set, explicit CHILD_SA rekey, evidence bundle, cleanup result, and immutable manifest row. The protected networks remain `10.10.0.0/24` and `10.20.0.0/24`; capture occurs on the `192.0.2.0/30` transit veth where UDP/500 IKE and native protocol-50 ESP are directly observable. NAT and NAT-T remain excluded.

The supported traffic classes are:

- `icmp`: seeded count, interval, and payload size.
- `web`: seeded local page/resource order, sizes, and think times, with matching client records and server receipts.
- `video`: seeded local segment profile, sequence, sizes, and pacing, with matching client records and server receipts.

The same generator version, scenario, and seed resolves the same workload parameters where practical. Different attempt seeds vary meaningful workload parameters. Every resolved value and observed result is written to `traffic.json`; no Internet service or third-party content is used.

Run these commands from the repository root inside WSL2:

```bash
python3 -m ipsec_sentinel.dataset list-traffic
sudo python3 -m ipsec_sentinel.dataset run \
  --traffic video --scenario secure-baseline
sudo python3 -m ipsec_sentinel.dataset generate configs/smoke-v1.yaml
sudo python3 -m ipsec_sentinel.dataset generate configs/smoke-v1.yaml --resume
python3 -m ipsec_sentinel.dataset validate dataset/cipherlens-smoke-v1
```

`full-evidence.pcap` preserves the complete secure session: IKE establishment, workload ESP, and rekey/PFS evidence. `encrypted.pcap` is the future-ML input. It is deterministically derived from the full capture after the run by retaining only Ethernet/IPv4 protocol-50 packets exchanged between `192.0.2.1` and `192.0.2.2` whose PCAP timestamps fall inclusively between the nanosecond timestamps taken immediately before and after the workload process. The derived file is then parsed again and rejected if it contains a non-ESP packet, a wrong peer, an out-of-window timestamp, or zero packets. IKE establishment and rekey occur outside this workload window, so they cannot become classifier shortcuts.

Each successful attempt records the requested policy separately from live SA/XFRM/capture observations. PFS is configured policy until an explicit CHILD_SA rekey changes reciprocal SPIs and a fresh ECP-384 DH selection appears in the new daemon log segment. Dataset validation requires verified traffic, IPsec, capture separation, and cleanup; `PASS` alone cannot make a run training-ready unless every requirement passes.

The SQLite manifest uses `PENDING`, `RUNNING`, `PASS`, `FAILED`, and `INCOMPLETE` lifecycle states. Cleanup has its own `NOT_STARTED`, `PASS`, or `FAILED` status so it never hides the primary failure. Retries create new attempt IDs, seeds, directories, tunnels, and manifest rows; failed diagnostics are retained. `--resume` verifies the matrix fingerprint, converts stale `RUNNING` attempts to `INCOMPLETE`, retries eligible slots within the configured limit, and never regenerates a successful slot. A changed matrix is rejected rather than silently mixed into an existing dataset.

A successful attempt has this shape:

```text
dataset/<dataset-name>/
  manifest.sqlite3
  matrix.yaml
  dataset_summary.json
  runs/run_000001/
    full-evidence.pcap
    encrypted.pcap
    cleartext-audit-gateway-{a,b}.pcap
    ground_truth.json
    verification.json
    traffic.json
    environment.json
    scenario.yaml
    run.log
    swanctl-{gateway-a,gateway-b}.txt
    swanctl-{before-rekey,after-rekey}-{gateway-a,gateway-b}.txt
    xfrm-{gateway-a,gateway-b}.txt
    pfs-rekey.log
    strongswan-{gateway-a,gateway-b}.log
    tcpdump*.log
```

The offline validator reconciles the manifest, terminal JSON, ground-truth label, traffic parameters, PFS status, capture counts, capture size, workload window, and required files. It reparses every training-ready `encrypted.pcap` using the strict ESP-only contract. Failed and incomplete attempts remain inspectable but are excluded from the successful training-ready set.

For resumable unattended collection, create and review a larger matrix first, then replace only the matrix path in this pattern:

```bash
sudo nohup python3 -m ipsec_sentinel.dataset generate configs/smoke-v1.yaml --resume \
  > dataset-generation.log 2>&1 &
```

A host-native supervisor such as systemd is preferred for long collections. A force-kill can leave a `RUNNING` row; the next `--resume` converts it to `INCOMPLETE` before deciding whether to retry. Execution is intentionally serial in Phase 2.

New generators implement the five-method traffic contract: `prepare(context)`, `run(context)`, `validate(context, result)`, `cleanup(context)`, and `metadata()`. They must be locally controlled, seed all planned variability, record every selected parameter, validate the intended class from both available endpoints, and make cleanup idempotent before registration in the traffic registry.

## Tests

Unit tests do not require privileges. The integration test creates the real tunnel and must run as root:

```bash
python3 -m unittest discover -s tests -v
sudo env IPSEC_SENTINEL_INTEGRATION=1 \
  python3 -m unittest tests.test_secure_baseline_integration -v
sudo env IPSEC_SENTINEL_DATASET_INTEGRATION=1 \
  python3 -m unittest tests.test_dataset_integration -v
```

## Cleanup and failure safety

Normal execution and handled interruption attempt every cleanup layer independently: all three tracked tcpdump processes, daemon log preservation, both tracked strongSwan processes, the four `ips-*` namespaces, exact root-veth names left by partial setup, and per-run VICI/PID/log/capture paths. Namespace deletion removes the remaining lab veths, routes, XFRM state, and policies. Durable run artifacts remain.

The runner does not use wildcard process killing. A host crash or force-kill that prevents `finally` cleanup may require deleting the four named namespaces before the next run; the next normal reset already attempts that scoped deletion.

## Troubleshooting

- `IPsec Sentinel must run as Linux root`: invoke the command with `sudo` inside WSL2, not with Windows Python.
- `kernel ... unavailable`: confirm the WSL2 kernel exposes XFRM and `rfc4106(gcm(aes))`; stop rather than substituting a different lab design.
- VICI readiness or daemon startup failure: inspect `strongswan-gateway-*.log`, `runtime/gateway-*/charon-stdout.log`, and the rendered per-run configuration.
- Topology readback failure: inspect `run.log` for the named route, forwarding, `rp_filter`, address, or NAT check. IKE is not started after this failure.
- PCAP failure: inspect all three `tcpdump*.log` files, confirm capture started on both gateway `wan0` endpoints, and use the filters above against the saved files.
- Optional swanctl plugin warnings: Ubuntu may report plugins that are not installed. They are harmless only when the required AES-GCM, PRF, ECP, kernel-netlink, VICI, and socket plugins load and the live evidence passes.

## Limitations and next phase

Only `secure-baseline` is supported: IKEv2, IPv4 tunnel mode, PSK authentication, AES-256-GCM, ECP-384, and PFS rekey. Dataset workloads are ICMP, local HTTP Web, and local segmented Video over the clean network profile. The deterministic lab PSK is test-only. There is no NAT-T, IPv6, transport mode, IKEv1, impairment injection, parallel execution, security scoring, UI, or cloud support.

The compact ground-truth schema stores configured policy, negotiated proposals, PFS evidence, traffic outcome, and capture counts. Detailed identities, selectors, SA states/SPIs, and XFRM directions remain in `verification.json` and the retained raw evidence files instead of being duplicated into `ground_truth.json`.

On this WSL2/veth kernel, a broad AF_PACKET capture on a gateway endpoint exposes a post-decryption inbound inner packet artifact. IPsec Sentinel therefore retains a filtered outer-wire PCAP plus broad audit PCAPs from both transit endpoints. Cleartext exclusion is based on cross-endpoint packet correlation, while bidirectional ESP and SPI-correlated XFRM/CHILD state provide independent corroboration. This is still a virtual-interface observation, not a physical-tap proof.

Phase 2 ends at validated evidence and dataset creation. It does not extract features, clean data for ML, construct train/test splits, train classifiers, evaluate models, or export a model. Those are Phase 3 concerns and require separate review and authorization.
