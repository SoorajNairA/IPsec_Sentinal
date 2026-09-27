# IPsec Sentinel

IPsec Sentinel is a Linux-first IPsec testbed, evidence verifier, reproducible encrypted-traffic dataset factory, classical ESP-session classifier prototype, and local security-forensics interface. It creates a genuine IKEv2 site-to-site tunnel with strongSwan, runs a known local workload through Linux XFRM, captures UDP/500 and native protocol-50 ESP, and writes configured-versus-observed evidence. The prototype adds leakage-controlled full-session metadata features, an exported scikit-learn model, and an evidence-backed React workspace without changing the Phase 1 `run_secure_baseline()` behavior. It does not decrypt payloads and does not implement deep learning, a remote/public service API, cloud deployment, NAT/NAT-T, OOD rejection, or network impairment profiles.

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
- `voip`: synthetic RTPv2/UDP-style bidirectional voice cadence with seeded packetization interval, talk-spurt timing, payload sizes, and call duration.
- `email`: local SMTP transactions with seeded message/body/attachment sizes, connection grouping, recipients, and think times.
- `messaging`: persistent bidirectional framed TCP chat with seeded bursts, directions, message sizes, replies, and idle gaps.
- `file_transfer`: checksum-verified bulk TCP upload, download, or bidirectional transfer with seeded sizes and write behavior.

The allowlisted IPsec scenarios are `secure-baseline`, `aes128-gcm`, `aes256-cbc`, and `no-pfs`. All retain IKEv2, the same protected/transit topology, and independent SA/XFRM/capture verification. The first three verify CHILD PFS after rekey with ECP-384. `no-pfs` verifies a changed CHILD SA without CHILD DH and records `VERIFIED_DISABLED` rather than mislabeling PFS as enabled.

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

`full-evidence.pcap` preserves the complete secure session: IKE establishment, workload ESP, and rekey/PFS evidence. `encrypted.pcap` is the ML input. It is deterministically derived from the full capture after the run by retaining only Ethernet/IPv4 protocol-50 packets exchanged between `192.0.2.1` and `192.0.2.2` whose PCAP timestamps fall inclusively between the nanosecond timestamps taken immediately before and after the workload process. Selected records are stably ordered by timestamp because Linux capture delivery can contain microsecond-scale inversions under load; the source evidence file is never rewritten. The derived file is parsed again and rejected if it contains a non-ESP packet, a wrong peer, an out-of-window timestamp, a remaining timestamp inversion, or zero packets. IKE establishment and rekey occur outside this workload window, so they cannot become classifier shortcuts.

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

The reviewed first production matrix is `configs/prototype-v1.yaml`: seven supervised classes × four IPsec scenarios × one clean network profile × six independent repetitions = 168 sessions. Start or resume it unattended from the repository root with:

```bash
sudo -v
sudo nohup python3 -m ipsec_sentinel.dataset generate configs/prototype-v1.yaml --resume \
  > dataset/prototype-v1-generation.log 2>&1 &
```

A host-native supervisor such as systemd is preferred for long collections. A force-kill can leave a `RUNNING` row; the next `--resume` converts it to `INCOMPLETE` before deciding whether to retry. Execution is intentionally serial in Phase 2.

New generators implement the five-method traffic contract: `prepare(context)`, `run(context)`, `validate(context, result)`, `cleanup(context)`, and `metadata()`. They must be locally controlled, seed all planned variability, record every selected parameter, validate the intended class from both available endpoints, and make cleanup idempotent before registration in the traffic registry.

## ESP feature and model pipeline

Install the optional ML dependencies in a virtual environment:

```bash
python3 -m venv ~/.venvs/ipsec-sentinel-ml
~/.venvs/ipsec-sentinel-ml/bin/pip install -r requirements-ml.txt
```

The feature schema is versioned as `ipsec-sentinel.esp-session-features/v1`. It summarizes one complete workload-window session using only relative packet times, outer ESP packet lengths, and peer direction. It excludes labels, seeds, scenario names, ports, IP-address values, run IDs, absolute timestamps, IKE/rekey packets, and payload contents. Build, split, benchmark/evaluate/export, and infer with:

```bash
python3 -m ipsec_sentinel.dataset validate dataset/ipsec-sentinel-prototype-v1

MLPY=~/.venvs/ipsec-sentinel-ml/bin/python
$MLPY -m ipsec_sentinel.ml build \
  dataset/ipsec-sentinel-prototype-v1 \
  dataset/ipsec-sentinel-prototype-v1/ml
$MLPY -m ipsec_sentinel.ml split \
  dataset/ipsec-sentinel-prototype-v1/ml/features.csv \
  dataset/ipsec-sentinel-prototype-v1/ml/split_manifest.json \
  --seed 20260926
$MLPY -m ipsec_sentinel.ml train \
  dataset/ipsec-sentinel-prototype-v1/ml/features.csv \
  dataset/ipsec-sentinel-prototype-v1/ml/split_manifest.json \
  dataset/ipsec-sentinel-prototype-v1/ml/model \
  --seed 20260926
$MLPY -m ipsec_sentinel.ml predict \
  path/to/encrypted.pcap \
  --model-dir dataset/ipsec-sentinel-prototype-v1/ml/model
```

`train` intentionally performs benchmark selection, held-out evaluation, and export as one leakage-safe operation. It compares Random Forest, Extra Trees, and Histogram Gradient Boosting using validation macro-F1, then writes the chosen model, immutable feature schema, class map, split manifest, metrics, and reproducibility metadata. Confidence is raw `predict_proba`, explicitly not calibrated. Inference is labeled `AI-INFERRED` and states that no payload was decrypted.

The split unit is a complete session, stratified by traffic class and IPsec scenario. No packets/windows from one session can cross train, validation, or test. Pilot metrics based on three sessions per class are pipeline evidence only; use the 168-session matrix before drawing performance or cross-scenario generalization conclusions.

## External dataset evidence

Public datasets live outside the repository and outside OneDrive. Install the optional inspection dependencies, select a WSL ext4 root, and use the allowlisted commands:

```bash
~/.venvs/ipsec-sentinel-ml/bin/pip install -r requirements-external.txt
export IPSEC_SENTINEL_EXTERNAL_DATA_ROOT=/home/$USER/ipsec-sentinel-external-datasets

~/.venvs/ipsec-sentinel-ml/bin/python -m ipsec_sentinel.external registry validate
~/.venvs/ipsec-sentinel-ml/bin/python -m ipsec_sentinel.external acquire usbvpn2022 --resume
~/.venvs/ipsec-sentinel-ml/bin/python -m ipsec_sentinel.external inspect usbvpn2022
~/.venvs/ipsec-sentinel-ml/bin/python -m ipsec_sentinel.external report
```

Acquisition receipts, inspection inventories, and compatibility reports are written beneath that external root. Raw public artifacts, extracted files, normalized observations, and reports are never committed. Source labels are accepted only through exact registry mappings. External observations may cross into the statistical calculator only as relative time, size, and direction; source IDs, filenames, protocols, ports, labels, addresses, and absolute timestamps are excluded from the feature schema.

External data is evaluation-only. Primary supervised training requires native `training_ready` sessions with `known_training_class == true` and an allowlisted class; public datasets are never mixed into the native training table.

## Local analysis frontend

The React frontend renders the immutable `ipsec-sentinel.analysis/v1` contract and a separately namespaced `ipsec-sentinel.xray/v1` packet-metadata projection. It never receives ESP payload bytes and labels model confidence as raw and uncalibrated. Five bundled guided demos were generated by the real analyzer from retained PCAPs; `frontend/public/demos/manifest.json` records each source run, capture name, analyzer commit, generation command, and artifact digest.

Install the pinned frontend dependencies and start guided-demo mode from Windows PowerShell:

```powershell
npm --prefix frontend install
npm --prefix frontend run dev -- --host 127.0.0.1 --port 4173
```

Open `http://127.0.0.1:4173` and select **Run Guided Demo**. Guided demos are static, local artifacts and do not require the Python analyzer or model to be running.

For live PCAP analysis, first build the frontend from Windows PowerShell:

```powershell
npm --prefix frontend run build
```

Then start the loopback-only bridge from WSL with the exported model directory:

```bash
~/.venvs/ipsec-sentinel-ml/bin/python -m ipsec_sentinel.frontend \
  --static-dir frontend/dist \
  --model-dir dataset/ipsec-sentinel-prototype-v1/ml/model
```

Open `http://127.0.0.1:8787`. The bridge accepts raw classic-PCAP uploads at `/api/analyze`, binds to `127.0.0.1`, limits uploads to 256 MiB by default, calls the analyzer directly without a shell, and removes temporary files on success and failure. PCAPNG, malformed captures, unsupported link/network layouts, missing models, and non-IPsec captures produce structured safe errors rather than tracebacks. For development, the Vite server proxies `/api` to the same bridge on port 8787.

Frontend verification commands are:

```powershell
npm --prefix frontend run lint
npm --prefix frontend test -- --run
npm --prefix frontend run build
npm --prefix frontend run e2e -- --project=chromium
npm --prefix frontend audit --audit-level=high
```

If Playwright cannot download a browser, set `IPSEC_SENTINEL_CHROMIUM_PATH` to a compatible local Chromium executable. The interface is a localhost prototype, not an authenticated multi-user service. It supports classic Ethernet/IPv4 PCAP input, uses a controlled synthetic testbed model with uncalibrated probabilities, and makes no payload-decryption claim.

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

The prototype supports four tightly allowlisted IPsec policies and seven local supervised workloads over the clean network profile. The deterministic lab PSK is test-only. The traffic generators are controlled behavioral simulations rather than public services, and the VoIP generator models RTP cadence rather than encoding live audio. There is no NAT-T, IPv6, transport mode, IKEv1, OOD dataset, impairment injection, parallel execution, remote/public API, authenticated multi-user UI, or cloud support. Frontend security scoring is the analyzer's evidence-weighted assessment, not an independent vulnerability scanner.

The compact ground-truth schema stores configured policy, negotiated proposals, PFS evidence, traffic outcome, and capture counts. Detailed identities, selectors, SA states/SPIs, and XFRM directions remain in `verification.json` and the retained raw evidence files instead of being duplicated into `ground_truth.json`.

On this WSL2/veth kernel, a broad AF_PACKET capture on a gateway endpoint exposes a post-decryption inbound inner packet artifact. IPsec Sentinel therefore retains a filtered outer-wire PCAP plus broad audit PCAPs from both transit endpoints. Cleartext exclusion is based on cross-endpoint packet correlation, while bidirectional ESP and SPI-correlated XFRM/CHILD state provide independent corroboration. This is still a virtual-interface observation, not a physical-tap proof.

The exported model is a classical proof of the end-to-end pipeline, not a production classifier. The 21-session pilot has only one validation and one test session per class, one IPsec scenario, no external captures, no calibrated probabilities, and no OOD rejection. The strict standalone inference command validates that its input file is ESP-only and peer-matched, but without the run's ground truth it cannot independently reconstruct the original workload-window timestamps. Production claims require the full balanced matrix and a separate evaluation phase.
