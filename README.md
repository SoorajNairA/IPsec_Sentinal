# IPsec Sentinel

IPsec Sentinel Phase 1 is a Linux-first IPsec testbed and verifier. It creates a genuine IKEv2 site-to-site tunnel with strongSwan, sends ICMP through Linux XFRM, captures UDP/500 and native protocol-50 ESP, and writes configured-versus-observed evidence. This phase deliberately contains no AI/ML, UI, dataset generation, NAT/NAT-T scenario, or generalized algorithm matrix.

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

The two audit PCAPs deliberately include protected ICMP. On this WSL2 endpoint-veth observation point, gateway A exposes only post-decryption replies and gateway B only post-decryption requests. The validator fingerprints source, destination, ICMP type, identifier, and sequence. The same fingerprint on both transit endpoints would prove cleartext crossed the veth and fails the run; correct encrypted traffic has no cross-endpoint match.

Raw independent state is available in the two `swanctl-*.txt` and two `xfrm-*.txt` files. Search `run.log` for the protected ping summary:

```bash
grep -F '5 packets transmitted, 5 received' "$RUN/run.log"
```

## Tests

Unit tests do not require privileges. The integration test creates the real tunnel and must run as root:

```bash
python3 -m unittest discover -s tests -v
sudo env IPSEC_SENTINEL_INTEGRATION=1 \
  python3 -m unittest tests.test_secure_baseline_integration -v
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

Only `secure-baseline` is supported: IKEv2, IPv4 tunnel mode, PSK authentication, AES-256-GCM, ECP-384, PFS rekey, and ICMP. The deterministic lab PSK is test-only. There is no NAT-T, IPv6, transport mode, IKEv1, impairment injection, application traffic, security scoring, UI, or cloud support.

The compact ground-truth schema stores configured policy, negotiated proposals, PFS evidence, traffic outcome, and capture counts. Detailed identities, selectors, SA states/SPIs, and XFRM directions remain in `verification.json` and the retained raw evidence files instead of being duplicated into `ground_truth.json`.

On this WSL2/veth kernel, a broad AF_PACKET capture on a gateway endpoint exposes a post-decryption inbound inner packet artifact. IPsec Sentinel therefore retains a filtered outer-wire PCAP plus broad audit PCAPs from both transit endpoints. Cleartext exclusion is based on cross-endpoint packet correlation, while bidirectional ESP and SPI-correlated XFRM/CHILD state provide independent corroboration. This is still a virtual-interface observation, not a physical-tap proof.

Phase 2 -- automated encrypted-traffic dataset generation -- is intentionally deferred. The recommended next step is to design it only after this Phase 1 baseline remains stable on the target collection hosts and the user explicitly authorizes Phase 2.
