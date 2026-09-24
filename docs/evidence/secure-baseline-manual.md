# Secure Baseline Manual Proof

## Result

The manual secure-baseline gate passed on 2026-09-23. A real IKEv2 site-to-site tunnel carried five ICMP echo request/reply exchanges between `10.10.0.2` and `10.20.0.2`. Both strongSwan instances, both Linux XFRM views, and the saved transit PCAP independently confirmed the result.

PFS is configured policy only at this gate. The initial CHILD_SA does not behaviorally prove a fresh CHILD_SA DH exchange:

```text
configured.pfs = true
observed.pfs.status = NOT_TESTED
```

## Environment

```text
Host: Windows with WSL2
Distribution: Ubuntu 26.04 LTS
Kernel: 6.18.33.2-microsoft-standard-WSL2
Python: 3.14.4
charon-systemd: 6.0.4-1ubuntu3.2
strongswan-swanctl: 6.0.4-1ubuntu3.2
libstrongswan: 6.0.4-1ubuntu3.2
libstrongswan-standard-plugins: 6.0.4-1ubuntu3.2
tcpdump: 4.99.6
iproute2: 6.19.0-1ubuntu1.1
```

The privileged preflight commands succeeded:

```bash
ip xfrm state
ip xfrm policy
test -r /proc/net/xfrm_stat
grep -F rfc4106 /proc/crypto
ip netns list
```

`/proc/crypto` reported `rfc4106(gcm(aes))` through AES-NI drivers. The installed strongSwan daemon reported these required algorithms:

```text
AES_GCM_16[aesni]
PRF_HMAC_SHA2_384[openssl]
ECP_384[openssl]
```

## Topology State

The four namespaces and their links were created with the commands in Task 2 of the implementation plan. The final addressing and routes were:

```text
ips-client eth0  10.10.0.2/24
ips-gwa    lan0  10.10.0.1/24
ips-gwa    wan0  192.0.2.1/30
ips-gwb    wan0  192.0.2.2/30
ips-gwb    lan0  10.20.0.1/24
ips-server eth0  10.20.0.2/24

ips-client: 10.20.0.0/24 via 10.10.0.1 dev eth0
ips-server: 10.10.0.0/24 via 10.20.0.1 dev eth0
```

Both gateways read back:

```text
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.lan0.rp_filter = 0
net.ipv4.conf.wan0.rp_filter = 0
```

`iptables -t nat -S` contained only the four built-in ACCEPT policies in each gateway namespace. No NAT rule was installed. Bidirectional adjacency pings succeeded on the client LAN, transit link, and server LAN before IKE initiation. No end-to-end ping was sent before XFRM policies existed.

## Isolated strongSwan Processes

The package-managed strongSwan service was stopped. Each manually launched daemon ran inside its gateway namespace with a different configuration, runtime directory, tracked PID, log, and VICI socket:

```text
/run/ipsec-sentinel/gateway-a/charon.vici
/run/ipsec-sentinel/gateway-b/charon.vici
```

The launch pattern was:

```bash
ip netns exec ips-gwa env \
  STRONGSWAN_CONF="$PWD/lab/manual/gateway-a/strongswan.conf" \
  charon-systemd

ip netns exec ips-gwb env \
  STRONGSWAN_CONF="$PWD/lab/manual/gateway-b/strongswan.conf" \
  charon-systemd
```

The actual strongSwan 6.0.4 CLI requires the operation before operation-specific options. Configuration was loaded with:

```bash
swanctl --load-all \
  --uri unix:///run/ipsec-sentinel/gateway-a/charon.vici \
  --file "$PWD/lab/manual/gateway-a/swanctl.conf" \
  --noprompt

swanctl --load-all \
  --uri unix:///run/ipsec-sentinel/gateway-b/charon.vici \
  --file "$PWD/lab/manual/gateway-b/swanctl.conf" \
  --noprompt
```

Both commands loaded the deterministic PSK and `secure-baseline` connection successfully. The swanctl process printed warnings for optional plugins not shipped by the Ubuntu package; the live daemon capability check and successful negotiation confirmed that all required plugins and algorithms were available.

## Capture and Initiation

The final capture started before initiation on gateway A's transit veth. Its BPF restricts the PCAP to the encrypted outer wire view:

```bash
ip netns exec ips-gwa tcpdump -U -n -i wan0 \
  -w /tmp/ipsec-sentinel-secure-baseline.pcap \
  'host 192.0.2.1 and host 192.0.2.2 and (udp port 500 or udp port 4500 or ip proto 50)'

swanctl --initiate \
  --child protected-nets \
  --uri unix:///run/ipsec-sentinel/gateway-a/charon.vici
```

The initiator log selected:

```text
IKE:AES_GCM_16_256/PRF_HMAC_SHA2_384/ECP_384
ESP:AES_GCM_16_256/NO_EXT_SEQ
```

The IKE SA and CHILD SA both established between `192.0.2.1[gateway-a]` and `192.0.2.2[gateway-b]` with selectors `10.10.0.0/24 === 10.20.0.0/24`.

## Independent SA Evidence

Gateway A reported:

```text
version=2 state=ESTABLISHED
local-host=192.0.2.1 local-port=500 local-id=gateway-a
remote-host=192.0.2.2 remote-port=500 remote-id=gateway-b
encr-alg=AES_GCM_16 encr-keysize=256
prf-alg=PRF_HMAC_SHA2_384 dh-group=ECP_384
CHILD state=INSTALLED mode=TUNNEL protocol=ESP
spi-in=c2ad5304 spi-out=cbecd5e6
packets-in=5 packets-out=5
local-ts=[10.10.0.0/24] remote-ts=[10.20.0.0/24]
```

Gateway B reported the reversed peer and selector view with the same IKE SPIs, reversed CHILD SPIs, and five inbound plus five outbound packets.

## Independent XFRM Evidence

Gateway A installed two tunnel-mode RFC 4106 AES-GCM states:

```text
192.0.2.1 -> 192.0.2.2 spi 0xcbecd5e6 reqid 1 mode tunnel dir out oseq 0x5
192.0.2.2 -> 192.0.2.1 spi 0xc2ad5304 reqid 1 mode tunnel dir in  seq 0x5
```

Gateway B installed the matching reversed states. Each gateway installed `out`, `fwd`, and `in` policies for the correct protected subnet pair and native ESP tunnel template.

## Traffic Evidence

The exact protected traffic command was:

```bash
ip netns exec ips-client ping -I 10.10.0.2 -c 5 -W 2 10.20.0.2
```

Result:

```text
5 packets transmitted, 5 received, 0% packet loss
reply TTL: 62
```

## PCAP Evidence

Tcpdump flushed the complete final capture after a one-second drain:

```text
14 packets captured
14 packets received by filter
0 packets dropped by kernel
```

Independent saved-file filters found:

```text
UDP/500 IKE packets: 4
  IKE_SA_INIT request and response
  IKE_AUTH request and response

Native ESP packets: 10
  5 from 192.0.2.1 to 192.0.2.2
  5 from 192.0.2.2 to 192.0.2.1

UDP/4500 packets: 0
Inner ICMP packets in outer-wire PCAP: 0
```

The final PCAP SHA-256 is:

```text
de096e360b6fd7d715a4ca9ba3b9b1ec1f9670c065d45fd6e720f4778a36fc18
```

## WSL2 Capture and Lifetime Notes

WSL2 stops the distribution when the final `wsl.exe` client exits, even when systemd services are configured. The manual proof therefore kept one root shell alive throughout. The future runner itself supplies that lifetime because setup, execution, validation, and cleanup occur in one Linux process.

A diagnostic broad BPF on gateway A's endpoint veth observed each inbound ESP packet and its post-decryption inner echo reply at the same timestamp and Ethernet direction. This is an AF_PACKET observation-point artifact, not cleartext transmission across the veth. `tcpdump -Q out` captured no packets on this WSL/veth combination. The final evidence capture therefore restricts packets to both outer peers and IKE/ESP protocols, while the independent XFRM state, policy, counters, and bidirectional ESP packets prove protection.

## Gate Decision

The manual gate passed because all required evidence agreed:

- IKEv2 SA established on both peers;
- tunnel-mode CHILD SA installed on both peers;
- client-to-server ICMP succeeded;
- matching XFRM state and `out`/`fwd`/`in` policies existed;
- genuine bidirectional native ESP was captured;
- the IKEv2 exchange was captured on UDP/500; and
- no NAT-T traffic appeared.

Automation was permitted to begin at this point. This manual milestone continues to record PFS as `NOT_TESTED`; later automated rekey evidence does not retroactively change what the initial CHILD_SA alone proved.

## Automated Baseline and PFS Follow-up

The completed runner preserves the manual gate and then performs a separate explicit CHILD_SA rekey. Representative final repeated runs are `runs/run_20260924T150855Z` and `runs/run_20260924T150909Z`.

The initial and rekey evidence remained distinct:

```text
configured.pfs = true
initial CHILD_SA PFS status = NOT_TESTED
explicit rekey attempted = true
gateway-a CHILD SPIs: ce47b343/c193b064 -> c662d0b7/cf387e36
gateway-b CHILD SPIs: c193b064/ce47b343 -> cf387e36/c662d0b7
rekey completed: true
reciprocal SPIs: true
both inbound and outbound SPIs changed: true
selected rekey proposal: ESP:AES_GCM_16_256/ECP_384/NO_EXT_SEQ
final observed.pfs.status = VERIFIED
```

The same run independently recorded:

```text
IKE SAs: ESTABLISHED on gateway A and gateway B
CHILD SAs: INSTALLED on gateway A and gateway B
XFRM: matching native-ESP tunnel state and out/fwd/in policies on both gateways
ICMP: 5 transmitted, 5 received
saved PCAP: 8 UDP/500 packets, 10 ESP packets, 0 UDP/4500 packets
protected cleartext packet fingerprints correlated across both transit endpoints: 0
gateway-a audit: 5 post-decryption replies, 0 requests
gateway-b audit: 5 post-decryption requests, 0 replies
overall verification: PASS
```

Independent saved-PCAP validation produced identical protocol counts in both final runs:

```text
run_20260924T150855Z sha256 3b68c92d9feed27fb6f8f09b8cc0394619da96e0ea89a9a90e71a171f6409a65
run_20260924T150909Z sha256 f5b2d082df8aa7f2c339160f71247e0b89f951b26e5d5ce87790644c16a1be33
```

The automated capture uses tcpdump immediate mode so packets received just before bounded SIGINT shutdown are published to the PCAP. The run directory retains the initial SA views, before/after-rekey SA views, XFRM snapshots, the rekey-only strongSwan log segment, full daemon logs, the filtered outer PCAP, two broad endpoint-audit PCAPs, scenario, run log, verification, and ground truth.

The broad-capture WSL2 endpoint-veth limitation described above still applies. The validator accounts for it by fingerprinting protected ICMP on both gateway transit endpoints: a true on-wire cleartext packet would occur in both captures, whereas the post-decryption artifact appears only at its receiving endpoint. Any matching source/destination/type/id/sequence fingerprint fails the run. Both audits must also contain outer IKE and ESP and report zero kernel drops, so an empty or degraded audit cannot prove absence. The CHILD SPIs must match reciprocal, direction-correlated XFRM states and policies.
