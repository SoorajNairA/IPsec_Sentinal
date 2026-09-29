# IPsec Analyzer Prototype Evidence

## Public command

```bash
python3 -m ipsec_sentinel.analyze capture.pcap --json analysis.json
```

Optional `--model-dir` selects an exported classifier bundle and optional
`--evidence-dir` selects controlled-run `ground_truth.json` and
`verification.json` artifacts. When valid artifacts are adjacent to a known
run capture they are discovered automatically. Packet evidence and controlled
evidence retain separate source components and provenance.

## Genuine capture verification

The gated real-capture test analyzed existing, independently generated dataset
artifacts without regenerating them:

| Run | Scenario | Observed IKE encryption | Integrity | IKE DH | CHILD PFS | ESP packets |
| --- | --- | --- | --- | --- | --- | ---: |
| `run_000001` | `secure-baseline` | AES-256-GCM | AEAD | ECP-384 | enabled, controlled rekey evidence | 14 |
| `run_000043` | `aes128-gcm` | AES-128-GCM | AEAD | ECP-384 | enabled, controlled rekey evidence | 14 |
| `run_000085` | `aes256-cbc` | AES-256-CBC | HMAC-SHA-256 | ECP-384 | enabled, controlled rekey evidence | 10 |
| `run_000127` | `no-pfs` | AES-256-GCM | AEAD | ECP-384 | disabled, controlled `VERIFIED_DISABLED` evidence | 18 |

The no-PFS capture produced an evidence-backed MEDIUM finding and a transparent
score of 88/100 based on 80% assessed weight. Unknown replay enforcement and
other passive-only properties were not penalized.

For the judge-friendly traffic demo, `run_000013/encrypted.pcap` contained
1,205 real ESP packets. The existing exported Extra Trees model inferred
`video` at 1.000 raw, uncalibrated confidence. The analysis states that no
payload was decrypted. End-to-end process time, including Python and model
startup under WSL2, was 2.36 seconds in the recorded run.

## Evidence and scoring semantics

- IKEv2 header fields and responder IKE_SA_INIT transform selection are
  `OBSERVED` packet evidence.
- ESP statistics are `DERIVED` from observed packet timestamps, lengths,
  directions, sequence fields, and SPIs.
- SPI replacement is `DERIVED` rekey evidence and is never treated as proof of
  CHILD-SA PFS.
- Controlled strongSwan/XFRM run artifacts may derive PFS enabled/disabled only
  when both run and verification status pass and their explicit PFS status
  matches the recorded configuration.
- Traffic inference is `AI_INFERRED`, raw/uncalibrated, and scoped to the
  controlled native-IPsec training environment.
- UNKNOWN assessment weight is exposed and never deducted as insecurity.

## Honest limitations

- Ethernet/IPv4 classic PCAP is implemented. PCAPNG is detected and returned as
  a structured unsupported-format result; IPv6 is not yet parsed.
- NAT-T and AH are detected. NAT-T supports IKE non-ESP markers and basic
  encapsulated ESP metadata, not a complete NAT mobility analysis.
- Passive IKE analysis extracts clear IKE_SA_INIT material. Encrypted IKE_AUTH
  and CREATE_CHILD_SA bodies are not decrypted.
- Arbitrary PCAP-only CHILD-SA PFS, replay enforcement, configured lifetimes,
  and tunnel-versus-transport mode generally remain unknown.
- ESP SAs are represented per directional SPI. Replacement chronology is a
  transparent heuristic; multiple peer pairs are reported and aggregate ESP
  features are limited to the dominant pair.
- The classifier is a prototype trained on controlled synthetic workloads and
  its probability is uncalibrated; it is not an OOD detector.
