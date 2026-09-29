# IPsec Sentinel prototype pilot evidence

Date: 2026-09-26

## Scope

The retained pilot at `dataset/ipsec-sentinel-prototype-pilot-v1` contains three independent secure sessions for each supervised class on `secure-baseline`. Separate retained one-session datasets prove each additional IPsec scenario. Dataset and model outputs are ignored by Git; this document records the reproducible commands and measured results.

## Dataset result

- Matrix: 7 classes × 1 IPsec scenario × 1 clean profile × 3 repetitions = 21 successful slots.
- Attempts: 24 total; 21 PASS, 3 FAILED, 0 INCOMPLETE.
- Failed attempts: one VoIP and two File Transfer attempts were preserved and independently retried. All three failures were `zero_or_insufficient_esp` caused by microsecond-scale source-PCAP timestamp inversions. Stable timestamp ordering in derived ML captures fixes the root cause without changing `full-evidence.pcap`.
- Offline validation: PASS, 21 valid runs, 3 retained failed attempts.
- Wall time: 319.37 seconds including three retries.
- Successful workload-window duration: 37.617 seconds.
- Successful ML captures: 15,312 ESP packets and 17,489,220 bytes.
- Successful full-evidence captures: 17,536,869 bytes.
- Successful capture roles including both cleartext audits: 70,117,647 bytes.
- Complete retained pilot directory including logs, metadata, failed attempts, and ML model: 153,392,812 bytes.
- Resume proof: rerunning the completed matrix with `--resume` left attempt rows at 24, PASS rows at 21, and run directories at 24; no successful slot was regenerated.

| Class | Sessions | ESP packets | ML bytes | Workload seconds |
|---|---:|---:|---:|---:|
| email | 3 | 413 | 256,694 | 1.193 |
| file_transfer | 3 | 10,270 | 13,173,732 | 2.962 |
| icmp | 3 | 38 | 20,020 | 2.060 |
| messaging | 3 | 127 | 48,226 | 3.270 |
| video | 3 | 3,127 | 3,184,878 | 14.351 |
| voip | 3 | 738 | 169,668 | 12.533 |
| web | 3 | 599 | 636,002 | 1.246 |

## Seeded variation examples

The values below come from successful `traffic.json` files. Replaying a generator version, seed, and scenario resolves the same plan; different seeds vary experimental intent rather than promising byte-identical capture timing.

- ICMP: `(count, interval, payload)` = `(7, 0.1 s, 512 B)`, `(7, 0.1 s, 512 B)`, `(5, 0.2 s, 128 B)`.
- Web: total selected resource bytes = 183,296; 201,728; 164,864, with ports 23534, 27261, and 29423.
- Video: high/5 segments/910,711 B/4 s; medium/6/721,078 B/5 s; high/6/1,116,944 B/5 s.
- VoIP: 30 ms/4.62 s/235 packets; 30 ms/4.05 s/208 packets; 20 ms/3.64 s/292 packets, with independent bidirectional talk-spurt plans.
- Email: 5 messages/18,624 body bytes/73,728 attachment bytes; 3/10,432/32,768; 3/4,288/8,192.
- Messaging: 20 messages/0.841 s/4,494 payload bytes; 23/1.517/10,600; 16/0.846/4,683, with seeded directions and bursts.
- File Transfer: download/3,668,992 B/8 KiB writes; upload/1,160,192 B/64 KiB writes; bidirectional/6,938,624 B/32 KiB writes.

## Capture separation

The strict parser re-read all 21 successful `encrypted.pcap` files using their recorded workload windows and fixed transit peers. It accepted 15,312 ESP packets, with a minimum of 10 per session, and found zero non-ESP, wrong-peer, out-of-window, or non-monotonic records. Consequently these files contain zero UDP/500 IKE, zero UDP/4500 NAT-T, and zero rekey packets. Feeding a retained `full-evidence.pcap` to the inference CLI fails closed with `ML capture contains a non-ESP packet`.

The full-evidence files retain eight peer-matched UDP/500 IKE/rekey packets per successful session plus workload ESP. PFS remains rekey evidence, not an inference from initial CHILD establishment.

## IPsec scenario proof

Each proof is a real ICMP session with independent swanctl, XFRM, capture, configured-policy, negotiated-policy, traffic, rekey, and cleanup checks.

| Scenario | Configured CHILD proposal | Observed CHILD proposal | PFS result | ML ESP packets |
|---|---|---|---|---:|
| aes128-gcm | `aes128gcm16-ecp384` | `AES_GCM_16_128/ECP_384/NO_EXT_SEQ` on rekey | `VERIFIED` | 10 |
| aes256-cbc | `aes256-sha256-ecp384` | `AES_CBC_256/HMAC_SHA2_256_128/ECP_384/NO_EXT_SEQ` on rekey | `VERIFIED` | 10 |
| no-pfs | `aes256gcm16` | `AES_GCM_16_256/NO_EXT_SEQ` on rekey | `VERIFIED_DISABLED` | 18 |

## ML pipeline proof

- Builder: 21 manifest-approved rows; dataset SHA-256 `41cba76e2ad845131c5c94760e8206a6c26bb4fd4b0a54d4007e6fe55edccdc1`.
- Split: 7 train, 7 validation, 7 test, grouped by complete session and stratified by class plus scenario.
- Candidates: Random Forest, Extra Trees, Histogram Gradient Boosting.
- Selected: Extra Trees by validation macro-F1.
- Held-out test: accuracy 0.857 and macro-F1 0.810 (7 sessions, one per class).
- Calibration: not applied; confidence is labeled raw `predict_proba`.
- Scenario holdout: unavailable because the pilot intentionally contains one scenario.
- Export: `model.joblib`, `feature_schema.json`, `class_map.json`, `metrics.json`, `split_manifest.json`, and `training_metadata.json`.

These metrics prove execution only. Seven training sessions and seven test sessions are not enough for a performance, robustness, calibration, or generalization claim.

## Accidental-shortcut review

- Ports: seeded per attempt but encrypted inside ESP; no port is a model feature.
- Addresses: all classes share the same topology. The feature vector stores only normalized forward/reverse direction, not address values.
- Tunnel and rekey timing: excluded by the recorded workload window and strict ESP derivation.
- Service startup: performed outside the workload measurement; no service identity or startup timestamp enters features.
- Absolute timestamps, seeds, labels, run IDs, scenario names, and metadata: excluded from feature columns.
- Payload sizes and packet counts: seeded within each workload and are legitimate encrypted-traffic behavior, but controlled generators can still be easier than real applications. The full matrix and later external/OOD evaluation are required.
- Directionality: varied for VoIP, Messaging, Email transactions, and File Transfer; some workload semantics remain naturally asymmetric.
- Duration: seeded and overlapping where practical, but session duration is still a potentially strong behavioral feature. Report it transparently and evaluate ablations after the full matrix.
- IPsec balance: the pilot is baseline-only and cannot support scenario-generalization claims. `configs/prototype-v1.yaml` balances every class across all four scenarios.
- Network-profile balance: only `clean` is in scope; no network-profile comparison or robustness claim is made.
- Synthetic fingerprints: generator versions and resolved parameters are recorded. The three-session pilot demonstrates variation but is too small to rule out implementation fingerprints; this remains a known limitation for later real-world validation.

## First unattended dataset

`configs/prototype-v1.yaml` defines 28 class/scenario combinations with six independent sessions each, for 168 supervised sessions. Based on the retained pilot, expect approximately five minutes of aggregate workload-window capture, 45–60 minutes wall time including tunnel setup/rekey/validation, and about 1.2 GiB of retained artifacts if retry frequency and class mix are similar. Reserve at least 2 GiB.

```bash
sudo -v
sudo nohup python3 -m ipsec_sentinel.dataset generate configs/prototype-v1.yaml --resume \
  > dataset/prototype-v1-generation.log 2>&1 &
```

The command is safe on a new dataset and after interruption. It fingerprints the matrix, converts stale `RUNNING` attempts to `INCOMPLETE`, preserves failed attempts, skips successful slots, and rejects incompatible matrix changes.
