# Live Lab local verification evidence

Date: 2026-09-29  
Branch: `feat/ipsec-sentinel-live-lab`  
Scope: Phase A local Live Lab only; no Google Cloud resources were accessed or created.

## Architecture verified

The local product uses one loopback-only Sentinel Agent, REST commands, and a
replayable Server-Sent Events stream. The agent owns one active session at a
time and persists ordered, timestamped events as JSONL. Event IDs support
`Last-Event-ID` replay, and a reconnecting frontend rebuilds its state from
backend events rather than timers.

`LocalLabProvider` adapts the existing `SecureSession`; it does not implement a
second IPsec lifecycle. The same namespace, strongSwan, capture, traffic,
rekey, XFRM validation, and cleanup machinery used by the validated dataset
factory therefore remains the privileged execution boundary. A process-wide
host lock and an ownership journal prevent a second agent or session from
claiming the same lab resources. Startup recovery removes only resources whose
recorded identities still match and preserves regular diagnostic files.

Capture begins before IKE establishment and remains active through interactive
traffic and rekey operations. Full-session analysis uses
`full-evidence.pcap`. ML inference snapshots only the latest completed
workload interval into `encrypted.pcap`, so sequential Ping and Video actions
cannot form one mixed prediction window.

The explicit session state machine rejects invalid commands. Mystery scenario
identity and configuration are redacted centrally from session snapshots,
events, evidence, analysis, and errors until an explicit reveal command.

## Real local run

The browser-driven retained run is:

`/home/black/ipsec-sentinel-playwright-live/SNT-31065BA9`

The real workflow performed the following actions against the local Linux
namespace/strongSwan testbed:

1. created an isolated sandbox and started capture;
2. established a real IKEv2/CHILD SA and verified XFRM state and policy;
3. rejected a second concurrent session;
4. ran ICMP and Video interactively;
5. streamed observed ESP activity to the browser;
6. classified the completed Video workload window;
7. triggered a real CHILD-SA rekey and evaluated fresh-DH/PFS evidence;
8. analyzed the full session without losing coherent tunnel state;
9. reloaded the browser and restored state through SSE replay;
10. disconnected and completed idempotent cleanup.

The persisted session finished with these values:

| Evidence | Result |
|---|---:|
| Session state | `COMPLETE` |
| Tunnel state | `DISCONNECTED` |
| Capture state | `SEALED` |
| Cleanup state | `SUCCEEDED` |
| Persisted events | 52 |
| Analysis state | `COMPLETE` |
| Security score | 100 |
| PFS assessment | `VERIFIED` |
| Latest workload | `video` |
| ML prediction | `video` |
| Raw confidence | 0.921875 |

## Capture separation

Independent parsing of the retained run produced:

| Capture | ESP packets | UDP/500 | Other non-ESP | Total packets | Bytes |
|---|---:|---:|---:|---:|---:|
| `full-evidence.pcap` | 1,201 | 8 | 0 | 1,209 | 1,465,891 |
| `encrypted.pcap` | 1,191 | 0 | 0 | 1,191 | 1,461,922 |

`full-evidence.pcap` retains IKE plus the ESP session and rekey chronology.
`encrypted.pcap` contains ESP only: zero IKE, zero UDP/500, zero UDP/4500,
and zero unrelated plaintext packets. The ML result names this workload-window
artifact as its provenance; full-session protocol/security analysis continues
to use the complete evidence capture.

## Verification runs

The final local gate covers:

- the complete Python unit/integration suite;
- the complete frontend Vitest suite, ESLint, and production build;
- the privileged Phase 1 secure-baseline regression;
- privileged Phase 2 ICMP, Web, and Video dataset regressions;
- the privileged interactive Live Lab integration;
- the real-agent Playwright flow and the deterministic browser suite;
- an independent post-run namespace, link, process, and runtime-directory
  cleanup audit.

The final ordinary suites completed with 324 Python tests passing (14
expected privileged/real-dataset skips) and 155 frontend tests passing across
18 files. Frontend lint and the production TypeScript/Vite build also passed;
Vite emitted only its advisory that the main minified bundle exceeds 500 kB.

The privileged checkpoints recorded:

| Checkpoint | Result |
|---|---:|
| Phase 1 secure baseline | 1 passed in 6.745 s |
| Phase 2 ICMP/Web/Video | 3 passed in 33.760 s |
| Interactive Live Lab integration | 1 passed in 14.825 s |
| Real-agent Playwright | 1 passed in 41.6 s |
| Deterministic Playwright | 21 passed |

The final cleanup audit found no lab network namespaces, no lab veth links,
no lab-owned strongSwan or tcpdump process, and no `/run/ipsec-sentinel`
runtime tree. A pre-existing system `charon-systemd` process was not owned by
the test and was correctly left untouched.

## Failure and recovery checks

Automated coverage verifies command/session acceptance races, invalid command
rejection, ownership retention after failed cleanup, retryable idempotent
cleanup, stale Unix-socket recovery, process identity checks that survive
`exec` without accepting PID reuse, preservation of runtime diagnostics, and
safe recovery after interruption. A failed attempt keeps its primary error and
cleanup outcome separately.

## Leakage and provenance review

- No frontend transition is timer-generated; state and progress originate in
  completed backend actions or parsed evidence.
- Mystery ground truth remains server-side and redacted until reveal.
- Traffic inference is absent until a workload window has completed.
- The X-Ray view consumes workload-window packet sizes, timing, direction, and
  burst data; it does not claim decrypted payload visibility.
- Rekey and PFS labels require the existing observed SA/XFRM evidence and are
  not inferred from configuration alone.
- The frontend cannot roll back to a delayed snapshot older than events it has
  already applied.

## Current limitations

- Real execution requires Linux root capabilities, network namespaces, XFRM,
  strongSwan, tcpdump, and the installed model artifact; the Windows frontend
  alone cannot provide the lab.
- The local validation path uses native ESP. A cloud path behind local/public
  NAT is expected to use NAT-T and must be independently validated.
- One active Live Lab session is supported by design for the prototype.
- An agent-process restart safely recovers stale owned resources and retains
  evidence, but it does not resurrect a dead interactive tunnel. The frontend
  must create a new session after such a restart.
- `GcpLabProvider` provisioning and cloud transport are intentionally outside
  this Phase A evidence set.
