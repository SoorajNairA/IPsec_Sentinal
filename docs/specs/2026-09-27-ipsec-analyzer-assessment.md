# IPsec Analyzer and Assessment Design

The analyzer consumes one supplied PCAP and emits a versioned, frontend-safe
analysis. Deterministic parsing owns capture validation, protocol/peer/SPI/IKE
evidence, ESP statistics, SA chronology, findings, and scoring. The existing
Extra Trees model is optional and is used only for encrypted-traffic inference.

Every conclusion is represented by an evidence record with provenance
`OBSERVED`, `DERIVED`, `AI_INFERRED`, or `UNKNOWN`. Passive packet evidence is
never upgraded from unknown by guesswork. In particular, an ESP SPI change is
rekey evidence, not PFS evidence. Adjacent controlled-lab artifacts may supply
explicit configured-versus-observed verification, but their source remains
separate from packet observations.

The implementation performs one capture read into an immutable parsed
representation. Focused analyzers consume that representation for protocols,
IKEv2 clear-text SA proposals/selections, ESP behavior, and SA chronology.
Classic Ethernet PCAP is fully parsed; PCAPNG is detected and reported as a
structured unsupported-format result until a safe parser is implemented.

The JSON contract is `ipsec-sentinel.analysis/v1` and always contains capture,
summary, peers, protocols, IKE, security associations, ESP, traffic
intelligence, evidence, findings, security score, and limitations. Unknown
properties do not incur score deductions; category output exposes assessed and
unassessed weight. Payload decryption is always false.

The CLI is `python3 -m ipsec_sentinel.analyze CAPTURE [--json PATH]
[--model-dir PATH] [--evidence-dir PATH]`. Human output is concise. Errors such
as missing, empty, malformed, non-IPsec, and insufficient-ESP inputs are
structured and do not produce Python tracebacks during normal CLI use.

The milestone excludes decryption, probing, dataset regeneration, model
training, frontend work, and claims of production generalization.
