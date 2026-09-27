# Frontend visual and operational QA

Date: 2026-09-27  
Branch: `feat/ipsec-sentinel-frontend`  
Analyzer contract: `ipsec-sentinel.analysis/v1`

## Reviewed product story

The final Playwright story loads the genuine PFS-disabled guided artifact, follows tunnel reconstruction, opens the failing CHILD-SA PFS finding and retained strongSwan/XFRM evidence, verifies focus restoration, visits the ESP X-Ray and its `Payload visibility: 0%` disclosure, and finishes at the evidence-backed report. The secure-baseline and real video critical paths were also exercised.

The final rendered review answers the specification's three questions favorably:

1. The interface reads as a purpose-built protocol instrument rather than a generic card dashboard.
2. Configured, observed, derived, unknown, and AI-inferred values stay visually and semantically distinct enough for technical scrutiny.
3. The tunnel, payload-visibility statement, evidence actions, raw-confidence label, findings, and limitations explain the core innovation without narration.

## Browser and responsive evidence

- Browser: Playwright Chromium 1187 (`chrome-win/chrome.exe`), used as a local fallback after the current CDN browser download was unavailable.
- Reviewed viewports: 1440x900, 1280x800, 768x1024, and 390x844.
- Final screenshots: `final-1440x900.png`, `final-1280x800.png`, `final-768x1024.png`, and `final-390x844.png`.
- All four final judge-story tests passed with no unexpected console errors, page errors, failed requests, or document-level horizontal overflow.
- Compact navigation remains deliberately horizontally scrollable so every destination retains a readable touch target rather than collapsing into an ambiguous icon menu.

## Accessibility and interaction

- Automated axe scans reported zero serious or critical violations on the landing and analysis workspace.
- Primary intake, guided-demo choice, navigation, and evidence inspection are keyboard operable.
- Closing the evidence dialog restores focus to the evidence trigger.
- Critical status uses text and shape in addition to color; visible focus styling is retained.
- With `prefers-reduced-motion: reduce`, continuous packet/path animation is replaced by static direction markers.
- Report print rendering retains provenance and limitations while hiding interactive-only controls.

## Performance and bounded rendering

- Production build: CSS 51.43 kB (10.09 kB gzip); JavaScript 590.17 kB (182.03 kB gzip).
- Vite reports the JavaScript chunk above its 500 kB advisory threshold. This is acceptable for the local prototype, but route-level code splitting is a documented optimization for a production distribution.
- The real video demo contains 1,205 ESP packets and displays all 1,205 metadata points smoothly. Projection generation is deterministically capped at 1,500 displayed points for larger captures while analyzer totals remain unchanged.
- Local guided-demo content became interactive within the Playwright navigation/assertion timeout without network services. This was an operational observation, not a formal performance benchmark.

## Live analyzer proof

The loopback bridge was started from the production build and tested over HTTP with the exported model and the genuine `run_000013/encrypted.pcap` workload capture. `/api/health` returned `ok`; `/api/analyze` returned schema `ipsec-sentinel.analysis/v1`, 1,205 ESP packets, 1,205 X-Ray points, class `video`, `payload_decrypted: false`, and `confidence_kind: raw_uncalibrated`.

## Known prototype constraints

- The bridge is local-only and has no authentication; it must not be exposed beyond loopback.
- Live upload supports classic Ethernet/IPv4 PCAP, not PCAPNG or arbitrary link types.
- The bundled model is trained on a small controlled synthetic testbed. Probabilities are uncalibrated and do not establish real-world generalization or OOD rejection.
- The UI analyzes encrypted metadata and protocol evidence. It does not decrypt or reconstruct ESP payloads.
- The main bundle remains a single advisory-large JavaScript chunk.
