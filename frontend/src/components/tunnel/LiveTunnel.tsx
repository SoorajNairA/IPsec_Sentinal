import { motion } from 'motion/react'

import type { AnalysisV1, XRayProjection } from '../../lib/analysis-contract/types'
import { ProvenanceMark } from '../evidence/ProvenanceMark'
import './tunnel.css'

type InspectEvidence = (ids: readonly string[], valueLabel?: string) => void

function value(input: unknown): string {
  return input === null || input === undefined || input === 'UNKNOWN' ? 'Unknown' : String(input)
}

export function LiveTunnel({
  analysis,
  xray,
  reducedMotion,
  onInspectEvidence,
}: {
  analysis: AnalysisV1
  xray: XRayProjection
  reducedMotion: boolean
  onInspectEvidence: InspectEvidence
}) {
  const counts = Object.values(analysis.esp.direction_counts)
  const forward = counts[0] ?? 0
  const reverse = counts[1] ?? 0
  const packetRate = analysis.esp.features?.packet_rate ?? (
    analysis.esp.duration_seconds ? analysis.esp.packet_count / analysis.esp.duration_seconds : 0
  )
  const cipher = value(analysis.ike.encryption.normalized)
  const dh = value(analysis.ike.dh_group.normalized)
  const pfsState = analysis.pfs?.state ?? 'unknown'
  const pfsLabel = `PFS ${pfsState}`
  const pfsEvidence = analysis.pfs?.evidence_ids ?? []
  const rekey = analysis.security_associations.find((sa) => sa.successor_spi || sa.rekey_evidence_id)
  const duration = Math.max(0.8, Math.min(3.2, 18 / Math.max(packetRate, 1)))
  const cipherEvidence = analysis.ike.encryption.evidence_id ? [analysis.ike.encryption.evidence_id] : []
  const dhEvidence = analysis.ike.dh_group.evidence_id ? [analysis.ike.dh_group.evidence_id] : []

  return (
    <section className="live-tunnel" aria-labelledby="tunnel-heading">
      <header className="tunnel-header">
        <div><span className="section-kicker">Live tunnel reconstruction</span><h2 id="tunnel-heading">Encrypted path</h2></div>
        <span className={`tunnel-state ${analysis.protocols.ipsec_detected ? 'is-live' : ''}`}>
          {analysis.protocols.ipsec_detected ? 'IPsec detected' : 'IPsec not detected'}
        </span>
      </header>

      <div className="tunnel-stage">
        <div className="tunnel-grid" aria-hidden="true" />
        <svg viewBox="0 0 1000 360" role="img" aria-label={`Encrypted tunnel from ${analysis.peers.initiator} to ${analysis.peers.responder}`}>
          <defs>
            <linearGradient id="tunnel-energy" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0" stopColor="#4d7f8d" />
              <stop offset="0.5" stopColor="#a8e6f5" />
              <stop offset="1" stopColor="#4d7f8d" />
            </linearGradient>
          </defs>
          <g className="tunnel-endpoint" transform="translate(108 180)">
            <circle r="51" /><circle r="35" /><path d="M-13 -5h26M-13 6h26M-7-13v26M7-13v26" />
            <text y="82" textAnchor="middle">INITIATOR</text>
            <text y="105" textAnchor="middle" className="endpoint-address">{analysis.peers.initiator}</text>
          </g>
          <g className="tunnel-endpoint" transform="translate(892 180)">
            <circle r="51" /><circle r="35" /><path d="M-13 -5h26M-13 6h26M-7-13v26M7-13v26" />
            <text y="82" textAnchor="middle">RESPONDER</text>
            <text y="105" textAnchor="middle" className="endpoint-address">{analysis.peers.responder}</text>
          </g>
          <path className="tunnel-outer" d="M160 180 C320 104 680 104 840 180 C680 256 320 256 160 180Z" />
          <motion.path
            className="tunnel-core"
            d="M160 180 C350 146 650 146 840 180"
            initial={reducedMotion ? false : { pathLength: 0, opacity: 0 }}
            animate={{ pathLength: 1, opacity: 1 }}
            transition={{ duration: 0.8, ease: 'easeOut' }}
          />
          <path className="tunnel-return" d="M840 180 C650 214 350 214 160 180" />
          <g data-testid="tunnel-flow" data-motion={reducedMotion ? 'reduced' : 'active'}>
            {reducedMotion ? (
              <>
                <path className="direction-glyph" d="M420 145l12 7-12 7" />
                <path className="direction-glyph" d="M580 215l-12-7 12-7" />
              </>
            ) : (
              <>
                <motion.circle className="flow-packet" r="4" cx="185" cy="160" animate={{ x: [0, 630] }} transition={{ duration, repeat: Infinity, ease: 'linear' }} />
                {reverse > 0 && <motion.circle className="flow-packet is-return" r="3" cx="815" cy="200" animate={{ x: [0, -630] }} transition={{ duration: duration * 1.25, repeat: Infinity, ease: 'linear' }} />}
              </>
            )}
          </g>
          {rekey && (
            <g className="rekey-marker" transform="translate(620 145)" aria-label="CHILD_SA rekey observed">
              <circle r="13" /><path d="M-5 0h10M2-4l4 4-4 4" /><text y="-22" textAnchor="middle">REKEY</text>
            </g>
          )}
        </svg>
        <div className="tunnel-negotiation">
          <div><span>Negotiation</span><strong>{analysis.ike.version}</strong></div>
          <div><span>ESP activity</span><strong>{packetRate.toFixed(1)} packets/s</strong></div>
          <div aria-label={`${forward} forward and ${reverse} reverse ESP packets`}><span>Direction</span><strong>{forward} → · {reverse} ←</strong></div>
          <div><span>Projection</span><strong>{xray.displayed_packet_count} / {xray.total_packet_count} packets</strong></div>
        </div>
      </div>

      <div className={`key-exchange-layer ${pfsState === 'disabled' ? 'is-warning' : ''}`} data-testid="key-exchange-layer">
        <div className="key-property">
          <span>Cipher</span><strong>{cipher}</strong>
          <ProvenanceMark provenance={analysis.ike.encryption.provenance} compact />
          {cipherEvidence.length > 0 && <button className="evidence-action" type="button" onClick={() => onInspectEvidence(cipherEvidence, cipher)}>How do you know?</button>}
        </div>
        <div className="key-property">
          <span>DH group</span><strong>{dh}</strong>
          <ProvenanceMark provenance={analysis.ike.dh_group.provenance} compact />
          {dhEvidence.length > 0 && <button className="evidence-action" type="button" onClick={() => onInspectEvidence(dhEvidence, dh)}>How do you know?</button>}
        </div>
        <div className="key-property pfs-property">
          <span>Key exchange</span><strong>{pfsLabel}</strong>
          <ProvenanceMark provenance={analysis.pfs?.provenance ?? 'UNKNOWN'} compact />
          {pfsState === 'disabled' && <p>Forward secrecy is not active for CHILD_SA keys.</p>}
          {pfsEvidence.length > 0 && (
            <button type="button" onClick={() => onInspectEvidence(pfsEvidence, pfsLabel)} aria-label="Inspect PFS evidence">Inspect evidence</button>
          )}
        </div>
      </div>
    </section>
  )
}
