import { motion } from 'motion/react'

import type { XRayProjection } from '../../lib/analysis-contract/types'
import './traffic.css'

function feature(features: Record<string, number> | null, name: string): number | null {
  const value = features?.[name]
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

export function XRayRibbon({
  projection,
  features,
  payloadDecrypted,
  reducedMotion,
}: {
  projection: XRayProjection
  features: Record<string, number> | null
  payloadDecrypted: boolean
  reducedMotion: boolean
}) {
  const duration = Math.max(projection.duration_seconds, 0.000001)
  const maxLength = Math.max(...projection.packets.map((packet) => packet.length), 1)
  const density = Array.from({ length: 40 }, () => 0)
  for (const packet of projection.packets) {
    const bin = Math.min(39, Math.floor(packet.relative_time_seconds / duration * 40))
    density[bin] += 1
  }
  const maxDensity = Math.max(...density, 1)
  const burstCount = feature(features, 'burst_count')
  const packetRate = feature(features, 'packet_rate')
  const idleGaps = feature(features, 'idle_gap_50ms_count')

  return (
    <section className="xray-ribbon" aria-labelledby="xray-heading">
      <header className="xray-header">
        <div><span className="section-kicker">ESP temporal projection</span><h2 id="xray-heading">Encrypted traffic X-Ray</h2></div>
        <div className="visibility-zero"><strong>{payloadDecrypted ? 'Payload visibility available' : 'Payload visibility: 0%'}</strong><span>Behavioral metadata available</span></div>
      </header>
      {projection.packets.length ? (
        <div className="xray-canvas">
          <svg viewBox="0 0 1000 300" role="img" aria-label="ESP packet timing, direction, and captured size">
            <line className="xray-axis" x1="40" x2="960" y1="150" y2="150" />
            <text x="40" y="35">FORWARD</text><text x="40" y="274">REVERSE</text>
            {projection.packets.map((packet, index) => {
              const x = 40 + packet.relative_time_seconds / duration * 920
              const size = 7 + packet.length / maxLength * 38
              const y = packet.direction === 'forward' ? 118 : 182
              return (
                <motion.line
                  key={`${packet.relative_time_seconds}-${index}`}
                  data-testid="packet-mark"
                  data-direction={packet.direction}
                  className={`packet-mark is-${packet.direction}`}
                  x1={x}
                  x2={x}
                  y1={packet.direction === 'forward' ? y - size : y}
                  y2={packet.direction === 'forward' ? y : y + size}
                  initial={reducedMotion ? false : { opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: Math.min(index * 0.003, 0.45) }}
                />
              )
            })}
          </svg>
          <div className="density-track" aria-label="Packet density track">
            {density.map((count, index) => <i key={index} style={{ height: `${Math.max(8, count / maxDensity * 100)}%` }} />)}
          </div>
          <div className="xray-time"><span>0.000 s</span><span>{projection.duration_seconds.toFixed(3)} s</span></div>
        </div>
      ) : (
        <div className="aggregate-fallback">
          <strong>Aggregate-only view</strong>
          <p>No per-packet projection was provided. The interface will not invent a temporal packet sequence.</p>
        </div>
      )}
      <div className="xray-metrics">
        <div><span>Projection</span><strong>{projection.displayed_packet_count} of {projection.total_packet_count} packets shown</strong><small>{projection.sampled ? 'Deterministically sampled' : 'Complete projection'}</small></div>
        <div><span>Packet rate</span><strong>{packetRate === null ? 'Unknown' : `${packetRate.toFixed(1)} packets/s`}</strong></div>
        <div><span>Bursts</span><strong>{burstCount === null ? 'Unknown' : `${Math.round(burstCount)} bursts`}</strong></div>
        <div><span>Idle gaps ≥50 ms</span><strong>{idleGaps === null ? 'Unknown' : Math.round(idleGaps)}</strong></div>
      </div>
    </section>
  )
}
