import { useReducedMotion } from 'motion/react'

import { TrafficIntelligence } from '../../components/traffic/TrafficIntelligence'
import { XRayRibbon } from '../../components/traffic/XRayRibbon'
import { useAnalysis } from '../AnalysisContext'

export function TrafficView() {
  const { envelope } = useAnalysis()
  const reducedMotion = useReducedMotion()
  if (!envelope) return null
  const { analysis, xray } = envelope

  return (
    <div className="traffic-view">
      <header className="view-heading">
        <div>
          <p className="eyebrow"><span />Outer ESP behavior</p>
          <h1>Traffic intelligence</h1>
          <p>Timing, captured length, and direction are projected without decrypting payload content.</p>
        </div>
        <div className="overview-summary">
          <span><i />ESP-only analysis</span>
          <strong>{analysis.esp.packet_count.toLocaleString()} packets · {analysis.esp.duration_seconds.toFixed(2)} s</strong>
        </div>
      </header>
      <div className="traffic-view-layout">
        <XRayRibbon
          projection={xray}
          features={analysis.esp.features}
          payloadDecrypted={analysis.esp.payload_decrypted}
          reducedMotion={Boolean(reducedMotion)}
        />
        <TrafficIntelligence traffic={analysis.traffic_intelligence} esp={analysis.esp} />
      </div>
    </div>
  )
}
