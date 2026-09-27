import type { AnalysisV1 } from '../../lib/analysis-contract/types'
import { formatRawConfidence } from '../../lib/presentation/format'
import { ProvenanceMark } from '../evidence/ProvenanceMark'

export function TrafficIntelligence({
  traffic,
  esp,
}: {
  traffic: AnalysisV1['traffic_intelligence']
  esp: AnalysisV1['esp']
}) {
  const probabilities = Object.entries(traffic.probabilities).sort((left, right) => right[1] - left[1])
  const unknown = traffic.predicted_class === 'UNKNOWN' || traffic.state !== 'PREDICTED'
  return (
    <section className={`traffic-intelligence ${unknown ? 'is-uncertain' : ''}`} aria-labelledby="traffic-intelligence-heading">
      <header>
        <div><span className="section-kicker">Behavioral inference</span><h2 id="traffic-intelligence-heading">Traffic intelligence</h2></div>
        <ProvenanceMark provenance={traffic.provenance} />
      </header>
      <div className="prediction-lead">
        <span>{traffic.state === 'LOW_CONFIDENCE' ? 'Low confidence' : traffic.state === 'PREDICTED' ? 'Model result' : 'Insufficient evidence'}</span>
        <strong>{unknown ? 'Unknown traffic' : traffic.predicted_class.replace('_', ' ')}</strong>
        <p>{formatRawConfidence(traffic.raw_confidence)}</p>
        {traffic.reason && <small>{traffic.reason}</small>}
      </div>
      <div className="probability-list" aria-label="Class probability distribution">
        {probabilities.map(([label, probability]) => (
          <div key={label}>
            <span>{label.replace('_', ' ')} {(probability * 100).toFixed(1)}%</span>
            <i><b style={{ width: `${probability * 100}%` }} /></i>
          </div>
        ))}
      </div>
      <dl className="model-metadata">
        <div><dt>Model version</dt><dd>{traffic.model_version}</dd></div>
        <div><dt>Feature schema</dt><dd>{traffic.feature_schema_version}</dd></div>
        <div><dt>Observed ESP</dt><dd>{esp.packet_count.toLocaleString()} packets · {esp.bytes.toLocaleString()} bytes</dd></div>
      </dl>
      <div className="payload-contract"><strong>Payload visibility: 0%</strong><span>Classification uses only outer ESP timing, captured length, and direction.</span></div>
    </section>
  )
}
