import { useReducedMotion } from 'motion/react'
import { ArrowUpRight, BrainCircuit, ShieldCheck } from 'lucide-react'

import { useAnalysis } from '../AnalysisContext'
import { LiveTunnel } from '../../components/tunnel/LiveTunnel'
import { SecurityScore } from '../../components/security/SecurityScore'
import { ProvenanceMark } from '../../components/evidence/ProvenanceMark'
import { buildAnalysisView } from '../../lib/presentation/analysisView'

export function OverviewView() {
  const { envelope, inspectEvidence, navigate } = useAnalysis()
  const reducedMotion = useReducedMotion()
  if (!envelope) return null
  const { analysis, xray } = envelope
  const view = buildAnalysisView(analysis)
  const leadingFinding = view.findings.find((finding) => !['PASS', 'INFO'].includes(finding.status)) ?? view.findings[0]

  return (
    <div className="overview-view">
      <header className="view-heading">
        <div>
          <p className="eyebrow"><span />Validated encrypted session</p>
          <h1>Analysis overview</h1>
          <p>{analysis.summary.message}</p>
        </div>
        <div className="overview-summary">
          <span><i />Analysis complete</span>
          <strong>{analysis.capture.packet_count.toLocaleString()} packets · {analysis.capture.duration_seconds.toFixed(2)} s</strong>
        </div>
      </header>

      <div className="overview-layout">
        <LiveTunnel
          analysis={analysis}
          xray={xray}
          reducedMotion={Boolean(reducedMotion)}
          onInspectEvidence={inspectEvidence}
        />
        <aside className="intelligence-rail" aria-label="Session intelligence">
          <SecurityScore score={analysis.security_score} findings={analysis.findings} onSelectDeduction={inspectEvidence} />
          <section className="traffic-signal">
            <div className="signal-heading"><BrainCircuit size={16} /><span>Traffic intelligence</span><ProvenanceMark provenance={analysis.traffic_intelligence.provenance} compact /></div>
            <strong>{view.traffic.predictedClass === 'UNKNOWN' ? 'Unknown' : view.traffic.predictedClass.replace('_', ' ')}</strong>
            <p>{view.traffic.confidenceLabel}</p>
            <span className="payload-zero">{view.traffic.payloadLabel}</span>
            <button type="button" onClick={() => navigate('traffic')}>Inspect behavior <ArrowUpRight size={13} /></button>
          </section>
          {leadingFinding && (
            <section className={`priority-finding severity-${leadingFinding.severity.toLowerCase()}`}>
              <div><ShieldCheck size={16} /><span>Priority finding · {leadingFinding.severity}</span></div>
              <strong>{leadingFinding.title}</strong>
              <p>{leadingFinding.summary}</p>
              <button type="button" onClick={() => inspectEvidence(leadingFinding.evidence_ids, leadingFinding.title)}>Inspect supporting evidence</button>
            </section>
          )}
        </aside>
      </div>
    </div>
  )
}
