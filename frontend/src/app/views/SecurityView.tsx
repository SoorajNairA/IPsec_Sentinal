import { FindingsPanel } from '../../components/security/FindingsPanel'
import { SecurityScore } from '../../components/security/SecurityScore'
import { useAnalysis } from '../AnalysisContext'

export function SecurityView() {
  const { envelope, inspectEvidence } = useAnalysis()
  if (!envelope) return null
  const { analysis } = envelope

  return (
    <div className="security-view">
      <header className="view-heading">
        <div>
          <p className="eyebrow"><span />Evidence-backed posture</p>
          <h1>Security findings</h1>
          <p>Prioritized observations grouped by the five scored security dimensions.</p>
        </div>
        <div className="overview-summary">
          <span><i />Rule evaluation complete</span>
          <strong>{analysis.findings.length} findings · score {analysis.security_score.total}/100</strong>
        </div>
      </header>
      <div className="security-view-layout">
        <aside aria-label="Security score summary">
          <SecurityScore score={analysis.security_score} findings={analysis.findings} onSelectDeduction={inspectEvidence} />
        </aside>
        <FindingsPanel findings={analysis.findings} onInspectEvidence={inspectEvidence} />
      </div>
    </div>
  )
}
