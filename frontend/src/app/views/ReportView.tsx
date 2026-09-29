import { AnalysisReport } from '../../components/report/AnalysisReport'
import { buildAnalysisView } from '../../lib/presentation/analysisView'
import { useAnalysis } from '../AnalysisContext'

export function ReportView() {
  const { envelope, inspectEvidence, languageMode, setLanguageMode } = useAnalysis()
  if (!envelope) return null
  return <div className="report-view"><header className="view-heading screen-only"><div><p className="eyebrow"><span />Export-ready analysis</p><h1>Analysis report</h1><p>The same evidence-backed conclusions, composed for review and print without adding new claims.</p></div><div className="language-toggle" role="group" aria-label="Explanation language"><button type="button" className={languageMode === 'PLAIN' ? 'is-active' : ''} onClick={() => setLanguageMode('PLAIN')}>Plain English</button><button type="button" className={languageMode === 'TECHNICAL' ? 'is-active' : ''} onClick={() => setLanguageMode('TECHNICAL')}>Technical</button></div></header><AnalysisReport analysis={envelope.analysis} analysisView={buildAnalysisView(envelope.analysis)} mode={languageMode === 'PLAIN' ? 'plain' : 'technical'} onInspectEvidence={inspectEvidence} /></div>
}
