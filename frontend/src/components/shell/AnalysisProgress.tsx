import { Activity } from 'lucide-react'

import { ANALYSIS_STAGES, useAnalysis } from '../../app/AnalysisContext'

export function AnalysisProgress() {
  const { stageIndex } = useAnalysis()
  return (
    <main className="analysis-progress" aria-live="polite">
      <div className="progress-mark"><Activity size={24} /></div>
      <p className="eyebrow"><span />Local analyzer active</p>
      <h1>Analyzing encrypted session</h1>
      <p>Technical results appear only after the analyzer response passes the strict v1 contract.</p>
      <ol className="stage-list">
        {ANALYSIS_STAGES.map((stage, index) => (
          <li key={stage} className={index < stageIndex ? 'is-complete' : index === stageIndex ? 'is-active' : ''}>
            <span>{String(index + 1).padStart(2, '0')}</span>{stage}
          </li>
        ))}
      </ol>
    </main>
  )
}
