import { Activity, RotateCcw } from 'lucide-react'
import { Outlet } from 'react-router-dom'

import { useAnalysis } from '../../app/AnalysisContext'
import { Navigation } from './Navigation'

export function AppShell() {
  const { envelope, reset } = useAnalysis()
  const captureName = envelope?.analysis.capture.path.split('/').at(-1) ?? 'Capture'
  return (
    <div className="workspace-shell">
      <header className="workspace-topbar">
        <button className="brand brand-button" type="button" onClick={reset} aria-label="Return to capture intake">
          <span className="brand-mark" aria-hidden="true"><Activity size={17} /></span>
          <span>IPsec Sentinel</span>
        </button>
        <span className="capture-chip"><i />{captureName}</span>
        <button className="reset-button" type="button" onClick={reset}><RotateCcw size={14} />New analysis</button>
      </header>
      <Navigation />
      <main className="workspace-main"><Outlet /></main>
    </div>
  )
}
