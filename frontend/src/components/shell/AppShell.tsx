import { Activity, RotateCcw } from 'lucide-react'
import { Outlet } from 'react-router-dom'

import { useAnalysis } from '../../app/AnalysisContext'
import { useLiveLab } from '../../app/LiveLabContext'
import { EvidenceDrawer } from '../evidence/EvidenceDrawer'
import { Navigation } from './Navigation'

export function AppShell({ mode = 'analysis' }: { mode?: 'analysis' | 'live' }) {
  const { envelope, reset } = useAnalysis()
  const live = useLiveLab()
  const captureName = mode === 'live'
    ? live.session?.session_id ?? 'Live Lab'
    : envelope?.analysis.capture.path.split('/').at(-1) ?? 'Capture'
  const exit = () => {
    if (mode === 'analysis') {
      reset()
      return
    }
    if (live.session && live.session.state !== 'COMPLETE' && live.session.allowed_actions.includes('DISCONNECT')) {
      void live.disconnect()
      return
    }
    live.reset()
    reset()
  }
  return (
    <div className="workspace-shell">
      <header className="workspace-topbar">
        <button className="brand brand-button" type="button" onClick={exit} aria-label={mode === 'live' ? 'Exit Live Lab' : 'Return to capture intake'}>
          <span className="brand-mark" aria-hidden="true"><Activity size={17} /></span>
          <span>IPsec Sentinel</span>
        </button>
        <span className="capture-chip"><i />{captureName}</span>
        <button className="reset-button" type="button" onClick={exit}><RotateCcw size={14} />{mode === 'live' ? 'Exit lab' : 'New analysis'}</button>
      </header>
      <Navigation />
      <main className="workspace-main"><Outlet /></main>
      <EvidenceDrawer />
    </div>
  )
}
