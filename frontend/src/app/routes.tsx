import type { ReactNode } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'

import { AppShell } from '../components/shell/AppShell'
import { Landing } from '../components/shell/Landing'
import { useAnalysis } from './AnalysisContext'
import { useLiveLab } from './LiveLabContext'
import { LiveLabView } from './views/LiveLabView'
import { OverviewView } from './views/OverviewView'
import { EvidenceView } from './views/EvidenceView'
import { ReportView } from './views/ReportView'
import { SecurityView } from './views/SecurityView'
import { TrafficView } from './views/TrafficView'
import { TunnelView } from './views/TunnelView'

function LandingRoute() {
  const { status } = useAnalysis()
  if (status === 'READY') return <Navigate to="/analysis/overview" replace />
  return <Landing />
}

function ReadyGuard() {
  const { envelope, status } = useAnalysis()
  if (status !== 'READY' || !envelope) return <Navigate to="/" replace />
  return <AppShell />
}

function LiveResult({ children }: { children: ReactNode }) {
  const { analysis } = useLiveLab()
  return analysis ? children : <LiveLabView />
}

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<LandingRoute />} />
      <Route path="/live" element={<AppShell mode="live" />}>
        <Route index element={<LiveLabView />} />
        <Route path="tunnel" element={<LiveLabView />} />
        <Route path="traffic" element={<LiveResult><TrafficView /></LiveResult>} />
        <Route path="security" element={<LiveResult><SecurityView /></LiveResult>} />
        <Route path="evidence" element={<LiveResult><EvidenceView /></LiveResult>} />
        <Route path="report" element={<LiveResult><ReportView /></LiveResult>} />
      </Route>
      <Route path="/analysis" element={<ReadyGuard />}>
        <Route index element={<Navigate to="overview" replace />} />
        <Route path="overview" element={<OverviewView />} />
        <Route path="tunnel" element={<TunnelView />} />
        <Route path="traffic" element={<TrafficView />} />
        <Route path="security" element={<SecurityView />} />
        <Route path="evidence" element={<EvidenceView />} />
        <Route path="report" element={<ReportView />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
