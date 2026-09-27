import { Navigate, Route, Routes } from 'react-router-dom'

import { AppShell } from '../components/shell/AppShell'
import { Landing } from '../components/shell/Landing'
import { useAnalysis } from './AnalysisContext'
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

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<LandingRoute />} />
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
