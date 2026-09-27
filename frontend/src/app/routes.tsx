import { Navigate, Route, Routes } from 'react-router-dom'

import { AppShell } from '../components/shell/AppShell'
import { Landing } from '../components/shell/Landing'
import { useAnalysis } from './AnalysisContext'
import { OverviewView } from './views/OverviewView'

const viewHeadings = {
  overview: ['Analysis overview', 'Tunnel health, negotiated security, and evidence coverage at a glance.'],
  tunnel: ['Tunnel reconstruction', 'IKE negotiation and Security Association chronology.'],
  traffic: ['Traffic intelligence', 'Encrypted ESP behavior and model inference.'],
  security: ['Security findings', 'Evidence-backed posture and prioritized recommendations.'],
  evidence: ['Evidence ledger', 'Observed, derived, inferred, and unknown claims.'],
  report: ['Analysis report', 'A clear, export-ready explanation of the session.'],
} as const

function PlaceholderView({ view }: { view: keyof typeof viewHeadings }) {
  const [heading, description] = viewHeadings[view]
  return (
    <section className="view-placeholder">
      <p className="eyebrow"><span />Validated analysis</p>
      <h1>{heading}</h1>
      <p>{description}</p>
    </section>
  )
}

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
        {(Object.keys(viewHeadings).filter((view) => view !== 'overview') as Array<keyof typeof viewHeadings>).map((view) => (
          <Route key={view} path={view} element={<PlaceholderView view={view} />} />
        ))}
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
