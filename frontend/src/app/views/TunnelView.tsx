import { SaTimeline } from '../../components/tunnel/SaTimeline'
import { useAnalysis } from '../AnalysisContext'

export function TunnelView() {
  const { envelope, inspectEvidence } = useAnalysis()
  if (!envelope) return null
  const { analysis } = envelope
  return <div className="tunnel-view"><header className="view-heading"><div><p className="eyebrow"><span />Session reconstruction</p><h1>Tunnel reconstruction</h1><p>IKE establishment, directional CHILD SAs, successor relationships, and rekey evidence in observed order.</p></div><div className="overview-summary"><span><i />{analysis.summary.ipsec}</span><strong>{analysis.peers.initiator} → {analysis.peers.responder}</strong></div></header><SaTimeline ike={analysis.ike} associations={analysis.security_associations} pfs={analysis.pfs} onInspectEvidence={inspectEvidence} /></div>
}
