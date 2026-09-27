import { Search } from 'lucide-react'
import { useState } from 'react'

import { EvidenceList, type EvidenceFilter } from '../../components/evidence/EvidenceList'
import { useAnalysis } from '../AnalysisContext'

const filters: Array<{ value: EvidenceFilter; label: string }> = [{ value: 'ALL', label: 'All' }, { value: 'OBSERVED', label: 'Observed' }, { value: 'DERIVED', label: 'Derived' }, { value: 'AI_INFERRED', label: 'AI-inferred' }, { value: 'UNKNOWN', label: 'Unknown' }]

export function EvidenceView() {
  const { envelope, inspectEvidence } = useAnalysis()
  const [filter, setFilter] = useState<EvidenceFilter>('ALL')
  const [query, setQuery] = useState('')
  if (!envelope) return null
  return <div className="evidence-view"><header className="view-heading"><div><p className="eyebrow"><span />Auditable provenance</p><h1>Evidence ledger</h1><p>Direct observations, deterministic derivations, model inferences, and explicit unknowns retained as separate claims.</p></div><div className="overview-summary"><span><i />Validated records</span><strong>{envelope.analysis.evidence.length} evidence items</strong></div></header><div className="evidence-toolbar"><div className="evidence-filters" role="group" aria-label="Filter evidence by provenance">{filters.map((item) => <button key={item.value} type="button" className={filter === item.value ? 'is-active' : ''} onClick={() => setFilter(item.value)}>{item.label}</button>)}</div><label><Search size={14} /><span className="visually-hidden">Search evidence</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search ID, protocol, source, or value" /></label></div><EvidenceList evidence={envelope.analysis.evidence} filter={filter} query={query} onSelect={(id) => inspectEvidence([id], id)} /></div>
}
