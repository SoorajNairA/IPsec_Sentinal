import { ScanSearch } from 'lucide-react'

import { useAnalysis } from '../../app/AnalysisContext'

export function EvidenceAction({
  evidenceIds,
  label = 'How do you know?',
  valueLabel,
}: {
  evidenceIds: readonly string[]
  label?: string
  valueLabel?: string
}) {
  const { inspectEvidence } = useAnalysis()
  return (
    <button className="evidence-action" type="button" onClick={() => inspectEvidence(evidenceIds, valueLabel)}>
      <ScanSearch size={14} aria-hidden="true" />
      {label}
    </button>
  )
}
