import type { Provenance } from '../../lib/analysis-contract/types'

const labels: Record<Provenance, string> = {
  OBSERVED: 'Observed',
  DERIVED: 'Derived',
  AI_INFERRED: 'AI-inferred',
  UNKNOWN: 'Unknown',
}

export function ProvenanceMark({ provenance, compact = false }: { provenance: Provenance; compact?: boolean }) {
  const label = labels[provenance]
  return (
    <span className={`provenance-mark provenance-${provenance.toLowerCase().replace('_', '-')} ${compact ? 'is-compact' : ''}`} aria-label={`${label} provenance`}>
      <i data-marker-shape aria-hidden="true" />
      <span>{label}</span>
    </span>
  )
}
