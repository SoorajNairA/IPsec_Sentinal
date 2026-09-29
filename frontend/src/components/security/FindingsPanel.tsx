import { ChevronDown, ScanSearch } from 'lucide-react'

import type { AnalysisV1, ScoreCategoryName } from '../../lib/analysis-contract/types'
import { findingCategory } from '../../lib/presentation/analysisView'
import { ProvenanceMark } from '../evidence/ProvenanceMark'

const categories: ScoreCategoryName[] = [
  'Cryptography',
  'Key Exchange / PFS',
  'Security Association Hygiene',
  'Replay / Protocol Protections',
  'Metadata / Privacy Exposure',
]

const severityOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }

export function FindingsPanel({
  findings,
  onInspectEvidence,
}: {
  findings: AnalysisV1['findings']
  onInspectEvidence: (ids: readonly string[], valueLabel?: string) => void
}) {
  const sorted = [...findings].sort((left, right) => (severityOrder[left.severity] ?? 99) - (severityOrder[right.severity] ?? 99))
  return (
    <div className="findings-panel">
      {categories.map((category) => {
        const items = sorted.filter((finding) => findingCategory(finding.rule_id) === category)
        return (
          <section className="finding-category" key={category}>
            <header><h2>{category}</h2><span>{items.length} finding{items.length === 1 ? '' : 's'}</span></header>
            {items.length ? items.map((finding) => {
              const quiet = finding.status === 'PASS' || finding.severity === 'INFO'
              return (
                <details className={`finding severity-${finding.severity.toLowerCase()} ${quiet ? 'is-quiet' : ''}`} key={finding.rule_id} open={!quiet}>
                  <summary data-testid="finding-summary">
                    <span className="severity-symbol" aria-hidden="true" />
                    <span><strong>{finding.title}</strong><small>{finding.summary}</small></span>
                    <ProvenanceMark provenance={finding.provenance} compact />
                    <ChevronDown size={15} aria-hidden="true" />
                  </summary>
                  <div className="finding-detail">
                    <dl>
                      <div><dt>Technical explanation</dt><dd>{finding.technical_explanation}</dd></div>
                      <div><dt>Potential impact</dt><dd>{finding.impact}</dd></div>
                      <div><dt>Recommendation</dt><dd>{finding.recommendation}</dd></div>
                    </dl>
                    {finding.evidence_ids.length > 0 && (
                      <button type="button" onClick={() => onInspectEvidence(finding.evidence_ids, finding.title)} aria-label={`Inspect evidence for ${finding.title}`}>
                        <ScanSearch size={14} />Inspect supporting evidence
                      </button>
                    )}
                  </div>
                </details>
              )
            }) : <p className="no-findings">No analyzer findings in this category.</p>}
          </section>
        )
      })}
    </div>
  )
}
