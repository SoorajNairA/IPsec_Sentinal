import { Search } from 'lucide-react'

import type { EvidenceRecord, Provenance } from '../../lib/analysis-contract/types'
import { ProvenanceMark } from './ProvenanceMark'

export type EvidenceFilter = 'ALL' | Provenance

function text(record: EvidenceRecord): string {
  return [record.id, record.description, record.protocol, record.source_component, record.raw_value, record.normalized_value]
    .map((value) => typeof value === 'string' ? value : JSON.stringify(value ?? ''))
    .join(' ')
    .toLowerCase()
}

export function EvidenceList({ evidence, filter, query, onSelect }: { evidence: EvidenceRecord[]; filter: EvidenceFilter; query: string; onSelect: (id: string) => void }) {
  const normalizedQuery = query.trim().toLowerCase()
  const records = evidence
    .filter((record) => filter === 'ALL' || record.provenance === filter)
    .filter((record) => !normalizedQuery || text(record).includes(normalizedQuery))
    .sort((left, right) => (left.timestamps_ns[0] ?? Number.MAX_SAFE_INTEGER) - (right.timestamps_ns[0] ?? Number.MAX_SAFE_INTEGER))

  if (!records.length) return <div className="evidence-empty"><Search size={18} /><strong>No matching evidence</strong><span>Change the provenance filter or search terms.</span></div>
  return (
    <div className="evidence-list" aria-live="polite">
      {records.map((record, index) => (
        <article key={record.id} className="evidence-row">
          <span className="evidence-sequence">{String(index + 1).padStart(2, '0')}</span>
          <div className="evidence-row-main"><code>{record.id}</code><strong>{record.description}</strong><small>{record.protocol ?? 'Protocol unavailable'} · {record.source_component}</small></div>
          <div className="evidence-row-reference"><span>{record.packet_numbers.length ? `Packets ${record.packet_numbers.join(', ')}` : 'No packet reference'}</span><code>{record.timestamps_ns.length ? `${(record.timestamps_ns[0] / 1e9).toFixed(6)} s` : 'No timestamp'}</code></div>
          <ProvenanceMark provenance={record.provenance} compact />
          <button type="button" onClick={() => onSelect(record.id)} aria-label={`Inspect evidence ${record.id}`}>Inspect evidence</button>
        </article>
      ))}
    </div>
  )
}
