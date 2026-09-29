import { ArrowRight, KeyRound, ScanSearch } from 'lucide-react'

import type { AnalysisV1 } from '../../lib/analysis-contract/types'
import { ProvenanceMark } from '../evidence/ProvenanceMark'
import './tunnel.css'

type Ike = AnalysisV1['ike']
type Association = AnalysisV1['security_associations'][number]
type Pfs = AnalysisV1['pfs']

export function SaTimeline({
  ike,
  associations,
  pfs,
  onInspectEvidence,
}: {
  ike: Ike
  associations: Association[]
  pfs: Pfs
  onInspectEvidence: (ids: readonly string[], valueLabel?: string) => void
}) {
  const ordered = [...associations].sort((left, right) => left.first_timestamp_ns - right.first_timestamp_ns)
  return (
    <section className="sa-timeline" aria-labelledby="sa-timeline-heading">
      <header>
        <div><span className="section-kicker">Negotiation chronology</span><h2 id="sa-timeline-heading">Security Association timeline</h2></div>
        <span className="timeline-count">{ordered.length} CHILD SA{ordered.length === 1 ? '' : 's'}</span>
      </header>
      <div className="ike-anchor">
        <KeyRound size={18} />
        <div><span>{ike.version} established</span><strong>{ike.initiator_spi} / {ike.responder_spi}</strong></div>
        <dl><div><dt>Cipher</dt><dd>{String(ike.encryption.normalized)}</dd></div><div><dt>DH group</dt><dd>{String(ike.dh_group.normalized)}</dd></div></dl>
      </div>
      {pfs && <div className={`session-pfs state-${pfs.state}`}><div><span>Session PFS {pfs.state}</span><small>{pfs.explanation}</small></div><ProvenanceMark provenance={pfs.provenance} compact />{pfs.evidence_ids.length > 0 && <button type="button" onClick={() => onInspectEvidence(pfs.evidence_ids, `Session PFS ${pfs.state}`)}><ScanSearch size={14} />Inspect PFS evidence</button>}</div>}
      <div className="sa-events">
        {ordered.map((association, index) => {
          const evidenceId = association.rekey_evidence_id
          const pfsState = association.pfs.state
          return (
            <article className="sa-event" key={`${association.spi}-${association.source}-${association.destination}`}>
              <div className="event-index"><span>{String(index + 1).padStart(2, '0')}</span><i /></div>
              <div className="sa-event-body">
                <header>
                  <div><span>{association.sa_type.replaceAll('_', ' ')}</span><strong>{association.spi}</strong></div>
                  <ProvenanceMark provenance={association.rekey_provenance} compact />
                </header>
                <div className="sa-direction"><code>{association.source}</code><ArrowRight size={14} /><code>{association.destination}</code></div>
                <dl>
                  <div><dt>First packet</dt><dd>#{association.first_packet_number}</dd></div>
                  <div><dt>Packets / bytes</dt><dd>{association.packet_count.toLocaleString()} / {association.bytes.toLocaleString()}</dd></div>
                  <div><dt>Predecessor</dt><dd>{association.predecessor_spi ?? 'Initial SA'}</dd></div>
                  <div><dt>Successor</dt><dd>{association.successor_spi ?? 'Current / final'}</dd></div>
                </dl>
                <div className={`sa-pfs state-${pfsState}`}><span>PFS {pfsState} for this SA</span><small>{pfsState === 'unknown' ? 'No association-specific CHILD-SA DH conclusion is available.' : 'Association-level PFS evidence is present.'}</small></div>
                {evidenceId && <button type="button" onClick={() => onInspectEvidence([evidenceId], `Rekey to ${association.spi}`)} aria-label={`Inspect rekey evidence for ${association.spi}`}><ScanSearch size={14} />Inspect rekey evidence</button>}
              </div>
            </article>
          )
        })}
      </div>
      <div className="sa-table-wrap">
        <table className="sa-table">
          <caption>Technical CHILD SA record</caption>
          <thead><tr><th>SPI</th><th>Direction</th><th>First packet</th><th>Unique packets</th><th>Successor</th></tr></thead>
          <tbody>{ordered.map((association) => <tr key={`row-${association.spi}`}><td><code>{association.spi}</code></td><td>{association.source} → {association.destination}</td><td>#{association.first_packet_number}</td><td>{association.unique_packet_count}</td><td><code>{association.successor_spi ?? '—'}</code></td></tr>)}</tbody>
        </table>
      </div>
    </section>
  )
}
