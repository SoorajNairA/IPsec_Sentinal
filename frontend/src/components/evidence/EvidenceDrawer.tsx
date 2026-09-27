import * as Dialog from '@radix-ui/react-dialog'
import * as ScrollArea from '@radix-ui/react-scroll-area'
import { FileSearch, X } from 'lucide-react'

import { useAnalysis } from '../../app/AnalysisContext'
import type { EvidenceRecord } from '../../lib/analysis-contract/types'
import { ProvenanceMark } from './ProvenanceMark'
import './evidence.css'

function show(value: unknown): string {
  if (value === null || value === undefined || value === '') return 'Not available'
  return typeof value === 'string' ? value : JSON.stringify(value)
}

function packets(record: EvidenceRecord): string {
  return record.packet_numbers.length ? `Packets ${record.packet_numbers.join(', ')}` : 'No direct packet references'
}

function timestamps(record: EvidenceRecord): string {
  if (!record.timestamps_ns.length) return 'No packet timestamps'
  return record.timestamps_ns.map((value) => `${(value / 1_000_000_000).toFixed(6)} s`).join(', ')
}

function Record({ record, sequence }: { record: EvidenceRecord; sequence: number }) {
  return (
    <article className="evidence-record">
      <div className="evidence-record-heading">
        <span>{String(sequence + 1).padStart(2, '0')}</span>
        <div><code>{record.id}</code><h3>{record.description}</h3></div>
        <ProvenanceMark provenance={record.provenance} compact />
      </div>
      <div className="packet-references"><span>{packets(record)}</span><span>{timestamps(record)}</span></div>
      <dl>
        <div><dt>Protocol</dt><dd>{show(record.protocol)}</dd></div>
        <div><dt>Source</dt><dd>{record.source_component}</dd></div>
        <div><dt>Raw value</dt><dd><code>{show(record.raw_value)}</code></dd></div>
        <div><dt>Normalized</dt><dd><code>{show(record.normalized_value)}</code></dd></div>
        <div><dt>Confidence</dt><dd>{record.confidence == null ? 'Not applicable' : `${(record.confidence * 100).toFixed(1)}%`}</dd></div>
      </dl>
    </article>
  )
}

export function EvidenceDrawer() {
  const { closeEvidence, envelope, evidenceRequest } = useAnalysis()
  const evidence = envelope?.analysis.evidence ?? []
  const records = evidenceRequest?.ids.map((id) => evidence.find((item) => item.id === id) ?? null) ?? []
  return (
    <Dialog.Root open={evidenceRequest !== null} onOpenChange={(open) => { if (!open) closeEvidence() }}>
      <Dialog.Portal>
        <Dialog.Overlay className="evidence-overlay" />
        <Dialog.Content className="evidence-drawer" aria-describedby="evidence-description">
          <header className="evidence-drawer-header">
            <span className="drawer-kicker"><FileSearch size={14} />Provenance chain</span>
            <Dialog.Title>Evidence inspector</Dialog.Title>
            <Dialog.Description id="evidence-description">Packet references and analyzer provenance supporting this result.</Dialog.Description>
            {evidenceRequest?.valueLabel && <strong className="inspected-value">{evidenceRequest.valueLabel}</strong>}
          </header>
          <ScrollArea.Root className="evidence-scroll">
            <ScrollArea.Viewport className="evidence-scroll-viewport">
              <div className="evidence-records">
                {records.map((record, index) => record
                  ? <Record key={`${record.id}-${index}`} record={record} sequence={index} />
                  : (
                    <article className="evidence-unavailable" key={`missing-${evidenceRequest?.ids[index]}`}>
                      <ProvenanceMark provenance="UNKNOWN" compact />
                      <h3>Evidence unavailable</h3>
                      <p>No record with ID <code>{evidenceRequest?.ids[index]}</code> exists in this validated analysis.</p>
                    </article>
                  ))}
              </div>
            </ScrollArea.Viewport>
            <ScrollArea.Scrollbar className="evidence-scrollbar" orientation="vertical"><ScrollArea.Thumb /></ScrollArea.Scrollbar>
          </ScrollArea.Root>
          <Dialog.Close className="evidence-close" aria-label="Close evidence inspector"><X size={19} /></Dialog.Close>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
