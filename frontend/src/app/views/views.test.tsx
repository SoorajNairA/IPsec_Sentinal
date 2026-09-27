import { fireEvent, render, screen, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { parseAnalysis } from '../../lib/analysis-contract/load'
import { makeAnalysis } from '../../test/analysisFixture'
import { EvidenceList } from '../../components/evidence/EvidenceList'
import { AnalysisReport } from '../../components/report/AnalysisReport'
import { SaTimeline } from '../../components/tunnel/SaTimeline'
import { buildAnalysisView } from '../../lib/presentation/analysisView'

function analysisWithChronology() {
  const base = makeAnalysis()
  return parseAnalysis({
    ...base,
    security_associations: [
      base.security_associations[0],
      {
        ...base.security_associations[0],
        spi: '0x00000003',
        first_packet_number: 21,
        first_timestamp_ns: 2_400_000_000,
        predecessor_spi: '0x00000001',
        successor_spi: null,
        rekey_evidence_id: 'ev-pfs',
        pfs: { state: 'enabled', provenance: 'DERIVED' },
      },
    ],
  })
}

describe('detailed workspace views', () => {
  it('renders predecessor/successor chronology, directional SPI, and attached PFS evidence', () => {
    const analysis = analysisWithChronology()
    const inspect = vi.fn()
    render(<SaTimeline ike={analysis.ike} associations={analysis.security_associations} pfs={analysis.pfs} onInspectEvidence={inspect} />)
    expect(screen.getAllByText('0x00000001').length).toBeGreaterThan(0)
    expect(screen.getAllByText('0x00000003').length).toBeGreaterThan(0)
    expect(screen.getAllByText(/successor/i).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/PFS enabled/i).length).toBeGreaterThan(0)
    fireEvent.click(screen.getByRole('button', { name: /Inspect rekey evidence for 0x00000003/i }))
    expect(inspect).toHaveBeenCalledWith(['ev-pfs'], expect.stringContaining('0x00000003'))
  })

  it('filters and searches the evidence chronology without changing records', () => {
    const analysis = analysisWithChronology()
    const select = vi.fn()
    const { rerender } = render(<EvidenceList evidence={analysis.evidence} filter="ALL" query="" onSelect={select} />)
    expect(screen.getAllByRole('button', { name: /Inspect evidence/i })).toHaveLength(4)
    rerender(<EvidenceList evidence={analysis.evidence} filter="OBSERVED" query="" onSelect={select} />)
    expect(screen.getByText('ev-cipher')).toBeVisible()
    expect(screen.queryByText('ev-pfs')).not.toBeInTheDocument()
    rerender(<EvidenceList evidence={analysis.evidence} filter="ALL" query="classifier" onSelect={select} />)
    fireEvent.click(screen.getByRole('button', { name: /Inspect evidence ev-traffic/i }))
    expect(select).toHaveBeenCalledWith('ev-traffic')
  })

  it('preserves the approved report order, limitations, provenance, and print control', () => {
    const analysis = analysisWithChronology()
    const report = render(<AnalysisReport analysis={analysis} analysisView={buildAnalysisView(analysis)} mode="plain" onInspectEvidence={vi.fn()} />)
    const headings = within(report.container).getAllByRole('heading', { level: 2 }).map((heading) => heading.textContent)
    expect(headings).toEqual([
      'Executive Summary', 'Security Score', 'Protocol Configuration', 'Traffic Intelligence',
      'Key Findings', 'Risk Summary', 'Evidence Coverage', 'Recommendations', 'Limitations',
    ])
    expect(screen.getByText('ESP payloads were not decrypted.')).toBeVisible()
    expect(screen.getAllByText(/Observed|Derived|AI-inferred/).length).toBeGreaterThan(0)
    expect(screen.getByRole('button', { name: 'Print report' })).toHaveClass('screen-only')
  })
})
