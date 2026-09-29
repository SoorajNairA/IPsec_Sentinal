import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { parseAnalysisEnvelope } from '../../lib/analysis-contract/load'
import { makeAnalysis, makeEnvelope } from '../../test/analysisFixture'
import { LiveTunnel } from './LiveTunnel'

describe('live tunnel visualization', () => {
  it('derives endpoints, negotiation, ESP activity, and rekey state from analysis', () => {
    const { analysis, xray } = parseAnalysisEnvelope(makeEnvelope())
    render(<LiveTunnel analysis={analysis} xray={xray} reducedMotion onInspectEvidence={vi.fn()} />)

    expect(screen.getByText('192.0.2.1')).toBeVisible()
    expect(screen.getByText('192.0.2.2')).toBeVisible()
    expect(screen.getByText('IKEv2')).toBeVisible()
    expect(screen.getByText('AES-256-GCM')).toBeVisible()
    expect(screen.getByText('ECP-384')).toBeVisible()
    expect(screen.getByText('PFS enabled')).toBeVisible()
    expect(screen.getByText('12.0 packets/s')).toBeVisible()
    expect(screen.getByLabelText('14 forward and 10 reverse ESP packets')).toBeVisible()
    expect(screen.getByLabelText('CHILD_SA rekey observed')).toBeVisible()
    expect(screen.getByTestId('tunnel-flow')).toHaveAttribute('data-motion', 'reduced')
  })

  it('attaches a no-PFS warning to the key-exchange layer and exposes its evidence', async () => {
    const user = userEvent.setup()
    const inspect = vi.fn()
    const base = makeAnalysis()
    const analysis = parseAnalysisEnvelope(makeEnvelope({
      ...base,
      pfs: { state: 'disabled', provenance: 'DERIVED', evidence_ids: ['ev-pfs'], explanation: 'No CHILD_SA DH was configured or observed.' },
    })).analysis
    const xray = parseAnalysisEnvelope(makeEnvelope()).xray
    render(<LiveTunnel analysis={analysis} xray={xray} reducedMotion onInspectEvidence={inspect} />)

    const layer = screen.getByTestId('key-exchange-layer')
    expect(within(layer).getByText('PFS disabled')).toBeVisible()
    expect(within(layer).getByText(/forward secrecy is not active/i)).toBeVisible()
    await user.click(within(layer).getByRole('button', { name: /inspect PFS evidence/i }))
    expect(inspect).toHaveBeenCalledWith(['ev-pfs'], 'PFS disabled')
  })

  it('renders unknown negotiation fields honestly', () => {
    const base = makeAnalysis()
    const analysis = parseAnalysisEnvelope(makeEnvelope({
      ...base,
      ike: {
        ...base.ike,
        encryption: { raw: 'UNKNOWN', normalized: 'UNKNOWN', provenance: 'UNKNOWN', evidence_id: 'ev-cipher' },
        dh_group: { raw: 'UNKNOWN', normalized: 'UNKNOWN', provenance: 'UNKNOWN' },
      },
      pfs: { state: 'unknown', provenance: 'UNKNOWN', evidence_ids: [], explanation: 'Insufficient evidence.' },
    })).analysis
    render(<LiveTunnel analysis={analysis} xray={parseAnalysisEnvelope(makeEnvelope()).xray} reducedMotion onInspectEvidence={vi.fn()} />)
    expect(screen.getAllByText('Unknown').length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText('PFS unknown')).toBeVisible()
  })
})
