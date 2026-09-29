import axe from 'axe-core'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'

import { AnalysisProvider, useAnalysis } from '../../app/AnalysisContext'
import { makeEnvelope } from '../../test/analysisFixture'
import { EvidenceAction } from './EvidenceAction'
import { EvidenceDrawer } from './EvidenceDrawer'
import { ProvenanceMark } from './ProvenanceMark'

function Harness() {
  const { loadDemo, status } = useAnalysis()
  return (
    <>
      {status !== 'READY' && <button type="button" onClick={() => void loadDemo('secure-baseline')}>Load analysis</button>}
      {status === 'READY' && (
        <>
          <div aria-label="Provenance examples">
            <ProvenanceMark provenance="OBSERVED" />
            <ProvenanceMark provenance="DERIVED" />
            <ProvenanceMark provenance="AI_INFERRED" />
            <ProvenanceMark provenance="UNKNOWN" />
          </div>
          <EvidenceAction evidenceIds={['ev-cipher', 'ev-rekey', 'ev-traffic']} label="Inspect cipher and rekey evidence" valueLabel="AES-256-GCM" />
          <EvidenceAction evidenceIds={['ev-missing']} label="Inspect missing evidence" valueLabel="Unavailable claim" />
        </>
      )}
      <EvidenceDrawer />
    </>
  )
}

function renderHarness() {
  return render(
    <MemoryRouter>
      <AnalysisProvider services={{ loadDemo: async () => makeEnvelope() }}>
        <Harness />
      </AnalysisProvider>
    </MemoryRouter>,
  )
}

async function load(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('button', { name: 'Load analysis' }))
  await screen.findByRole('button', { name: 'Inspect cipher and rekey evidence' })
}

describe('evidence provenance and global inspector', () => {
  it('renders all four provenance states with visible text and distinct non-color shapes', async () => {
    const user = userEvent.setup()
    renderHarness()
    await load(user)
    for (const state of ['Observed', 'Derived', 'AI-inferred', 'Unknown']) {
      const marker = screen.getByLabelText(`${state} provenance`)
      expect(marker).toHaveTextContent(state)
      expect(marker.querySelector('[data-marker-shape]')).toBeInTheDocument()
    }
  })

  it('resolves multiple records and exposes packet-level evidence fields', async () => {
    const user = userEvent.setup()
    renderHarness()
    await load(user)
    await user.click(screen.getByRole('button', { name: 'Inspect cipher and rekey evidence' }))

    expect(screen.getByRole('dialog', { name: 'Evidence inspector' })).toBeVisible()
    expect(screen.getAllByText('AES-256-GCM')[0]).toBeVisible()
    expect(screen.getByText('ev-cipher')).toBeVisible()
    expect(screen.getByText('ev-rekey')).toBeVisible()
    expect(screen.getByText('Packets 4, 5')).toBeVisible()
    expect(screen.getByText('1.100000 s, 1.200000 s')).toBeVisible()
    expect(screen.getByText('IKEv2')).toBeVisible()
    expect(screen.getByText('ENCR_AES_GCM_16/256')).toBeVisible()
    expect(screen.getAllByText('AES-256-GCM').length).toBeGreaterThan(1)
    expect(screen.getByText('ike-analyzer')).toBeVisible()
    expect(screen.getByText('96.4%')).toBeVisible()

    const results = await axe.run(document.body)
    expect(results.violations).toEqual([])
  })

  it('shows missing evidence honestly and restores trigger focus on Escape and close', async () => {
    const user = userEvent.setup()
    renderHarness()
    await load(user)
    const missing = screen.getByRole('button', { name: 'Inspect missing evidence' })
    await user.click(missing)
    expect(screen.getByText('Evidence unavailable')).toBeVisible()
    await user.keyboard('{Escape}')
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(missing).toHaveFocus()

    const inspect = screen.getByRole('button', { name: 'Inspect cipher and rekey evidence' })
    await user.click(inspect)
    await user.click(screen.getByRole('button', { name: 'Close evidence inspector' }))
    expect(inspect).toHaveFocus()
  })
})
