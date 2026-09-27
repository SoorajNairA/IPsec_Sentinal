import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { parseAnalysis } from '../../lib/analysis-contract/load'
import { makeAnalysis } from '../../test/analysisFixture'
import { FindingsPanel } from './FindingsPanel'

describe('security findings panel', () => {
  it('groups all analyzer categories, orders issues first, and keeps PASS findings quiet', () => {
    const base = makeAnalysis()
    const findings = [
      { ...base.findings[0], rule_id: 'IPSEC-CRYPTO-002', title: 'Weak cipher', severity: 'HIGH', status: 'FAIL', summary: 'A weak cipher was selected.' },
      { ...base.findings[1], rule_id: 'IPSEC-PFS-001', severity: 'MEDIUM', status: 'FAIL' },
      base.findings[0],
    ]
    const analysis = parseAnalysis({ ...base, findings })
    render(<FindingsPanel findings={analysis.findings} onInspectEvidence={vi.fn()} />)
    for (const category of [
      'Cryptography', 'Key Exchange / PFS', 'Security Association Hygiene',
      'Replay / Protocol Protections', 'Metadata / Privacy Exposure',
    ]) expect(screen.getByRole('heading', { name: category })).toBeVisible()
    const summaries = screen.getAllByTestId('finding-summary')
    expect(summaries[0]).toHaveTextContent('Weak cipher')
    expect(screen.getByText('Modern AEAD encryption').closest('details')).not.toHaveAttribute('open')
  })

  it('expands recommendation detail and makes supporting evidence inspectable', async () => {
    const user = userEvent.setup()
    const inspect = vi.fn()
    const analysis = parseAnalysis(makeAnalysis())
    render(<FindingsPanel findings={analysis.findings} onInspectEvidence={inspect} />)
    await user.click(screen.getByText('Modern AEAD encryption'))
    expect(screen.getByText('Retain an approved GCM configuration.')).toBeVisible()
    await user.click(screen.getByRole('button', { name: /inspect evidence for Modern AEAD encryption/i }))
    expect(inspect).toHaveBeenCalledWith(['ev-cipher'], 'Modern AEAD encryption')
  })
})
