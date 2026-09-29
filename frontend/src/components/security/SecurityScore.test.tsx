import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { parseAnalysis } from '../../lib/analysis-contract/load'
import { makeAnalysis } from '../../test/analysisFixture'
import { SecurityScore } from './SecurityScore'

describe('transparent security score', () => {
  it('shows score composition, evidence coverage, unassessed weight, and categories', () => {
    const analysis = parseAnalysis(makeAnalysis())
    render(<SecurityScore score={analysis.security_score} findings={analysis.findings} onSelectDeduction={vi.fn()} />)
    expect(screen.getByText('96')).toBeVisible()
    expect(screen.getByText('/ 100')).toBeVisible()
    expect(screen.getByText('82% evidence coverage')).toBeVisible()
    expect(screen.getByText('18% unassessed')).toBeVisible()
    for (const category of analysis.security_score.categories) expect(screen.getByText(category.name)).toBeVisible()
    expect(screen.getByText(/unknown is not penalized/i)).toBeVisible()
  })

  it('makes score deductions inspectable', async () => {
    const user = userEvent.setup()
    const select = vi.fn()
    const base = makeAnalysis()
    const securityScore = {
      ...base.security_score,
      total: 91,
      categories: base.security_score.categories.map((category, index) => index === 0
        ? { ...category, achieved_score: 25, deductions: [{ rule_id: 'IPSEC-CRYPTO-001', points: 5, evidence_ids: ['ev-cipher'] }] }
        : category),
    }
    const analysis = parseAnalysis({ ...base, security_score: securityScore })
    render(<SecurityScore score={analysis.security_score} findings={analysis.findings} onSelectDeduction={select} />)
    await user.click(screen.getByRole('button', { name: /inspect 5 point deduction/i }))
    expect(select).toHaveBeenCalledWith(['ev-cipher'], '5 point deduction')
  })
})
