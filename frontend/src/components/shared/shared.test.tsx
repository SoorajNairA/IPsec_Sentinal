import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { AnalysisError } from './AnalysisError'
import { safeAnalysisError } from './errorStates'
import { UnknownValue } from './UnknownValue'

describe('safe analysis states', () => {
  it.each([
    ['NO_IPSEC', 'No IPsec traffic detected'],
    ['INVALID_CAPTURE', 'Capture could not be parsed'],
    ['PAYLOAD_TOO_LARGE', 'Capture is too large'],
    ['UNSUPPORTED_PCAPNG', 'PCAPNG is not supported yet'],
    ['UNSUPPORTED_LAYOUT', 'Capture layout is not supported'],
    ['INSUFFICIENT_ESP', 'Not enough ESP traffic'],
    ['MODEL_UNAVAILABLE', 'Traffic model is unavailable'],
  ])('maps %s to reviewed copy', (code, title) => {
    expect(safeAnalysisError(code).title).toBe(title)
  })

  it('does not expose unexpected backend text or stack traces', () => {
    const state = safeAnalysisError('UNEXPECTED_CODE')
    expect(state.message).not.toContain('Traceback')
    render(<AnalysisError code="UNEXPECTED_CODE" unsafeMessage="Traceback: secret path" onReset={vi.fn()} />)
    expect(screen.queryByText(/secret path/i)).not.toBeInTheDocument()
    expect(screen.getByText('UNEXPECTED_CODE')).toBeVisible()
  })

  it('renders an explicit unassessed value with a practical explanation', () => {
    render(<UnknownValue label="Replay protection" explanation="Passive ESP does not expose the replay window." />)
    expect(screen.getByText('Not assessed')).toBeVisible()
    expect(screen.getByText(/does not expose the replay window/i)).toBeVisible()
  })
})
