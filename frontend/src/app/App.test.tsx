import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { App } from './App'

describe('IPsec Sentinel application shell', () => {
  it('presents the analysis actions and trust contract', () => {
    render(<App />)

    expect(screen.getByRole('heading', { name: 'IPsec Sentinel' })).toBeVisible()
    expect(screen.getByRole('link', { name: 'Start Live Lab' })).toBeVisible()
    expect(screen.getByRole('button', { name: 'Offline PCAP Analysis' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Run Guided Demo' })).toBeEnabled()
    expect(screen.getByText('Local Analysis')).toBeVisible()
    expect(screen.getByText('Payload Decryption: Never')).toBeVisible()
    expect(screen.getByText('Evidence-Aware Results')).toBeVisible()
  })
})

