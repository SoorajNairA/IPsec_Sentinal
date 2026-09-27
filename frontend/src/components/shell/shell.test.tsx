import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'

import { AnalysisProvider, type AnalysisServices } from '../../app/AnalysisContext'
import { AppRoutes } from '../../app/routes'
import { makeEnvelope } from '../../test/analysisFixture'

const demos = [
  ['secure-baseline', 'Secure Baseline', 'run_000001', 'full-evidence.pcap'],
  ['aes128-gcm', 'AES-128-GCM', 'run_000043', 'full-evidence.pcap'],
  ['aes256-cbc', 'AES-256-CBC + SHA-256', 'run_000085', 'full-evidence.pcap'],
  ['no-pfs', 'PFS Disabled', 'run_000127', 'full-evidence.pcap'],
  ['video-traffic', 'Video Traffic Intelligence', 'run_000013', 'encrypted.pcap'],
] as const

const manifest = {
  schema_id: 'ipsec-sentinel.frontend-demos/v1' as const,
  version: '1.0' as const,
  analyzer_commit: '64b5884edc9cac3ceea321ce785f36cb24132401',
  generation_command: 'python scripts/generate_frontend_demos.py',
  demos: demos.map(([id, label, run_id, capture]) => ({
    id,
    label,
    description: `${label} genuine session`,
    source: { run_id, capture },
    analysis_path: `/demos/${id}/analysis.json`,
    xray_path: `/demos/${id}/xray.json`,
    sha256: { analysis: 'a'.repeat(64), xray: 'b'.repeat(64) },
  })),
}

function labelPattern(value: string) {
  return new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i')
}

function renderApp(services: Partial<AnalysisServices> = {}, path = '/') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AnalysisProvider services={services}>
        <AppRoutes />
      </AnalysisProvider>
    </MemoryRouter>,
  )
}

describe('guided analysis workspace shell', () => {
  it('exposes a semantic PCAP picker and accepts drag/drop analysis', async () => {
    const analyzeCapture = vi.fn(async () => makeEnvelope())
    renderApp({ analyzeCapture })

    expect(screen.getByRole('heading', { name: 'IPsec Sentinel' })).toBeVisible()
    const input = screen.getByLabelText('Choose a classic PCAP capture')
    expect(input).toHaveAttribute('accept', '.pcap,.pcapng,application/vnd.tcpdump.pcap')

    const capture = new File(['capture'], 'sample.pcap', { type: 'application/vnd.tcpdump.pcap' })
    fireEvent.drop(screen.getByRole('button', { name: /drop a packet capture/i }), {
      dataTransfer: { files: [capture] },
    })
    await waitFor(() => expect(analyzeCapture).toHaveBeenCalledWith(capture))
    expect(await screen.findByRole('heading', { name: 'Analysis overview' })).toBeVisible()
  })

  it('shows all genuine demo choices, supports Escape, and enters READY on selection', async () => {
    const user = userEvent.setup()
    const loadManifest = vi.fn(async () => manifest)
    const loadDemo = vi.fn(async () => makeEnvelope())
    renderApp({ loadManifest, loadDemo })

    await user.click(screen.getByRole('button', { name: 'Run Guided Demo' }))
    expect(await screen.findByRole('dialog', { name: 'Choose a guided demo' })).toBeVisible()
    for (const [, label] of demos) expect(screen.getByRole('button', { name: labelPattern(label) })).toBeVisible()
    await user.keyboard('{Escape}')
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Run Guided Demo' }))
    await user.click(await screen.findByRole('button', { name: /PFS Disabled/i }))
    expect(loadDemo).toHaveBeenCalledWith('no-pfs')
    expect(await screen.findByRole('heading', { name: 'Analysis overview' })).toBeVisible()
    expect(screen.getByRole('navigation', { name: 'Analysis views' })).toBeVisible()
  })

  it('shows deterministic orchestration stages while a genuine request is pending', async () => {
    const user = userEvent.setup()
    let finish: ((value: ReturnType<typeof makeEnvelope>) => void) | undefined
    const analyzeCapture = vi.fn(() => new Promise<ReturnType<typeof makeEnvelope>>((resolve) => { finish = resolve }))
    renderApp({ analyzeCapture })
    await user.upload(
      screen.getByLabelText('Choose a classic PCAP capture'),
      new File(['capture'], 'pending.pcap', { type: 'application/vnd.tcpdump.pcap' }),
    )

    expect(await screen.findByRole('heading', { name: 'Analyzing encrypted session' })).toBeVisible()
    expect(screen.getByText('Reading capture')).toBeVisible()
    expect(screen.queryByText('AES-256-GCM')).not.toBeInTheDocument()
    finish?.(makeEnvelope())
    expect(await screen.findByRole('heading', { name: 'Analysis overview' })).toBeVisible()
  })

  it('detects PCAPNG before upload and explains the supported export path', async () => {
    const user = userEvent.setup()
    const analyzeCapture = vi.fn()
    renderApp({ analyzeCapture })
    await user.upload(
      screen.getByLabelText('Choose a classic PCAP capture'),
      new File(['capture'], 'capture.pcapng'),
    )
    expect(await screen.findByRole('alert')).toHaveTextContent('PCAPNG is not supported yet')
    expect(screen.getByRole('alert')).toHaveTextContent('Export the capture as classic PCAP and retry')
    expect(analyzeCapture).not.toHaveBeenCalled()
  })

  it('navigates analysis routes without losing the loaded result', async () => {
    const user = userEvent.setup()
    renderApp({ loadManifest: async () => manifest, loadDemo: async () => makeEnvelope() })
    await user.click(screen.getByRole('button', { name: 'Run Guided Demo' }))
    await user.click(await screen.findByRole('button', { name: /Secure Baseline/i }))
    await user.click(await screen.findByRole('link', { name: 'Security' }))
    expect(screen.getByRole('heading', { name: 'Security findings' })).toBeVisible()
    await user.click(screen.getByRole('link', { name: 'Traffic' }))
    expect(screen.getByRole('heading', { level: 1, name: 'Traffic intelligence' })).toBeVisible()
  })

  it('guards direct analysis routes until a validated analysis is loaded', async () => {
    renderApp({}, '/analysis/security')
    expect(await screen.findByRole('heading', { name: 'IPsec Sentinel' })).toBeVisible()
    expect(screen.queryByRole('heading', { name: 'Security findings' })).not.toBeInTheDocument()
  })
})
