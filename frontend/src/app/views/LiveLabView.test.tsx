import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { AnalysisProvider } from '../AnalysisContext'
import { LiveLabProvider } from '../LiveLabContext'
import { AppRoutes } from '../routes'
import { parseAnalysisEnvelope } from '../../lib/analysis-contract/load'
import type { LiveEvent, LiveLabServices, LiveSession, LiveStreamHandlers } from '../../lib/live/types'
import { makeEnvelope } from '../../test/analysisFixture'

const catalogue = {
  scenarios: [
    { id: 'secure-baseline', display_name: 'Secure Baseline', mystery: false },
    { id: 'aes128-gcm', display_name: 'AES-128-GCM', mystery: false },
    { id: 'aes256-cbc', display_name: 'AES-256-CBC + HMAC', mystery: false },
    { id: 'no-pfs', display_name: 'PFS Disabled', mystery: false },
    { id: 'mystery', display_name: 'Mystery VPN', mystery: true },
  ],
  workloads: ['icmp', 'video'],
}

function session(overrides: Partial<LiveSession> = {}): LiveSession {
  return {
    session_id: 'SNT-8A31', display_name: 'Secure Baseline', state: 'IDLE', state_reason: 'ready',
    tunnel_status: 'INACTIVE', capture_status: 'NOT_STARTED', cleanup_status: 'NOT_RUN', active_action: null,
    child_sa_established: false, completed_workloads: [], latest_completed_workload_sequence: null,
    latest_event_id: 1, analysis_available: false, mystery: false, revealed: false, failure: null,
    allowed_actions: ['CONNECT', 'DISCONNECT'], ...overrides,
  }
}

function event(id: number, type: LiveEvent['type'], state: LiveEvent['state'], data: Record<string, unknown> = {}, analysis?: LiveEvent['analysis']): LiveEvent {
  return {
    schema: 'ipsec-sentinel.live-event/v1', event_id: id, session_id: 'SNT-8A31',
    timestamp: `2026-09-28T10:00:${String(id).padStart(2, '0')}.000Z`, type, state,
    reason: type.replaceAll('.', ' '), data, evidence: [], ...(analysis ? { analysis } : {}),
  }
}

function setup(created = session()) {
  let stream: LiveStreamHandlers | null = null
  const services: LiveLabServices = {
    scenarios: vi.fn(async () => catalogue),
    createSession: vi.fn(async () => created),
    getSession: vi.fn(async () => created),
    command: vi.fn(async () => undefined),
    subscribe: vi.fn((_id, _after, handlers) => {
      stream = handlers
      handlers.onOpen?.()
      return { close: vi.fn() }
    }),
  }
  render(
    <MemoryRouter initialEntries={['/live']}>
      <AnalysisProvider>
        <LiveLabProvider services={services}><AppRoutes /></LiveLabProvider>
      </AnalysisProvider>
    </MemoryRouter>,
  )
  return { services, emit: (item: LiveEvent) => act(() => stream?.onEvent(item)) }
}

describe('Live Lab product flow', () => {
  beforeEach(() => window.localStorage.clear())

  it('creates a scenario, connects through server actions, and renders only real progressive events', async () => {
    const user = userEvent.setup()
    const { services, emit } = setup()
    expect(await screen.findByRole('heading', { name: 'Start Live Lab' })).toBeVisible()
    expect(screen.getByRole('button', { name: 'Secure Baseline' })).toBeVisible()

    await user.click(screen.getByRole('button', { name: 'Secure Baseline' }))
    await user.click(screen.getByRole('button', { name: 'Create lab session' }))
    expect(services.createSession).toHaveBeenCalledWith('secure-baseline')
    expect((await screen.findAllByText('SNT-8A31')).length).toBeGreaterThanOrEqual(1)
    expect(screen.queryByText('AES-256-GCM')).not.toBeInTheDocument()
    expect(screen.queryByText('TUNNEL ACTIVE')).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Connect' }))
    expect(services.command).toHaveBeenCalledWith('SNT-8A31', 'CONNECT', {})
    emit(event(1, 'session.created', 'IDLE', { display_name: 'Secure Baseline', mystery: false }))
    emit(event(2, 'sandbox.preparing', 'PREPARING_SANDBOX'))
    emit(event(3, 'capture.started', 'STARTING_CAPTURE'))
    emit(event(4, 'ike.sa_init.request', 'IKE_NEGOTIATING', { direction: 'outbound' }))
    expect(screen.getByText(/IKE SA INIT request/i)).toBeVisible()
    expect(screen.queryByText('AES-256-GCM')).not.toBeInTheDocument()

    emit(event(5, 'ike.proposal.selected', 'IKE_NEGOTIATING', { encryption: 'AES_GCM_16_256', dh_group: 'ECP_384' }))
    expect(screen.getByText('AES_GCM_16_256')).toBeVisible()
    emit(event(6, 'child_sa.verified', 'CHILD_SA_ESTABLISHED'))
    emit(event(7, 'tunnel.active', 'TUNNEL_ACTIVE', { endpoint: { address: '192.0.2.2' } }))
    expect(screen.getAllByText('TUNNEL ACTIVE').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByRole('button', { name: 'Ping Server' })).toBeEnabled()
  })

  it('gates packet flow, ML inference, PFS, and final score on their evidence events', async () => {
    const user = userEvent.setup()
    const { emit } = setup()
    await user.click(await screen.findByRole('button', { name: 'Secure Baseline' }))
    await user.click(screen.getByRole('button', { name: 'Create lab session' }))
    emit(event(1, 'session.created', 'IDLE', { display_name: 'Secure Baseline', mystery: false }))
    emit(event(2, 'capture.started', 'STARTING_CAPTURE'))
    emit(event(3, 'child_sa.verified', 'CHILD_SA_ESTABLISHED'))
    emit(event(4, 'tunnel.active', 'TUNNEL_ACTIVE'))

    expect(screen.queryByTestId('live-esp-flow')).not.toBeInTheDocument()
    expect(screen.getByText('Collecting evidence...')).toBeVisible()
    expect(screen.queryByText(/PFS VERIFIED/i)).not.toBeInTheDocument()
    emit(event(5, 'traffic.started', 'TRAFFIC_RUNNING', { workload: 'video', sequence: 1 }))
    emit(event(6, 'esp.observed', 'TRAFFIC_RUNNING', { packet_delta: 184, byte_delta: 251322, direction_counts: { forward: 100, reverse: 84 } }))
    expect(screen.getByTestId('live-esp-flow')).toBeVisible()
    expect(screen.getByText(/184 new ESP packets/i)).toBeVisible()
    emit(event(7, 'traffic.completed', 'TUNNEL_ACTIVE', { workload: 'video', sequence: 1, seed: 9 }))
    emit(event(8, 'rekey.started', 'REKEYING', { before_spis: ['0x01'] }))
    emit(event(9, 'child_sa.rekeyed', 'TUNNEL_ACTIVE', { after_spis: ['0x02'], verification_state: 'enabled', observed: { status: 'VERIFIED' } }))
    expect(screen.getByText('PFS VERIFIED')).toBeVisible()

    const envelope = parseAnalysisEnvelope(makeEnvelope())
    emit(event(10, 'analysis.completed', 'READY', makeEnvelope(), envelope))
    expect(await screen.findByText('VIDEO')).toBeVisible()
    expect(screen.getByText('96/100')).toBeVisible()
    expect(screen.getByText('Payload decrypted: NO')).toBeVisible()
  })

  it('keeps Mystery identity hidden until explicit reveal and invokes disconnect', async () => {
    const user = userEvent.setup()
    const mystery = session({ display_name: 'Mystery VPN #01', mystery: true })
    const { services, emit } = setup(mystery)
    await user.click(await screen.findByRole('button', { name: 'Mystery VPN' }))
    await user.click(screen.getByRole('button', { name: 'Create lab session' }))
    emit(event(1, 'session.created', 'IDLE', { display_name: 'Mystery VPN #01', mystery: true }))
    expect(screen.getByText('Configuration hidden')).toBeVisible()
    expect(screen.queryByText('secure-baseline')).not.toBeInTheDocument()

    const envelope = parseAnalysisEnvelope(makeEnvelope())
    emit(event(2, 'analysis.completed', 'READY', makeEnvelope(), envelope))
    await user.click(screen.getByRole('button', { name: 'Reveal Ground Truth' }))
    expect(services.command).toHaveBeenCalledWith('SNT-8A31', 'REVEAL', {})
    emit(event(3, 'mystery.revealed', 'READY', { ground_truth: { scenario_id: 'secure-baseline', display_name: 'Secure Baseline', encryption: 'AES-256-GCM', pfs: 'enabled' } }))
    const comparison = screen.getByRole('region', { name: 'Mystery VPN comparison' })
    expect(within(comparison).getByText('Secure Baseline')).toBeVisible()

    await user.click(screen.getByRole('button', { name: 'Disconnect' }))
    expect(services.command).toHaveBeenCalledWith('SNT-8A31', 'DISCONNECT', {})
  })

  it('shows structured action errors without inventing progress', async () => {
    const user = userEvent.setup()
    const { services } = setup()
    vi.mocked(services.command).mockRejectedValueOnce(Object.assign(new Error('Connect first.'), { code: 'TUNNEL_NOT_ACTIVE' }))
    await user.click(await screen.findByRole('button', { name: 'Secure Baseline' }))
    await user.click(screen.getByRole('button', { name: 'Create lab session' }))
    await user.click(screen.getByRole('button', { name: 'Connect' }))
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Connect first.'))
  })
})
