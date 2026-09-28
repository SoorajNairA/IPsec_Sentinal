import { act, renderHook, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { describe, expect, it, vi } from 'vitest'

import { makeEnvelope } from '../test/analysisFixture'
import { parseAnalysisEnvelope } from '../lib/analysis-contract/load'
import type { LiveEvent, LiveSession, LiveStreamHandlers } from '../lib/live/types'
import { LiveLabProvider, liveLabReducer, useLiveLab, type LiveLabState } from './LiveLabContext'

const baseSession: LiveSession = {
  session_id: 'SNT-AB12', display_name: 'Secure Baseline', state: 'IDLE',
  state_reason: 'ready', tunnel_status: 'INACTIVE', capture_status: 'NOT_STARTED', cleanup_status: 'NOT_RUN',
  active_action: null, child_sa_established: false, completed_workloads: [], latest_completed_workload_sequence: null,
  latest_event_id: 1, analysis_available: false, mystery: false, revealed: false, failure: null,
  allowed_actions: ['CONNECT', 'DISCONNECT'],
}

function liveEvent(id: number, type: LiveEvent['type'], state: LiveEvent['state'], data: Record<string, unknown> = {}): LiveEvent {
  return {
    schema: 'ipsec-sentinel.live-event/v1', event_id: id, session_id: 'SNT-AB12',
    timestamp: `2026-09-28T10:00:${String(id).padStart(2, '0')}.000Z`, type, state, reason: type,
    data, evidence: [],
  }
}

const initial: LiveLabState = {
  catalogue: null, session: null, events: [], latestEventId: 0, analysis: null,
  streamStatus: 'CLOSED', problem: null,
}

describe('Live Lab reducer and provider', () => {
  it('applies events in exact order, suppresses duplicates, and restores projection by replay', () => {
    const created = liveEvent(1, 'session.created', 'IDLE', { display_name: 'Secure Baseline', mystery: false })
    const active = liveEvent(2, 'tunnel.active', 'TUNNEL_ACTIVE', { endpoint: { address: '192.0.2.2' } })
    const traffic = liveEvent(3, 'traffic.started', 'TRAFFIC_RUNNING', { workload: 'video', sequence: 1 })
    const completed = liveEvent(4, 'traffic.completed', 'TUNNEL_ACTIVE', { workload: 'video', sequence: 1, seed: 42 })
    let state = liveLabReducer(initial, { type: 'SESSION_LOADED', session: baseSession, replayFromStart: true })
    for (const item of [created, active, traffic, completed]) state = liveLabReducer(state, { type: 'EVENT', event: item })
    state = liveLabReducer(state, { type: 'EVENT', event: completed })

    expect(state.events.map((item) => item.event_id)).toEqual([1, 2, 3, 4])
    expect(state.session).toMatchObject({ state: 'TUNNEL_ACTIVE', tunnel_status: 'ACTIVE' })
    expect(state.latestEventId).toBe(4)
    expect(state.session?.completed_workloads[0]).toMatchObject({ workload_id: 'video', sequence: 1, seed: 42 })
    expect(() => liveLabReducer(state, { type: 'EVENT', event: liveEvent(6, 'traffic.started', 'TRAFFIC_RUNNING') })).toThrow(/ordered/i)
  })

  it('clears accepted actions, exposes command errors, and hands off full analysis', () => {
    let state = liveLabReducer(initial, { type: 'SESSION_LOADED', session: baseSession, replayFromStart: true })
    state = liveLabReducer(state, { type: 'EVENT', event: liveEvent(1, 'action.accepted', 'IDLE', { action: 'CONNECT' }) })
    expect(state.session?.active_action).toBe('CONNECT')
    state = liveLabReducer(state, { type: 'EVENT', event: liveEvent(2, 'action.completed', 'TUNNEL_ACTIVE', { action: 'CONNECT' }) })
    expect(state.session?.active_action).toBeNull()
    const envelope = parseAnalysisEnvelope(makeEnvelope())
    state = liveLabReducer(state, { type: 'EVENT', event: { ...liveEvent(3, 'analysis.completed', 'READY', makeEnvelope()), analysis: envelope } })
    expect(state.analysis?.analysis.schema_id).toBe('ipsec-sentinel.analysis/v1')
    state = liveLabReducer(state, { type: 'PROBLEM', problem: { code: 'SESSION_BUSY', message: 'Wait.', session_id: 'SNT-AB12' } })
    expect(state.problem?.code).toBe('SESSION_BUSY')
  })

  it('reconnects from the last applied ID and rebuilds missed active traffic state', async () => {
    let handlers: LiveStreamHandlers | null = null
    const subscribe = vi.fn((_id: string, _after: number, next: LiveStreamHandlers) => {
      handlers = next
      return { close: vi.fn() }
    })
    const services = {
      scenarios: vi.fn().mockResolvedValue({ scenarios: [], workloads: ['video'] }),
      createSession: vi.fn().mockResolvedValue(baseSession),
      getSession: vi.fn().mockResolvedValue(baseSession),
      command: vi.fn().mockResolvedValue(undefined),
      subscribe,
    }
    const wrapper = ({ children }: { children: ReactNode }) => <LiveLabProvider services={services}>{children}</LiveLabProvider>
    const { result } = renderHook(() => useLiveLab(), { wrapper })

    await act(async () => { await result.current.createSession('secure-baseline') })
    act(() => handlers?.onEvent(liveEvent(1, 'session.created', 'IDLE', { display_name: 'Secure Baseline', mystery: false })))
    act(() => handlers?.onEvent(liveEvent(2, 'tunnel.active', 'TUNNEL_ACTIVE')))
    act(() => handlers?.onEvent(liveEvent(3, 'traffic.started', 'TRAFFIC_RUNNING', { workload: 'video', sequence: 1 })))
    expect(result.current.session?.state).toBe('TRAFFIC_RUNNING')

    act(() => result.current.reconnect())
    expect(subscribe).toHaveBeenLastCalledWith('SNT-AB12', 3, expect.any(Object), expect.any(Object))
    act(() => handlers?.onEvent(liveEvent(4, 'esp.observed', 'TRAFFIC_RUNNING', { packet_delta: 80, byte_delta: 12000 })))
    act(() => handlers?.onEvent(liveEvent(5, 'traffic.completed', 'TUNNEL_ACTIVE', { workload: 'video', sequence: 1, seed: 9 })))
    await waitFor(() => expect(result.current.session?.state).toBe('TUNNEL_ACTIVE'))
    expect(result.current.latestEventId).toBe(5)
    expect(result.current.events).toHaveLength(5)
  })
})
