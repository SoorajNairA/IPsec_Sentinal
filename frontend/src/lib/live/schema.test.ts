import { describe, expect, it } from 'vitest'

import { makeEnvelope } from '../../test/analysisFixture'
import {
  LIVE_EVENT_TYPES,
  LIVE_SESSION_STATES,
  parseLiveEvent,
  parseLiveSession,
} from './schema'

function event(overrides: Record<string, unknown> = {}) {
  return {
    schema: 'ipsec-sentinel.live-event/v1',
    event_id: 1,
    session_id: 'SNT-AB12',
    timestamp: '2026-09-28T10:00:00.000Z',
    type: 'session.created',
    state: 'IDLE',
    reason: 'session persisted and ready',
    data: { display_name: 'Secure Baseline', mystery: false },
    evidence: [],
    ...overrides,
  }
}

function session(overrides: Record<string, unknown> = {}) {
  return {
    session_id: 'SNT-AB12',
    display_name: 'Secure Baseline',
    state: 'IDLE',
    state_reason: 'session persisted and ready',
    tunnel_status: 'INACTIVE',
    capture_status: 'NOT_STARTED',
    cleanup_status: 'NOT_RUN',
    active_action: null,
    child_sa_established: false,
    completed_workloads: [],
    latest_completed_workload_sequence: null,
    latest_event_id: 1,
    analysis_available: false,
    mystery: false,
    revealed: false,
    failure: null,
    allowed_actions: ['CONNECT', 'DISCONNECT'],
    ...overrides,
  }
}

describe('Live Lab wire schema', () => {
  it.each(LIVE_SESSION_STATES)('accepts session state %s', (state) => {
    expect(parseLiveSession(session({ state })).state).toBe(state)
    expect(parseLiveEvent(event({ state })).state).toBe(state)
  })

  it.each(LIVE_EVENT_TYPES)('accepts known event type %s', (type) => {
    const data = type === 'analysis.completed' ? makeEnvelope() : undefined
    expect(parseLiveEvent(event({ type, ...(data ? { data } : {}) })).type).toBe(type)
  })

  it('accepts backend 64-bit workload seeds and nanosecond audit timestamps', () => {
    const parsed = parseLiveSession(session({
      state: 'TUNNEL_ACTIVE',
      tunnel_status: 'ACTIVE',
      capture_status: 'RUNNING',
      child_sa_established: true,
      latest_completed_workload_sequence: 1,
      completed_workloads: [{
        sequence: 1,
        workload_id: 'video',
        seed: Number('5041830736788146658'),
        started_at: '2026-09-28T18:34:30.184Z',
        ended_at: '2026-09-28T18:34:35.600Z',
        started_unix_ns: Number('1790620470184454632'),
        ended_unix_ns: Number('1790620475600557782'),
        validated: true,
        metadata: { generator: 'local-segmented-video' },
      }],
      allowed_actions: ['TRAFFIC', 'REKEY', 'REFRESH', 'ANALYZE', 'DISCONNECT'],
    }))

    expect(parsed.completed_workloads[0]?.workload_id).toBe('video')
  })

  it('rejects unknown event types, status values, and unsafe JSON object keys', () => {
    expect(() => parseLiveEvent(event({ type: 'progress.fabricated' }))).toThrow(/type|option/i)
    expect(() => parseLiveSession(session({ tunnel_status: 'MAYBE' }))).toThrow()
    const unsafe = JSON.parse(JSON.stringify(event()).replace(
      '"data":{',
      '"data":{"__proto__":{"polluted":true},',
    ))
    expect(() => parseLiveEvent(unsafe)).toThrow(/unsafe/i)
  })

  it('validates completed analysis and preserves literal false payload semantics', () => {
    const envelope = makeEnvelope()
    const parsed = parseLiveEvent(event({ type: 'analysis.completed', state: 'READY', data: envelope }))
    expect(parsed.analysis?.analysis.esp.payload_decrypted).toBe(false)
    expect(parsed.analysis?.analysis.traffic_intelligence.payload_decrypted).toBe(false)

    expect(() => parseLiveEvent(event({
      type: 'analysis.completed',
      state: 'READY',
      data: {
        ...envelope,
        analysis: {
          ...envelope.analysis,
          esp: { ...envelope.analysis.esp, payload_decrypted: true },
        },
      },
    }))).toThrow()
  })

  it('enforces Mystery redaction until the explicit reveal event', () => {
    expect(() => parseLiveEvent(event({
      type: 'child_sa.rekeyed',
      data: { configured: { pfs: true } },
    }), { mystery: true, revealed: false })).toThrow(/mystery/i)

    expect(parseLiveEvent(event({
      type: 'mystery.revealed',
      state: 'READY',
      data: { ground_truth: { scenario_id: 'secure-baseline' } },
    }), { mystery: true, revealed: false }).type).toBe('mystery.revealed')

    expect(() => parseLiveSession(session({
      display_name: 'Mystery VPN #01',
      mystery: true,
      scenario_id: 'secure-baseline',
    }))).toThrow(/unrecognized/i)
  })
})
