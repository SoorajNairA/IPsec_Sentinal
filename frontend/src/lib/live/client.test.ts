import { describe, expect, it, vi } from 'vitest'

import { makeEnvelope } from '../../test/analysisFixture'
import { LiveLabClient, type EventSourceLike } from './client'

class FakeEventSource implements EventSourceLike {
  onmessage: ((event: MessageEvent<string>) => void) | null = null
  onerror: ((event: Event) => void) | null = null
  closed = false
  listeners = new Map<string, EventListener>()

  close() { this.closed = true }
  addEventListener(type: string, listener: EventListener) { this.listeners.set(type, listener) }
  removeEventListener(type: string) { this.listeners.delete(type) }
  emit(type: string, event: MessageEvent<string>) { this.listeners.get(type)?.(event) }
}

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function wireEvent(id: number, type = 'traffic.started', data: unknown = { workload: 'video' }) {
  return {
    schema: 'ipsec-sentinel.live-event/v1',
    event_id: id,
    session_id: 'SNT-AB12',
    timestamp: '2026-09-28T10:00:00.000Z',
    type,
    state: type === 'traffic.started' ? 'TRAFFIC_RUNNING' : 'TUNNEL_ACTIVE',
    reason: type,
    data,
    evidence: [],
  }
}

describe('LiveLabClient', () => {
  it('uses strict JSON REST requests and exposes structured command problems', async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(response({
        scenarios: [{ id: 'secure-baseline', display_name: 'Secure Baseline', mystery: false }],
        workloads: ['icmp', 'video'],
      }))
      .mockResolvedValueOnce(response({ error: { code: 'TUNNEL_NOT_ACTIVE', message: 'Connect first.', session_id: 'SNT-AB12' } }, 409))
    const client = new LiveLabClient({ fetcher })

    expect((await client.scenarios()).workloads).toEqual(['icmp', 'video'])
    await expect(client.command('SNT-AB12', 'TRAFFIC', { workload_id: 'video' }))
      .rejects.toMatchObject({ code: 'TUNNEL_NOT_ACTIVE', sessionId: 'SNT-AB12' })
    expect(fetcher).toHaveBeenLastCalledWith('/api/lab/sessions/SNT-AB12/traffic', expect.objectContaining({
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ workload_id: 'video' }),
    }))
  })

  it('opens replay from the last applied event ID and validates streamed events', () => {
    const source = new FakeEventSource()
    const factory = vi.fn(() => source)
    const received = vi.fn()
    const client = new LiveLabClient({ eventSourceFactory: factory })
    const subscription = client.subscribe('SNT-AB12', 14, { onEvent: received, onError: vi.fn() })

    expect(factory).toHaveBeenCalledWith('/api/lab/sessions/SNT-AB12/events?lastEventId=14')
    source.emit('traffic.started', new MessageEvent('traffic.started', {
      data: JSON.stringify(wireEvent(15)),
      lastEventId: '15',
    }))
    expect(received).toHaveBeenCalledWith(expect.objectContaining({ event_id: 15 }))
    subscription.close()
    expect(source.closed).toBe(true)
  })

  it('replays missed persisted traffic events after reconnect without mixing analysis windows', () => {
    const first = new FakeEventSource()
    const second = new FakeEventSource()
    const factory = vi.fn()
      .mockReturnValueOnce(first)
      .mockReturnValueOnce(second)
    const received: number[] = []
    const client = new LiveLabClient({ eventSourceFactory: factory })

    client.subscribe('SNT-AB12', 20, { onEvent: (item) => received.push(item.event_id), onError: vi.fn() }).close()
    client.subscribe('SNT-AB12', 20, { onEvent: (item) => received.push(item.event_id), onError: vi.fn() })
    second.emit('traffic.started', new MessageEvent('traffic.started', { data: JSON.stringify(wireEvent(21)), lastEventId: '21' }))
    second.emit('esp.observed', new MessageEvent('esp.observed', { data: JSON.stringify(wireEvent(22, 'esp.observed', { packet_delta: 80, byte_delta: 12000 })), lastEventId: '22' }))
    second.emit('traffic.completed', new MessageEvent('traffic.completed', { data: JSON.stringify(wireEvent(23, 'traffic.completed', { workload: 'video', sequence: 2 })), lastEventId: '23' }))

    expect(factory).toHaveBeenLastCalledWith('/api/lab/sessions/SNT-AB12/events?lastEventId=20')
    expect(received).toEqual([21, 22, 23])
  })

  it('hands off a fully validated analysis envelope', () => {
    const source = new FakeEventSource()
    const received = vi.fn()
    const client = new LiveLabClient({ eventSourceFactory: () => source })
    client.subscribe('SNT-AB12', 30, { onEvent: received, onError: vi.fn() }, { mystery: false, revealed: false })
    source.emit('analysis.completed', new MessageEvent('analysis.completed', {
      data: JSON.stringify(wireEvent(31, 'analysis.completed', makeEnvelope())),
      lastEventId: '31',
    }))
    expect(received.mock.calls[0][0].analysis.analysis.schema_id).toBe('ipsec-sentinel.analysis/v1')
  })
})
