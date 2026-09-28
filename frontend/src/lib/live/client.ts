import { LIVE_EVENT_TYPES, parseLiveCatalogue, parseLiveEvent, parseLiveProblem, parseLiveSession } from './schema'
import type {
  LiveAction,
  LiveCatalogue,
  LiveLabServices,
  LiveProblemShape,
  LiveSession,
  LiveStreamHandlers,
  MysteryDecodeContext,
} from './types'

export interface EventSourceLike {
  onmessage: ((event: MessageEvent<string>) => void) | null
  onerror: ((event: Event) => void) | null
  onopen?: ((event: Event) => void) | null
  addEventListener?: (type: string, listener: EventListener) => void
  removeEventListener?: (type: string, listener: EventListener) => void
  close: () => void
}

export class LiveProblemError extends Error {
  readonly code: string
  readonly sessionId?: string

  constructor(problem: LiveProblemShape) {
    super(problem.message)
    this.name = 'LiveProblemError'
    this.code = problem.code
    this.sessionId = problem.session_id
  }
}

interface ClientOptions {
  fetcher?: typeof fetch
  eventSourceFactory?: (url: string) => EventSourceLike
}

export class LiveLabClient implements LiveLabServices {
  private readonly fetcher: typeof fetch
  private readonly eventSourceFactory: (url: string) => EventSourceLike

  constructor(options: ClientOptions = {}) {
    this.fetcher = options.fetcher ?? fetch.bind(globalThis)
    this.eventSourceFactory = options.eventSourceFactory ?? ((url) => new EventSource(url))
  }

  async scenarios(): Promise<LiveCatalogue> {
    return parseLiveCatalogue(await this.request('/api/lab/scenarios'))
  }

  async createSession(scenarioId: string): Promise<LiveSession> {
    const payload = await this.request('/api/lab/sessions', { scenario_id: scenarioId }) as { session?: unknown }
    return parseLiveSession(payload.session)
  }

  async getSession(sessionId: string): Promise<LiveSession> {
    const payload = await this.request(`/api/lab/sessions/${encodeURIComponent(sessionId)}`) as { session?: unknown }
    return parseLiveSession(payload.session)
  }

  async command(sessionId: string, action: LiveAction, payload: Record<string, unknown> = {}): Promise<void> {
    await this.request(
      `/api/lab/sessions/${encodeURIComponent(sessionId)}/${action.toLowerCase()}`,
      payload,
    )
  }

  subscribe(
    sessionId: string,
    afterEventId: number,
    handlers: LiveStreamHandlers,
    mystery?: MysteryDecodeContext,
  ) {
    const url = `/api/lab/sessions/${encodeURIComponent(sessionId)}/events?lastEventId=${afterEventId}`
    const source = this.eventSourceFactory(url)
    source.onopen = () => handlers.onOpen?.()
    const receive = (raw: Event) => {
      const message = raw as MessageEvent<string>
      try {
        const event = parseLiveEvent(JSON.parse(message.data), mystery)
        if (message.lastEventId && Number(message.lastEventId) !== event.event_id) {
          throw new Error('SSE event ID does not match its payload')
        }
        handlers.onEvent(event)
      } catch (error) {
        handlers.onError({
          code: 'INVALID_LIVE_EVENT',
          message: error instanceof Error ? error.message : 'Live event could not be decoded.',
          session_id: sessionId,
        })
      }
    }
    source.onmessage = receive
    if (source.addEventListener) {
      for (const type of LIVE_EVENT_TYPES) source.addEventListener(type, receive)
    }
    source.onerror = () => handlers.onError({
      code: 'EVENT_STREAM_INTERRUPTED',
      message: 'Live event stream interrupted; the browser will resume from the last event ID.',
      session_id: sessionId,
    })
    return { close: () => {
      if (source.removeEventListener) {
        for (const type of LIVE_EVENT_TYPES) source.removeEventListener(type, receive)
      }
      source.close()
    } }
  }

  private async request(path: string, body?: Record<string, unknown>): Promise<unknown> {
    const response = await this.fetcher(path, body === undefined ? undefined : {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    let payload: unknown
    try {
      payload = await response.json()
    } catch {
      throw new LiveProblemError({ code: 'INVALID_RESPONSE', message: 'Sentinel Agent returned invalid JSON.' })
    }
    if (!response.ok) {
      try {
        throw new LiveProblemError(parseLiveProblem(payload))
      } catch (error) {
        if (error instanceof LiveProblemError) throw error
        throw new LiveProblemError({ code: 'REQUEST_FAILED', message: `Sentinel Agent request failed (${response.status}).` })
      }
    }
    return payload
  }
}

export const defaultLiveLabServices: LiveLabServices = new LiveLabClient()
