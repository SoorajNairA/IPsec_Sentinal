/* oxlint-disable react/only-export-components -- reducer, provider, and hook form one public state contract */
import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useLayoutEffect,
  useMemo,
  useReducer,
  useRef,
} from 'react'

import type { AnalysisEnvelope } from '../lib/analysis-contract/types'
import { defaultLiveLabServices, LiveProblemError } from '../lib/live/client'
import type {
  CaptureStatus,
  CleanupStatus,
  LiveAction,
  LiveCatalogue,
  LiveEvent,
  LiveLabServices,
  LiveProblemShape,
  LiveSession,
  LiveSubscription,
  TunnelStatus,
  WorkloadWindow,
} from '../lib/live/types'

export interface LiveLabState {
  catalogue: LiveCatalogue | null
  session: LiveSession | null
  events: LiveEvent[]
  latestEventId: number
  analysis: AnalysisEnvelope | null
  streamStatus: 'CLOSED' | 'CONNECTING' | 'OPEN' | 'INTERRUPTED'
  problem: LiveProblemShape | null
}

type LiveLabReducerAction =
  | { type: 'CATALOGUE'; catalogue: LiveCatalogue }
  | { type: 'SESSION_LOADED'; session: LiveSession; replayFromStart: boolean }
  | { type: 'SESSION_SYNCED'; session: LiveSession }
  | { type: 'EVENT'; event: LiveEvent }
  | { type: 'STREAM_STATUS'; status: LiveLabState['streamStatus'] }
  | { type: 'PROBLEM'; problem: LiveProblemShape | null }
  | { type: 'RESET' }

const initialState: LiveLabState = {
  catalogue: null,
  session: null,
  events: [],
  latestEventId: 0,
  analysis: null,
  streamStatus: 'CLOSED',
  problem: null,
}

function actionsForProjection(session: LiveSession): LiveAction[] {
  if (session.active_action) return []
  if (session.state === 'IDLE') return ['CONNECT', 'DISCONNECT']
  if (session.state === 'TUNNEL_ACTIVE' && session.tunnel_status === 'ACTIVE' && session.capture_status === 'RUNNING') {
    const actions: LiveAction[] = ['TRAFFIC']
    if (session.child_sa_established) actions.push('REKEY')
    actions.push('REFRESH')
    if (session.latest_completed_workload_sequence !== null) actions.push('ANALYZE')
    actions.push('DISCONNECT')
    return actions
  }
  if (session.state === 'READY') return session.mystery && !session.revealed ? ['REVEAL', 'DISCONNECT'] : ['DISCONNECT']
  if (session.state === 'FAILED' || session.state === 'COMPLETE') return ['DISCONNECT']
  return []
}

function stringValue(data: Record<string, unknown>, key: string): string | undefined {
  return typeof data[key] === 'string' ? data[key] : undefined
}

function numberValue(data: Record<string, unknown>, key: string): number | undefined {
  return typeof data[key] === 'number' ? data[key] : undefined
}

function projectEvent(session: LiveSession, event: LiveEvent): LiveSession {
  let tunnelStatus: TunnelStatus = session.tunnel_status
  let captureStatus: CaptureStatus = session.capture_status
  let cleanupStatus: CleanupStatus = session.cleanup_status
  let activeAction = session.active_action
  let childSaEstablished = session.child_sa_established
  let analysisAvailable = session.analysis_available
  let revealed = session.revealed
  let failure = session.failure
  let completedWorkloads = session.completed_workloads
  let latestCompleted = session.latest_completed_workload_sequence

  if (event.type === 'action.accepted') activeAction = stringValue(event.data, 'action') as LiveAction | undefined ?? null
  if (event.type === 'action.completed' || event.type === 'action.failed') activeAction = null
  if (event.type === 'capture.started') captureStatus = 'RUNNING'
  if (event.type === 'capture.sealed') captureStatus = 'SEALED'
  if (event.type === 'child_sa.verified') childSaEstablished = true
  if (event.type === 'tunnel.active') tunnelStatus = 'ACTIVE'
  if (event.type === 'analysis.completed') analysisAvailable = true
  if (event.type === 'mystery.revealed') revealed = true
  if (event.type === 'disconnect.started') tunnelStatus = session.tunnel_status
  if (event.type === 'cleanup.started') cleanupStatus = 'RUNNING'
  if (event.type === 'cleanup.completed') {
    cleanupStatus = 'SUCCEEDED'
    tunnelStatus = 'DISCONNECTED'
    if (captureStatus === 'RUNNING') captureStatus = 'STOPPED'
  }
  if (event.type === 'cleanup.failed') cleanupStatus = 'FAILED'
  if (event.type === 'action.failed') {
    const candidate = event.data.error
    failure = candidate && typeof candidate === 'object' && !Array.isArray(candidate)
      ? candidate as Record<string, unknown>
      : { code: 'ACTION_FAILED', message: event.reason }
  }
  if (event.type === 'traffic.completed') {
    const sequence = numberValue(event.data, 'sequence')
    const workloadId = stringValue(event.data, 'workload')
    if (sequence !== undefined && workloadId) {
      const workload: WorkloadWindow = {
        sequence,
        workload_id: workloadId,
        seed: numberValue(event.data, 'seed') ?? 0,
        started_at: event.timestamp,
        ended_at: event.timestamp,
        started_unix_ns: 0,
        ended_unix_ns: 0,
        validated: true,
        metadata: { validation: event.data.validation ?? null },
      }
      completedWorkloads = [...completedWorkloads.filter((item) => item.sequence !== sequence), workload]
      latestCompleted = sequence
    }
  }

  const projected: LiveSession = {
    ...session,
    state: event.state,
    state_reason: event.reason,
    latest_event_id: event.event_id,
    tunnel_status: tunnelStatus,
    capture_status: captureStatus,
    cleanup_status: cleanupStatus,
    active_action: activeAction,
    child_sa_established: childSaEstablished,
    analysis_available: analysisAvailable,
    revealed,
    failure,
    completed_workloads: completedWorkloads,
    latest_completed_workload_sequence: latestCompleted,
    allowed_actions: [],
  }
  return { ...projected, allowed_actions: actionsForProjection(projected) }
}

export function liveLabReducer(state: LiveLabState, action: LiveLabReducerAction): LiveLabState {
  if (action.type === 'CATALOGUE') return { ...state, catalogue: action.catalogue }
  if (action.type === 'STREAM_STATUS') return { ...state, streamStatus: action.status }
  if (action.type === 'PROBLEM') return { ...state, problem: action.problem }
  if (action.type === 'RESET') return { ...initialState, catalogue: state.catalogue }
  if (action.type === 'SESSION_LOADED') {
    return {
      ...state,
      session: action.session,
      events: action.replayFromStart ? [] : state.events,
      latestEventId: action.replayFromStart ? 0 : action.session.latest_event_id,
      analysis: action.replayFromStart ? null : state.analysis,
      problem: null,
    }
  }
  if (action.type === 'SESSION_SYNCED') {
    if (!state.session || action.session.session_id !== state.session.session_id) return state
    if (action.session.latest_event_id !== state.latestEventId) return state
    return { ...state, session: { ...action.session, latest_event_id: state.latestEventId } }
  }
  const event = action.event
  if (!state.session) throw new Error('Cannot apply a Live Lab event without a session')
  if (event.session_id !== state.session.session_id) throw new Error('Live Lab event belongs to another session')
  if (event.event_id <= state.latestEventId) return state
  if (event.event_id !== state.latestEventId + 1) throw new Error('Live Lab events must be applied in exact ordered sequence')
  return {
    ...state,
    session: projectEvent(state.session, event),
    events: [...state.events, event],
    latestEventId: event.event_id,
    analysis: event.analysis ?? state.analysis,
    problem: null,
  }
}

interface LiveLabContextValue extends LiveLabState {
  loadCatalogue: () => Promise<void>
  createSession: (scenarioId: string) => Promise<void>
  connect: () => Promise<void>
  runTraffic: (workloadId: string) => Promise<void>
  triggerRekey: () => Promise<void>
  refresh: () => Promise<void>
  analyze: () => Promise<void>
  reveal: () => Promise<void>
  disconnect: () => Promise<void>
  reconnect: () => void
  reset: () => void
}

const LiveLabContext = createContext<LiveLabContextValue | null>(null)
const STORAGE_KEY = 'ipsec-sentinel.live-session-id'

function toProblem(error: unknown, sessionId?: string): LiveProblemShape {
  if (error instanceof LiveProblemError) return { code: error.code, message: error.message, ...(error.sessionId ? { session_id: error.sessionId } : {}) }
  return { code: 'LIVE_LAB_FAILED', message: error instanceof Error ? error.message : 'Live Lab operation failed.', ...(sessionId ? { session_id: sessionId } : {}) }
}

export function LiveLabProvider({ children, services = defaultLiveLabServices }: { children: ReactNode; services?: LiveLabServices }) {
  const [state, dispatch] = useReducer(liveLabReducer, initialState)
  const stateRef = useRef(state)
  const subscriptionRef = useRef<LiveSubscription | null>(null)
  const catalogueRequestRef = useRef<Promise<void> | null>(null)
  useLayoutEffect(() => {
    stateRef.current = state
  }, [state])

  const subscribe = useCallback((session: LiveSession, afterEventId: number) => {
    subscriptionRef.current?.close()
    dispatch({ type: 'STREAM_STATUS', status: 'CONNECTING' })
    subscriptionRef.current = services.subscribe(session.session_id, afterEventId, {
      onOpen: () => dispatch({ type: 'STREAM_STATUS', status: 'OPEN' }),
      onEvent: (event) => {
        try {
          dispatch({ type: 'EVENT', event })
          if (event.type === 'action.completed' || event.type === 'action.failed' || event.type === 'cleanup.completed') {
            void services.getSession(session.session_id).then((snapshot) => {
              dispatch({ type: 'SESSION_SYNCED', session: snapshot })
            }).catch((error: unknown) => dispatch({ type: 'PROBLEM', problem: toProblem(error, session.session_id) }))
          }
        } catch (error) {
          dispatch({ type: 'PROBLEM', problem: toProblem(error, session.session_id) })
        }
      },
      onError: (problem) => {
        dispatch({ type: 'STREAM_STATUS', status: 'INTERRUPTED' })
        dispatch({ type: 'PROBLEM', problem })
      },
    }, { mystery: session.mystery, revealed: session.revealed })
  }, [services])

  useEffect(() => {
    let disposed = false
    const storedSessionId = window.localStorage.getItem(STORAGE_KEY)
    if (storedSessionId) {
      void services.getSession(storedSessionId).then((session) => {
        if (disposed) return
        dispatch({ type: 'SESSION_LOADED', session, replayFromStart: true })
        subscribe(session, 0)
      }).catch(() => {
        if (!disposed) window.localStorage.removeItem(STORAGE_KEY)
      })
    }
    return () => {
      disposed = true
      subscriptionRef.current?.close()
    }
  }, [services, subscribe])

  const loadCatalogue = useCallback((): Promise<void> => {
    if (stateRef.current.catalogue) return Promise.resolve()
    if (catalogueRequestRef.current) return catalogueRequestRef.current
    const request = services.scenarios().then((catalogue) => {
      dispatch({ type: 'CATALOGUE', catalogue })
      dispatch({ type: 'PROBLEM', problem: null })
    }).catch((error: unknown) => {
      dispatch({ type: 'PROBLEM', problem: toProblem(error) })
    }).finally(() => {
      if (catalogueRequestRef.current === request) catalogueRequestRef.current = null
    })
    catalogueRequestRef.current = request
    return request
  }, [services])

  const createSession = useCallback(async (scenarioId: string) => {
    try {
      const session = await services.createSession(scenarioId)
      window.localStorage.setItem(STORAGE_KEY, session.session_id)
      dispatch({ type: 'SESSION_LOADED', session, replayFromStart: true })
      subscribe(session, 0)
    } catch (error) {
      dispatch({ type: 'PROBLEM', problem: toProblem(error) })
    }
  }, [services, subscribe])

  const command = useCallback(async (action: LiveAction, payload: Record<string, unknown> = {}) => {
    const session = stateRef.current.session
    if (!session) {
      dispatch({ type: 'PROBLEM', problem: { code: 'NO_ACTIVE_SESSION', message: 'Create a Live Lab session first.' } })
      return
    }
    try {
      await services.command(session.session_id, action, payload)
    } catch (error) {
      dispatch({ type: 'PROBLEM', problem: toProblem(error, session.session_id) })
    }
  }, [services])

  const reconnect = useCallback(() => {
    const session = stateRef.current.session
    if (session) subscribe(session, stateRef.current.latestEventId)
  }, [subscribe])

  const reset = useCallback(() => {
    subscriptionRef.current?.close()
    subscriptionRef.current = null
    window.localStorage.removeItem(STORAGE_KEY)
    dispatch({ type: 'RESET' })
  }, [])

  const value = useMemo<LiveLabContextValue>(() => ({
    ...state,
    loadCatalogue,
    createSession,
    connect: () => command('CONNECT'),
    runTraffic: (workloadId) => command('TRAFFIC', { workload_id: workloadId }),
    triggerRekey: () => command('REKEY'),
    refresh: () => command('REFRESH'),
    analyze: () => command('ANALYZE'),
    reveal: () => command('REVEAL'),
    disconnect: () => command('DISCONNECT'),
    reconnect,
    reset,
  }), [state, loadCatalogue, createSession, command, reconnect, reset])

  return <LiveLabContext.Provider value={value}>{children}</LiveLabContext.Provider>
}

export function useLiveLab(): LiveLabContextValue {
  const value = useContext(LiveLabContext)
  if (!value) throw new Error('useLiveLab must be used within LiveLabProvider')
  return value
}
