import type { AnalysisEnvelope } from '../analysis-contract/types'

export type LiveSessionState =
  | 'CREATING_SESSION' | 'IDLE' | 'PREPARING_SANDBOX' | 'STARTING_ENDPOINT'
  | 'WAITING_FOR_ENDPOINT' | 'STARTING_CAPTURE' | 'IKE_NEGOTIATING' | 'AUTHENTICATING'
  | 'CHILD_SA_ESTABLISHED' | 'TUNNEL_ACTIVE' | 'TRAFFIC_RUNNING' | 'REKEYING'
  | 'ANALYZING' | 'READY' | 'DISCONNECTING' | 'CLEANING_UP' | 'COMPLETE' | 'FAILED'

export type LiveAction = 'CONNECT' | 'TRAFFIC' | 'REKEY' | 'REFRESH' | 'ANALYZE' | 'REVEAL' | 'DISCONNECT'
export type TunnelStatus = 'INACTIVE' | 'ACTIVE' | 'DISCONNECTED' | 'FAILED'
export type CaptureStatus = 'NOT_STARTED' | 'RUNNING' | 'SEALED' | 'STOPPED' | 'FAILED'
export type CleanupStatus = 'NOT_RUN' | 'RUNNING' | 'SUCCEEDED' | 'FAILED'

export interface WorkloadWindow {
  sequence: number
  workload_id: string
  seed: number
  started_at: string
  ended_at: string
  started_unix_ns: number
  ended_unix_ns: number
  validated: boolean
  metadata: Record<string, unknown>
}

export interface LiveProblemShape {
  code: string
  message: string
  session_id?: string
}

export interface LiveSession {
  session_id: string
  display_name: string
  state: LiveSessionState
  state_reason: string
  tunnel_status: TunnelStatus
  capture_status: CaptureStatus
  cleanup_status: CleanupStatus
  active_action: LiveAction | null
  child_sa_established: boolean
  completed_workloads: WorkloadWindow[]
  latest_completed_workload_sequence: number | null
  latest_event_id: number
  analysis_available: boolean
  mystery: boolean
  revealed: boolean
  failure: Record<string, unknown> | null
  allowed_actions: LiveAction[]
}

export interface LiveEvidenceReference {
  source?: string
  record?: string
  [key: string]: unknown
}

export interface LiveEvent {
  schema: 'ipsec-sentinel.live-event/v1'
  event_id: number
  session_id: string
  timestamp: string
  type: LiveEventType
  state: LiveSessionState
  reason: string
  data: Record<string, unknown>
  evidence: LiveEvidenceReference[]
  analysis?: AnalysisEnvelope
}

export type LiveEventType =
  | 'session.created' | 'action.accepted' | 'action.completed' | 'action.failed'
  | 'sandbox.preparing' | 'sandbox.prepared' | 'endpoint.starting' | 'endpoint.waiting'
  | 'endpoint.ready' | 'capture.starting' | 'capture.started' | 'capture.sealed'
  | 'ipsec.configuration.loaded' | 'ike.negotiating' | 'ike.sa_init.request'
  | 'ike.sa_init.response' | 'ike.proposal.selected' | 'ike.auth.request'
  | 'ike.auth.response' | 'ike.sa.established' | 'ike.sa.verified'
  | 'child_sa.observed' | 'child_sa.verified' | 'xfrm.verified' | 'tunnel.active'
  | 'traffic.preparing' | 'traffic.started' | 'esp.observed' | 'traffic.completed'
  | 'traffic.failed' | 'rekey.started' | 'child_sa.rekeyed' | 'sa.refreshed'
  | 'analysis.started' | 'analysis.completed' | 'mystery.revealed'
  | 'disconnect.started' | 'cleanup.started' | 'cleanup.completed' | 'cleanup.failed'

export interface LabScenario {
  id: string
  display_name: string
  mystery: boolean
}

export interface LiveCatalogue {
  scenarios: LabScenario[]
  workloads: string[]
}

export interface LiveStreamHandlers {
  onEvent: (event: LiveEvent) => void
  onError: (problem: LiveProblemShape) => void
  onOpen?: () => void
}

export interface LiveSubscription { close: () => void }

export interface MysteryDecodeContext {
  mystery: boolean
  revealed: boolean
}

export interface LiveLabServices {
  scenarios: () => Promise<LiveCatalogue>
  createSession: (scenarioId: string) => Promise<LiveSession>
  getSession: (sessionId: string) => Promise<LiveSession>
  command: (sessionId: string, action: LiveAction, payload?: Record<string, unknown>) => Promise<void>
  subscribe: (
    sessionId: string,
    afterEventId: number,
    handlers: LiveStreamHandlers,
    mystery?: MysteryDecodeContext,
  ) => LiveSubscription
}
