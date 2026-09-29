import { z } from 'zod'

import { parseAnalysisEnvelope } from '../analysis-contract/load'
import type { LiveEvent, LiveSession, MysteryDecodeContext } from './types'

export const LIVE_SESSION_STATES = [
  'CREATING_SESSION', 'IDLE', 'PREPARING_SANDBOX', 'STARTING_ENDPOINT', 'WAITING_FOR_ENDPOINT',
  'STARTING_CAPTURE', 'IKE_NEGOTIATING', 'AUTHENTICATING', 'CHILD_SA_ESTABLISHED',
  'TUNNEL_ACTIVE', 'TRAFFIC_RUNNING', 'REKEYING', 'ANALYZING', 'READY', 'DISCONNECTING',
  'CLEANING_UP', 'COMPLETE', 'FAILED',
] as const

export const LIVE_ACTIONS = ['CONNECT', 'TRAFFIC', 'REKEY', 'REFRESH', 'ANALYZE', 'REVEAL', 'DISCONNECT'] as const

export const LIVE_EVENT_TYPES = [
  'session.created', 'action.accepted', 'action.completed', 'action.failed',
  'sandbox.preparing', 'sandbox.prepared', 'endpoint.starting', 'endpoint.waiting', 'endpoint.ready',
  'capture.starting', 'capture.started', 'capture.sealed', 'ipsec.configuration.loaded',
  'ike.negotiating', 'ike.sa_init.request', 'ike.sa_init.response', 'ike.proposal.selected',
  'ike.auth.request', 'ike.auth.response', 'ike.sa.established', 'ike.sa.verified',
  'child_sa.observed', 'child_sa.verified', 'xfrm.verified', 'tunnel.active',
  'traffic.preparing', 'traffic.started', 'esp.observed', 'traffic.completed', 'traffic.failed',
  'rekey.started', 'child_sa.rekeyed', 'sa.refreshed', 'analysis.started', 'analysis.completed',
  'mystery.revealed', 'disconnect.started', 'cleanup.started', 'cleanup.completed', 'cleanup.failed',
] as const

const jsonRecord = z.record(z.string(), z.unknown())
const isoTimestamp = z.string().min(1).refine((value) => Number.isFinite(Date.parse(value)), 'invalid timestamp')
// Python records 64-bit seeds and epoch nanoseconds. JSON numbers preserve
// their magnitude in the browser but not exact precision above 2^53; the UI
// treats these fields as opaque audit metadata and never computes with them.
const auditInteger = z.number().refine(Number.isInteger, 'Expected an integer')
const auditNonnegativeInteger = auditInteger.refine((value) => value >= 0, 'Expected a non-negative integer')

const workloadWindowSchema = z.object({
  sequence: z.number().int().positive(),
  workload_id: z.string().min(1),
  seed: auditNonnegativeInteger,
  started_at: isoTimestamp,
  ended_at: isoTimestamp,
  started_unix_ns: auditNonnegativeInteger,
  ended_unix_ns: auditNonnegativeInteger,
  validated: z.boolean(),
  metadata: jsonRecord,
}).strict()

const liveSessionSchema = z.object({
  session_id: z.string().min(1),
  display_name: z.string().min(1),
  state: z.enum(LIVE_SESSION_STATES),
  state_reason: z.string().min(1),
  tunnel_status: z.enum(['INACTIVE', 'ACTIVE', 'DISCONNECTED', 'FAILED']),
  capture_status: z.enum(['NOT_STARTED', 'RUNNING', 'SEALED', 'STOPPED', 'FAILED']),
  cleanup_status: z.enum(['NOT_RUN', 'RUNNING', 'SUCCEEDED', 'FAILED']),
  active_action: z.enum(LIVE_ACTIONS).nullable(),
  child_sa_established: z.boolean(),
  completed_workloads: z.array(workloadWindowSchema),
  latest_completed_workload_sequence: z.number().int().positive().nullable(),
  latest_event_id: z.number().int().nonnegative(),
  analysis_available: z.boolean(),
  mystery: z.boolean(),
  revealed: z.boolean(),
  failure: jsonRecord.nullable(),
  allowed_actions: z.array(z.enum(LIVE_ACTIONS)),
}).strict()

const liveEventSchema = z.object({
  schema: z.literal('ipsec-sentinel.live-event/v1'),
  event_id: z.number().int().positive(),
  session_id: z.string().min(1),
  timestamp: isoTimestamp,
  type: z.enum(LIVE_EVENT_TYPES),
  state: z.enum(LIVE_SESSION_STATES),
  reason: z.string().min(1),
  data: jsonRecord,
  evidence: z.array(jsonRecord),
}).strict()

function assertSafeJson(value: unknown, path = '$'): void {
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertSafeJson(item, `${path}[${index}]`))
    return
  }
  if (value === null || typeof value !== 'object') return
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) throw new Error(`Unsafe JSON object at ${path}`)
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      throw new Error(`Unsafe JSON key at ${path}.${key}`)
    }
    assertSafeJson(child, `${path}.${key}`)
  }
}

function containsWithheldConfiguration(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(containsWithheldConfiguration)
  if (value === null || typeof value !== 'object') return false
  return Object.entries(value as Record<string, unknown>).some(([key, child]) => (
    key === 'configured' || key === 'ground_truth' || key === 'scenario_id' || containsWithheldConfiguration(child)
  ))
}

export function parseLiveSession(input: unknown): LiveSession {
  assertSafeJson(input)
  const session = liveSessionSchema.parse(input)
  if (!session.mystery && session.revealed) throw new Error('Only a Mystery session may be revealed')
  return session
}

export function parseLiveEvent(input: unknown, mystery?: MysteryDecodeContext): LiveEvent {
  assertSafeJson(input)
  const event = liveEventSchema.parse(input)
  if (
    mystery?.mystery && !mystery.revealed && event.type !== 'mystery.revealed'
    && containsWithheldConfiguration(event.data)
  ) {
    throw new Error('Mystery configuration was exposed before reveal')
  }
  if (event.type === 'analysis.completed') {
    return { ...event, analysis: parseAnalysisEnvelope(event.data) }
  }
  return event
}

export function parseLiveCatalogue(input: unknown) {
  assertSafeJson(input)
  return z.object({
    scenarios: z.array(z.object({ id: z.string().min(1), display_name: z.string().min(1), mystery: z.boolean() }).strict()),
    workloads: z.array(z.string().min(1)),
  }).strict().parse(input)
}

export function parseLiveProblem(input: unknown) {
  assertSafeJson(input)
  return z.object({
    error: z.object({ code: z.string().min(1), message: z.string().min(1), session_id: z.string().min(1).optional() }).strict(),
  }).strict().parse(input).error
}
