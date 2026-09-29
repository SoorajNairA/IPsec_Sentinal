import { z } from 'zod'

export const provenanceSchema = z.enum(['OBSERVED', 'DERIVED', 'AI_INFERRED', 'UNKNOWN'])

const normalizedFieldSchema = z.object({
  raw: z.unknown(),
  normalized: z.unknown(),
  provenance: provenanceSchema,
  evidence_id: z.string().optional(),
}).passthrough()

export const evidenceRecordSchema = z.object({
  id: z.string().min(1),
  provenance: provenanceSchema,
  description: z.string(),
  packet_numbers: z.array(z.number().int().nonnegative()),
  timestamps_ns: z.array(z.number().nonnegative()),
  protocol: z.string().nullable().optional(),
  raw_value: z.unknown().optional(),
  normalized_value: z.unknown().optional(),
  source_component: z.string(),
  confidence: z.number().min(0).max(1).nullable().optional(),
}).passthrough()

const findingSchema = z.object({
  rule_id: z.string(),
  title: z.string(),
  severity: z.string(),
  status: z.string(),
  provenance: provenanceSchema,
  summary: z.string(),
  technical_explanation: z.string(),
  impact: z.string(),
  recommendation: z.string(),
  evidence_ids: z.array(z.string()),
}).passthrough()

const deductionSchema = z.object({
  rule_id: z.string(),
  points: z.number().nonnegative(),
  evidence_ids: z.array(z.string()),
}).passthrough()

const scoreCategorySchema = z.object({
  name: z.string(),
  maximum_score: z.number().min(0).max(100),
  achieved_score: z.number().min(0).max(100),
  assessed_weight: z.number().min(0).max(100),
  unassessed_weight: z.number().min(0).max(100),
  deductions: z.array(deductionSchema),
}).passthrough()

export const analysisSchema = z.object({
  analysis_version: z.literal('1.0'),
  schema_id: z.literal('ipsec-sentinel.analysis/v1'),
  capture: z.object({
    path: z.string(),
    format: z.string(),
    packet_count: z.number().int().nonnegative(),
    capture_bytes: z.number().nonnegative(),
    first_timestamp_ns: z.number().nonnegative().optional(),
    last_timestamp_ns: z.number().nonnegative().optional(),
    duration_seconds: z.number().nonnegative(),
    warnings: z.array(z.string()),
  }).passthrough(),
  summary: z.object({
    status: z.string(),
    ipsec: z.string(),
    message: z.string(),
  }).passthrough(),
  peers: z.object({
    initiator: z.string(),
    responder: z.string(),
    peer_pairs: z.array(z.array(z.string()).length(2)),
    multiple_sessions: z.boolean(),
  }).passthrough(),
  protocols: z.object({
    ipsec_detected: z.boolean(),
    ike_detected: z.boolean(),
    ike_version: z.string(),
    esp_detected: z.boolean(),
    ah_detected: z.boolean(),
    natt_detected: z.boolean(),
    ike_packets: z.number().int().nonnegative(),
    esp_packets: z.number().int().nonnegative(),
    ah_packets: z.number().int().nonnegative(),
    natt_packets: z.number().int().nonnegative(),
    peer_pairs: z.array(z.array(z.string()).length(2)),
  }).passthrough(),
  ike: z.object({
    detected: z.boolean(),
    version: z.string(),
    exchanges: z.array(z.unknown()),
    initiator_spi: z.string(),
    responder_spi: z.string(),
    encryption: normalizedFieldSchema,
    integrity: normalizedFieldSchema,
    prf: normalizedFieldSchema,
    dh_group: normalizedFieldSchema,
    selection_basis: z.string(),
    traffic_selectors: z.object({ value: z.unknown(), provenance: provenanceSchema }).passthrough(),
  }).passthrough(),
  controlled_evidence: z.object({ available: z.boolean(), source: z.string() }).passthrough(),
  security_associations: z.array(z.object({
    sa_type: z.string(),
    source: z.string(),
    destination: z.string(),
    spi: z.string(),
    first_packet_number: z.number().int().nonnegative(),
    first_timestamp_ns: z.number().nonnegative(),
    packet_count: z.number().int().nonnegative(),
    unique_packet_count: z.number().int().nonnegative(),
    bytes: z.number().nonnegative(),
    predecessor_spi: z.string().nullable(),
    successor_spi: z.string().nullable(),
    rekey_provenance: provenanceSchema,
    rekey_evidence_id: z.string().optional(),
    pfs: z.object({ state: z.string(), provenance: provenanceSchema }).passthrough(),
  }).passthrough()),
  pfs: z.object({
    state: z.string(),
    provenance: provenanceSchema,
    evidence_ids: z.array(z.string()),
    explanation: z.string(),
  }).passthrough().optional(),
  esp: z.object({
    packet_count: z.number().int().nonnegative(),
    bytes: z.number().nonnegative(),
    duration_seconds: z.number().nonnegative(),
    direction_counts: z.record(z.string(), z.number().nonnegative()),
    direction_bytes: z.record(z.string(), z.number().nonnegative()),
    spi_distribution: z.record(z.string(), z.number().nonnegative()),
    peer_pair: z.array(z.string()).length(2).nullable(),
    features: z.record(z.string(), z.number()).nullable(),
    feature_schema_version: z.string(),
    payload_decrypted: z.literal(false),
  }).passthrough(),
  traffic_intelligence: z.object({
    state: z.string(),
    predicted_class: z.string(),
    raw_confidence: z.number().min(0).max(1).nullable(),
    confidence_kind: z.literal('raw_uncalibrated'),
    probabilities: z.record(z.string(), z.number().min(0).max(1)),
    provenance: provenanceSchema,
    model_version: z.string(),
    feature_schema_version: z.string(),
    payload_decrypted: z.literal(false),
    reason: z.string().nullable().optional(),
  }).passthrough(),
  evidence: z.array(evidenceRecordSchema),
  findings: z.array(findingSchema),
  security_score: z.object({
    total: z.number().min(0).max(100),
    maximum: z.number().min(0).max(100),
    assessed_weight: z.number().min(0).max(100),
    unassessed_weight: z.number().min(0).max(100),
    categories: z.array(scoreCategorySchema),
    method: z.string(),
  }).passthrough(),
  limitations: z.array(z.object({ code: z.string(), description: z.string() }).passthrough()),
}).passthrough()

export const xrayProjectionSchema = z.object({
  schema_id: z.literal('ipsec-sentinel.xray/v1'),
  version: z.literal('1.0'),
  total_packet_count: z.number().int().nonnegative(),
  displayed_packet_count: z.number().int().nonnegative(),
  sampled: z.boolean(),
  duration_seconds: z.number().nonnegative(),
  peer_pair: z.array(z.string()).length(2).nullable(),
  packets: z.array(z.object({
    relative_time_seconds: z.number().nonnegative(),
    length: z.number().int().positive(),
    direction: z.enum(['forward', 'reverse']),
  })),
}).passthrough()

export const analysisEnvelopeSchema = z.object({
  analysis: analysisSchema,
  xray: xrayProjectionSchema,
})

