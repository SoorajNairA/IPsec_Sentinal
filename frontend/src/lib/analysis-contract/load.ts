import { analysisEnvelopeSchema, analysisSchema } from './schema'
import type { AnalysisEnvelope, AnalysisV1 } from './types'

function assertAnalysisSemantics(analysis: AnalysisV1): void {
  const identifiers = new Set<string>()
  for (const item of analysis.evidence) {
    if (identifiers.has(item.id)) throw new Error(`Analysis evidence ID is duplicated: ${item.id}`)
    identifiers.add(item.id)
  }
  for (const finding of analysis.findings) {
    const missing = finding.evidence_ids.filter((identifier) => !identifiers.has(identifier))
    if (missing.length) throw new Error(`Finding ${finding.rule_id} has invalid evidence links: ${missing.join(', ')}`)
  }
  const score = analysis.security_score
  if (score.maximum > 100 || score.total > score.maximum) throw new Error('Security score is outside bounds')
  if (score.assessed_weight + score.unassessed_weight !== 100) throw new Error('Security score weights must total 100')
}

export function parseAnalysis(input: unknown): AnalysisV1 {
  const marker = input as { schema_id?: unknown; analysis_version?: unknown } | null
  if (marker?.schema_id !== 'ipsec-sentinel.analysis/v1' || marker.analysis_version !== '1.0') {
    throw new Error('Unsupported analysis schema or version')
  }
  const analysis = analysisSchema.parse(input)
  assertAnalysisSemantics(analysis)
  return analysis
}

export function parseAnalysisEnvelope(input: unknown): AnalysisEnvelope {
  const marker = input as { xray?: { schema_id?: unknown; version?: unknown } } | null
  if (marker?.xray?.schema_id !== 'ipsec-sentinel.xray/v1' || marker.xray.version !== '1.0') {
    throw new Error('Unsupported X-Ray schema or version')
  }
  const envelope = analysisEnvelopeSchema.parse(input)
  return { ...envelope, analysis: parseAnalysis(envelope.analysis) }
}

