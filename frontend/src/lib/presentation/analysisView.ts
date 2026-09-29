import type { AnalysisV1, ScoreCategoryName } from '../analysis-contract/types'
import { formatRawConfidence } from './format'

const CATEGORY_BY_RULE: Readonly<Record<string, ScoreCategoryName>> = {
  'IPSEC-IKE-001': 'Replay / Protocol Protections',
  'IPSEC-IKE-002': 'Replay / Protocol Protections',
  'IPSEC-IKE-003': 'Replay / Protocol Protections',
  'IPSEC-CRYPTO-001': 'Cryptography',
  'IPSEC-CRYPTO-002': 'Cryptography',
  'IPSEC-CRYPTO-003': 'Cryptography',
  'IPSEC-INTEGRITY-001': 'Cryptography',
  'IPSEC-DH-001': 'Key Exchange / PFS',
  'IPSEC-DH-002': 'Key Exchange / PFS',
  'IPSEC-PFS-001': 'Key Exchange / PFS',
  'IPSEC-PFS-002': 'Key Exchange / PFS',
  'IPSEC-PFS-003': 'Key Exchange / PFS',
  'IPSEC-REKEY-001': 'Security Association Hygiene',
  'IPSEC-REPLAY-001': 'Replay / Protocol Protections',
  'IPSEC-METADATA-001': 'Metadata / Privacy Exposure',
  'IPSEC-ML-001': 'Metadata / Privacy Exposure',
  'IPSEC-EVIDENCE-001': 'Security Association Hygiene',
}

const SEVERITY_ORDER: Readonly<Record<string, number>> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
}

export function findingCategory(ruleId: string): ScoreCategoryName {
  const category = CATEGORY_BY_RULE[ruleId]
  if (!category) throw new Error(`Unknown analyzer rule ID: ${ruleId}`)
  return category
}

function postureLabel(total: number, coverage: number): string {
  if (coverage < 60) return 'Limited evidence'
  if (total >= 90) return 'Strong posture'
  if (total >= 75) return 'Moderate posture'
  return 'Attention required'
}

export interface AnalysisView {
  score: {
    total: number
    maximum: number
    coverage: number
    unassessed: number
    postureLabel: string
  }
  traffic: {
    state: string
    predictedClass: string
    confidenceLabel: string
    payloadLabel: 'Payload visibility: 0%'
  }
  findings: Array<AnalysisV1['findings'][number] & { category: ScoreCategoryName }>
}

export function buildAnalysisView(analysis: AnalysisV1): AnalysisView {
  const score = analysis.security_score
  const findings = analysis.findings
    .map((finding) => ({ ...finding, category: findingCategory(finding.rule_id) }))
    .sort((left, right) => (SEVERITY_ORDER[left.severity] ?? 99) - (SEVERITY_ORDER[right.severity] ?? 99))

  return {
    score: {
      total: score.total,
      maximum: score.maximum,
      coverage: score.assessed_weight,
      unassessed: score.unassessed_weight,
      postureLabel: postureLabel(score.total, score.assessed_weight),
    },
    traffic: {
      state: analysis.traffic_intelligence.state,
      predictedClass: analysis.traffic_intelligence.predicted_class,
      confidenceLabel: formatRawConfidence(analysis.traffic_intelligence.raw_confidence),
      payloadLabel: 'Payload visibility: 0%',
    },
    findings,
  }
}

