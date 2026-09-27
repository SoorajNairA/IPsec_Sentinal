import { describe, expect, it } from 'vitest'

import { parseAnalysis } from '../analysis-contract/load'
import { makeAnalysis } from '../../test/analysisFixture'
import { buildAnalysisView, findingCategory } from './analysisView'

describe('analysis presentation model', () => {
  it('uses assessed weight as evidence coverage and labels confidence honestly', () => {
    const view = buildAnalysisView(parseAnalysis(makeAnalysis()))
    expect(view.score.coverage).toBe(82)
    expect(view.score.unassessed).toBe(18)
    expect(view.traffic.confidenceLabel).toBe('96.4% raw / uncalibrated')
    expect(view.traffic.payloadLabel).toBe('Payload visibility: 0%')
  })

  it('retains unknown traffic confidence', () => {
    const base = makeAnalysis()
    const traffic = { ...base.traffic_intelligence, state: 'UNKNOWN', predicted_class: 'UNKNOWN', raw_confidence: null, provenance: 'UNKNOWN' }
    const view = buildAnalysisView(parseAnalysis({ ...base, traffic_intelligence: traffic }))
    expect(view.traffic.confidenceLabel).toBe('Unknown')
    expect(view.traffic.predictedClass).toBe('UNKNOWN')
  })

  it('prioritizes high then medium findings without hiding lower evidence', () => {
    const base = makeAnalysis()
    const findings = [
      { ...base.findings[0], rule_id: 'IPSEC-METADATA-001', severity: 'INFO', title: 'Info' },
      { ...base.findings[0], rule_id: 'IPSEC-PFS-002', severity: 'MEDIUM', title: 'Medium' },
      { ...base.findings[0], rule_id: 'IPSEC-CRYPTO-003', severity: 'HIGH', title: 'High' },
      { ...base.findings[0], rule_id: 'IPSEC-CRYPTO-002', severity: 'LOW', title: 'Low' },
    ]
    const view = buildAnalysisView(parseAnalysis({ ...base, findings }))
    expect(view.findings.map((item) => item.title)).toEqual(['High', 'Medium', 'Low', 'Info'])
  })

  it('does not call an unassessed perfect score secure', () => {
    const base = makeAnalysis()
    const security_score = { ...base.security_score, total: 100, assessed_weight: 40, unassessed_weight: 60 }
    const view = buildAnalysisView(parseAnalysis({ ...base, security_score }))
    expect(view.score.postureLabel).toBe('Limited evidence')
    expect(view.score.postureLabel.toLowerCase()).not.toContain('secure')
  })

  it.each([
    ['IPSEC-IKE-001', 'Replay / Protocol Protections'],
    ['IPSEC-IKE-002', 'Replay / Protocol Protections'],
    ['IPSEC-IKE-003', 'Replay / Protocol Protections'],
    ['IPSEC-CRYPTO-001', 'Cryptography'],
    ['IPSEC-CRYPTO-002', 'Cryptography'],
    ['IPSEC-CRYPTO-003', 'Cryptography'],
    ['IPSEC-INTEGRITY-001', 'Cryptography'],
    ['IPSEC-DH-001', 'Key Exchange / PFS'],
    ['IPSEC-DH-002', 'Key Exchange / PFS'],
    ['IPSEC-PFS-001', 'Key Exchange / PFS'],
    ['IPSEC-PFS-002', 'Key Exchange / PFS'],
    ['IPSEC-PFS-003', 'Key Exchange / PFS'],
    ['IPSEC-REKEY-001', 'Security Association Hygiene'],
    ['IPSEC-REPLAY-001', 'Replay / Protocol Protections'],
    ['IPSEC-METADATA-001', 'Metadata / Privacy Exposure'],
    ['IPSEC-ML-001', 'Metadata / Privacy Exposure'],
    ['IPSEC-EVIDENCE-001', 'Security Association Hygiene'],
  ] as const)('maps %s into the analyzer score category', (ruleId, category) => {
    expect(findingCategory(ruleId)).toBe(category)
  })
})

