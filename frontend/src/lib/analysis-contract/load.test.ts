import { describe, expect, it } from 'vitest'

import { makeAnalysis, makeEnvelope } from '../../test/analysisFixture'
import { parseAnalysis, parseAnalysisEnvelope } from './load'

describe('analysis contract loading', () => {
  it('loads the supported v1 contract and preserves UNKNOWN values', () => {
    const input = makeAnalysis({
      ike: { ...makeAnalysis().ike, dh_group: { raw: 'UNKNOWN', normalized: 'UNKNOWN', provenance: 'UNKNOWN' } },
    })

    expect(parseAnalysis(input).ike.dh_group.normalized).toBe('UNKNOWN')
  })

  it.each([
    ['analysis schema', { schema_id: 'ipsec-sentinel.analysis/v2' }],
    ['analysis version', { analysis_version: '2.0' }],
  ])('rejects an unsupported %s', (_name, override) => {
    expect(() => parseAnalysis(makeAnalysis(override))).toThrow(/schema|version/i)
  })

  it('rejects duplicate evidence IDs and invalid provenance', () => {
    const base = makeAnalysis()
    expect(() => parseAnalysis({ ...base, evidence: [base.evidence[0], base.evidence[0]] })).toThrow(/evidence/i)
    expect(() => parseAnalysis({ ...base, evidence: [{ ...base.evidence[0], provenance: 'GUESSED' }] })).toThrow(/provenance/i)
  })

  it('rejects dangling finding evidence links', () => {
    const base = makeAnalysis()
    expect(() => parseAnalysis({ ...base, findings: [{ ...base.findings[0], evidence_ids: ['ev-missing'] }] })).toThrow(/evidence/i)
  })

  it('rejects invalid score bounds and evidence weights', () => {
    const base = makeAnalysis()
    expect(() => parseAnalysis({ ...base, security_score: { ...base.security_score, total: 101 } })).toThrow(/score/i)
    expect(() => parseAnalysis({ ...base, security_score: { ...base.security_score, assessed_weight: 70 } })).toThrow(/weight/i)
  })

  it('loads a separate X-Ray projection and rejects its wrong schema or version', () => {
    const envelope = makeEnvelope()
    expect(parseAnalysisEnvelope(envelope).xray.packets).toHaveLength(3)
    expect(() => parseAnalysisEnvelope({ ...envelope, xray: { ...envelope.xray, schema_id: 'decorative.xray/v1' } })).toThrow(/x-ray|schema/i)
    expect(() => parseAnalysisEnvelope({ ...envelope, xray: { ...envelope.xray, version: '2.0' } })).toThrow(/x-ray|version/i)
  })
})

