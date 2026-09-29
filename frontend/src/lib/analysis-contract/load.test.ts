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

  it('allows workload-window X-Ray totals to differ from full-session ESP totals', () => {
    const envelope = makeEnvelope()
    const packets = envelope.xray.packets.slice(0, 2)
    const workloadEnvelope = {
      ...envelope,
      analysis: {
        ...envelope.analysis,
        traffic_intelligence: {
          ...envelope.analysis.traffic_intelligence,
          capture_source: 'WORKLOAD_WINDOW',
          capture_path: '/runs/SNT-1/encrypted.pcap',
        },
      },
      xray: {
        ...envelope.xray,
        total_packet_count: 2,
        displayed_packet_count: 2,
        sampled: false,
        duration_seconds: packets[1].relative_time_seconds,
        packets,
        capture_source: 'WORKLOAD_WINDOW',
        capture_path: '/runs/SNT-1/encrypted.pcap',
      },
    }

    expect(parseAnalysisEnvelope(workloadEnvelope).xray.total_packet_count).toBe(2)
    expect(() => parseAnalysisEnvelope({
      ...workloadEnvelope,
      xray: { ...workloadEnvelope.xray, capture_path: '/runs/SNT-1/wrong.pcap' },
    })).toThrow(/x-ray.*path/i)
  })

  it('rejects payload-decryption and calibrated-confidence claims outside v1', () => {
    const base = makeAnalysis()
    expect(() => parseAnalysis({ ...base, esp: { ...base.esp, payload_decrypted: true } })).toThrow()
    expect(() => parseAnalysis({
      ...base,
      traffic_intelligence: { ...base.traffic_intelligence, payload_decrypted: true },
    })).toThrow()
    expect(() => parseAnalysis({
      ...base,
      traffic_intelligence: { ...base.traffic_intelligence, confidence_kind: 'calibrated' },
    })).toThrow()
  })

  it.each([
    ['display count', (envelope: ReturnType<typeof makeEnvelope>) => ({
      ...envelope.xray,
      displayed_packet_count: 2,
    })],
    ['total count', (envelope: ReturnType<typeof makeEnvelope>) => ({
      ...envelope.xray,
      total_packet_count: 2,
    })],
    ['sampling flag', (envelope: ReturnType<typeof makeEnvelope>) => ({
      ...envelope.xray,
      sampled: false,
    })],
    ['duration mismatch', (envelope: ReturnType<typeof makeEnvelope>) => ({
      ...envelope.xray,
      duration_seconds: 3,
    })],
    ['packet beyond duration', (envelope: ReturnType<typeof makeEnvelope>) => ({
      ...envelope.xray,
      packets: envelope.xray.packets.map((packet, index) => (
        index === 2 ? { ...packet, relative_time_seconds: 3 } : packet
      )),
    })],
    ['timestamp order', (envelope: ReturnType<typeof makeEnvelope>) => ({
      ...envelope.xray,
      packets: [envelope.xray.packets[1], envelope.xray.packets[0], envelope.xray.packets[2]],
    })],
  ])('rejects inconsistent X-Ray %s metadata', (_name, mutate) => {
    const envelope = makeEnvelope()
    expect(() => parseAnalysisEnvelope({ ...envelope, xray: mutate(envelope) })).toThrow(/x-ray/i)
  })
})

