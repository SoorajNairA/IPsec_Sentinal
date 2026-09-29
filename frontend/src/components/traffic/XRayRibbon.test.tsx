import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { parseAnalysisEnvelope } from '../../lib/analysis-contract/load'
import { makeEnvelope } from '../../test/analysisFixture'
import { TrafficIntelligence } from './TrafficIntelligence'
import { XRayRibbon } from './XRayRibbon'

describe('encrypted traffic X-Ray', () => {
  it('renders exact projection time, direction, size, gaps, density, and disclosure', () => {
    const { analysis, xray } = parseAnalysisEnvelope(makeEnvelope())
    render(<XRayRibbon projection={xray} features={analysis.esp.features} payloadDecrypted={analysis.esp.payload_decrypted} reducedMotion />)
    expect(screen.getAllByTestId('packet-mark')).toHaveLength(3)
    expect(screen.getAllByTestId('packet-mark')[0]).toHaveAttribute('data-direction', 'forward')
    expect(screen.getAllByTestId('packet-mark')[2]).toHaveAttribute('data-direction', 'reverse')
    expect(screen.getByText('2.000 s')).toBeVisible()
    expect(screen.getByText('3 of 24 packets shown')).toBeVisible()
    expect(screen.getByText('5 bursts')).toBeVisible()
    expect(screen.getByText('12.0 packets/s')).toBeVisible()
    expect(screen.getByText('Payload visibility: 0%')).toBeVisible()
    expect(screen.getByLabelText('Packet density track')).toBeVisible()
  })

  it('uses an honest aggregate-only fallback when no packet projection exists', () => {
    const { analysis, xray } = parseAnalysisEnvelope(makeEnvelope())
    render(<XRayRibbon projection={{ ...xray, total_packet_count: 24, displayed_packet_count: 0, sampled: true, packets: [] }} features={analysis.esp.features} payloadDecrypted={false} reducedMotion />)
    expect(screen.getByText('Aggregate-only view')).toBeVisible()
    expect(screen.getByText(/no per-packet projection was provided/i)).toBeVisible()
    expect(screen.queryByTestId('packet-mark')).not.toBeInTheDocument()
  })
})

describe('traffic intelligence', () => {
  it('shows model provenance, probabilities, and raw uncalibrated confidence', () => {
    const { analysis } = parseAnalysisEnvelope(makeEnvelope())
    render(<TrafficIntelligence traffic={analysis.traffic_intelligence} esp={analysis.esp} />)
    expect(screen.getByText('video')).toBeVisible()
    expect(screen.getByText('96.4% raw / uncalibrated')).toBeVisible()
    expect(screen.getByText('ipsec-sentinel.classifier/v1')).toBeVisible()
    expect(screen.getByText('ipsec-sentinel.esp-session-features/v1')).toBeVisible()
    expect(screen.getByText('video 96.4%')).toBeVisible()
    expect(screen.getByText('web 3.6%')).toBeVisible()
    expect(screen.getByText('Payload visibility: 0%')).toBeVisible()
  })

  it('renders unknown and low-confidence states without overstating a class', () => {
    const { analysis } = parseAnalysisEnvelope(makeEnvelope())
    const traffic = {
      ...analysis.traffic_intelligence,
      state: 'LOW_CONFIDENCE',
      predicted_class: 'UNKNOWN',
      raw_confidence: 0.42,
      probabilities: { web: 0.42, video: 0.31 },
      provenance: 'UNKNOWN' as const,
      reason: 'Evidence is insufficient for a reliable classification.',
    }
    render(<TrafficIntelligence traffic={traffic} esp={analysis.esp} />)
    expect(screen.getByText('Unknown traffic')).toBeVisible()
    expect(screen.getByText('Low confidence')).toBeVisible()
    expect(screen.getByText(/insufficient/i)).toBeVisible()
  })
})
