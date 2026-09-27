import { describe, expect, it } from 'vitest'

import { makeAnalysis } from '../../test/analysisFixture'
import { indexEvidence, resolveEvidence } from './evidence'
import { parseAnalysis } from './load'

describe('evidence resolution', () => {
  it('indexes evidence without changing its source records', () => {
    const analysis = parseAnalysis(makeAnalysis())
    const index = indexEvidence(analysis)
    expect(index.get('ev-cipher')?.normalized_value).toBe('AES-256-GCM')
    expect(index.size).toBe(4)
  })

  it('returns resolved records and names unavailable references', () => {
    const index = indexEvidence(parseAnalysis(makeAnalysis()))
    const result = resolveEvidence(['ev-cipher', 'ev-absent'], index)
    expect(result.records.map((item) => item.id)).toEqual(['ev-cipher'])
    expect(result.missingIds).toEqual(['ev-absent'])
  })
})

