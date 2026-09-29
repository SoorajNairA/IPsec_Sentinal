import { describe, expect, it } from 'vitest'

import { explain } from './plainEnglish'

describe('reviewed explanation mappings', () => {
  it('keeps analyzer wording in technical mode', () => {
    expect(explain('pfs_disabled', 'technical', 'Rekeying occurs without a fresh CHILD-SA DH exchange.'))
      .toBe('Rekeying occurs without a fresh CHILD-SA DH exchange.')
  })

  it('explains known concepts without changing their meaning', () => {
    expect(explain('pfs_disabled', 'plain', 'fallback')).toContain('changed encryption keys')
    expect(explain('metadata_exposure', 'plain', 'fallback')).toContain('timing and size')
  })

  it('falls back exactly when no reviewed mapping exists', () => {
    expect(explain('unmapped' as never, 'plain', 'Analyzer-owned explanation')).toBe('Analyzer-owned explanation')
  })
})
