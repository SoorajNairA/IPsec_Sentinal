export type ExplanationKey = 'pfs_disabled' | 'pfs_enabled' | 'metadata_exposure' | 'raw_confidence'
export type ExplanationMode = 'technical' | 'plain'

const plainMappings: Readonly<Record<ExplanationKey, string>> = {
  pfs_disabled: 'The tunnel changed encryption keys without creating new shared key material. If a key is later compromised, more past traffic could be affected.',
  pfs_enabled: 'The tunnel created fresh shared key material when it changed encryption keys, limiting how much past traffic one compromised key could expose.',
  metadata_exposure: 'The message contents stay encrypted, but timing and size patterns remain visible to an observer.',
  raw_confidence: 'This is the model’s direct score. It has not been calibrated into a real-world probability.',
}

export function explain(key: ExplanationKey, mode: ExplanationMode, fallback: string): string {
  if (mode === 'technical') return fallback
  return plainMappings[key] ?? fallback
}
