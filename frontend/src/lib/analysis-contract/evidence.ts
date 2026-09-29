import type { AnalysisV1, EvidenceRecord } from './types'

export interface EvidenceResolution {
  records: EvidenceRecord[]
  missingIds: string[]
}

export function indexEvidence(analysis: AnalysisV1): ReadonlyMap<string, EvidenceRecord> {
  return new Map(analysis.evidence.map((item) => [item.id, item]))
}

export function resolveEvidence(
  identifiers: readonly string[],
  index: ReadonlyMap<string, EvidenceRecord>,
): EvidenceResolution {
  const records: EvidenceRecord[] = []
  const missingIds: string[] = []
  for (const identifier of identifiers) {
    const record = index.get(identifier)
    if (record) records.push(record)
    else missingIds.push(identifier)
  }
  return { records, missingIds }
}

