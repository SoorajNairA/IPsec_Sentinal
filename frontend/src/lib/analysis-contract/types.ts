import type { z } from 'zod'

import type { analysisEnvelopeSchema, analysisSchema, evidenceRecordSchema, provenanceSchema, xrayProjectionSchema } from './schema'

export type Provenance = z.infer<typeof provenanceSchema>
export type EvidenceRecord = z.infer<typeof evidenceRecordSchema>
export type AnalysisV1 = z.infer<typeof analysisSchema>
export type XRayProjection = z.infer<typeof xrayProjectionSchema>
export type AnalysisEnvelope = z.infer<typeof analysisEnvelopeSchema>

export type ScoreCategoryName =
  | 'Cryptography'
  | 'Key Exchange / PFS'
  | 'Security Association Hygiene'
  | 'Replay / Protocol Protections'
  | 'Metadata / Privacy Exposure'

