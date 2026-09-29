import { z } from 'zod'

import { parseAnalysisEnvelope } from '../analysis-contract/load'
import type { AnalysisEnvelope } from '../analysis-contract/types'

const demoIdSchema = z.enum([
  'secure-baseline',
  'aes128-gcm',
  'aes256-cbc',
  'no-pfs',
  'video-traffic',
])

const digestSchema = z.string().regex(/^[a-f0-9]{64}$/)

const demoManifestSchema = z.object({
  schema_id: z.literal('ipsec-sentinel.frontend-demos/v1'),
  version: z.literal('1.0'),
  analyzer_commit: z.string().regex(/^[a-f0-9]{40}$/),
  generation_command: z.string().min(1),
  demos: z.array(z.object({
    id: demoIdSchema,
    label: z.string().min(1),
    description: z.string().min(1),
    source: z.object({
      run_id: z.string().regex(/^run_[0-9]{6}$/),
      capture: z.enum(['full-evidence.pcap', 'encrypted.pcap']),
    }),
    analysis_path: z.string().startsWith('/demos/'),
    xray_path: z.string().startsWith('/demos/'),
    sha256: z.object({ analysis: digestSchema, xray: digestSchema }),
  })).min(1),
})

export type DemoId = z.infer<typeof demoIdSchema>
export type DemoManifest = z.infer<typeof demoManifestSchema>
export type DemoManifestEntry = DemoManifest['demos'][number]
export const demoIds = demoIdSchema.options

type Fetcher = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>

async function fetchBytes(path: string, fetcher: Fetcher): Promise<ArrayBuffer> {
  const response = await fetcher(path)
  if (!response.ok) throw new Error(`Demo artifact request failed (${response.status}): ${path}`)
  return response.arrayBuffer()
}

async function sha256Hex(bytes: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

async function verifiedJson(path: string, expectedDigest: string, fetcher: Fetcher): Promise<unknown> {
  const bytes = await fetchBytes(path, fetcher)
  const actualDigest = await sha256Hex(bytes)
  if (actualDigest !== expectedDigest) {
    throw new Error(`Demo artifact digest mismatch: ${path}`)
  }
  return JSON.parse(new TextDecoder().decode(bytes)) as unknown
}

export async function loadDemoManifest(fetcher: Fetcher = fetch): Promise<DemoManifest> {
  const response = await fetcher('/demos/manifest.json')
  if (!response.ok) throw new Error(`Demo manifest request failed (${response.status}).`)
  return demoManifestSchema.parse(await response.json())
}

export async function loadDemo(id: DemoId, fetcher: Fetcher = fetch): Promise<AnalysisEnvelope> {
  const manifest = await loadDemoManifest(fetcher)
  const demo = manifest.demos.find((item) => item.id === id)
  if (!demo) throw new Error(`Unknown demo: ${id}`)
  const [analysis, xray] = await Promise.all([
    verifiedJson(demo.analysis_path, demo.sha256.analysis, fetcher),
    verifiedJson(demo.xray_path, demo.sha256.xray, fetcher),
  ])
  return parseAnalysisEnvelope({ analysis, xray })
}
