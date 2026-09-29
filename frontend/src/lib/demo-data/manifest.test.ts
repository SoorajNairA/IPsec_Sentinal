import { describe, expect, it, vi } from 'vitest'

import aes128Analysis from '../../../public/demos/aes128-gcm/analysis.json'
import aes128Xray from '../../../public/demos/aes128-gcm/xray.json'
import aes256Analysis from '../../../public/demos/aes256-cbc/analysis.json'
import aes256Xray from '../../../public/demos/aes256-cbc/xray.json'
import noPfsAnalysis from '../../../public/demos/no-pfs/analysis.json'
import noPfsXray from '../../../public/demos/no-pfs/xray.json'
import baselineAnalysis from '../../../public/demos/secure-baseline/analysis.json'
import baselineXray from '../../../public/demos/secure-baseline/xray.json'
import videoAnalysis from '../../../public/demos/video-traffic/analysis.json'
import videoXray from '../../../public/demos/video-traffic/xray.json'
import { makeEnvelope } from '../../test/analysisFixture'
import { parseAnalysisEnvelope } from '../analysis-contract/load'
import { loadDemo, loadDemoManifest } from './manifest'

const encoder = new TextEncoder()

async function digest(text: string) {
  const result = await crypto.subtle.digest('SHA-256', encoder.encode(text))
  return Array.from(new Uint8Array(result), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

async function fixture() {
  const envelope = makeEnvelope()
  const analysis = JSON.stringify(envelope.analysis)
  const xray = JSON.stringify(envelope.xray)
  const manifest = {
    schema_id: 'ipsec-sentinel.frontend-demos/v1',
    version: '1.0',
    analyzer_commit: '64b5884edc9cac3ceea321ce785f36cb24132401',
    generation_command: 'python scripts/generate_frontend_demos.py',
    demos: [{
      id: 'secure-baseline',
      label: 'Secure Baseline',
      description: 'Genuine retained session.',
      source: { run_id: 'run_000001', capture: 'full-evidence.pcap' },
      analysis_path: '/demos/secure-baseline/analysis.json',
      xray_path: '/demos/secure-baseline/xray.json',
      sha256: { analysis: await digest(analysis), xray: await digest(xray) },
    }],
  }
  return { analysis, envelope, manifest, xray }
}

function fetcher(files: Record<string, string>) {
  return vi.fn(async (input: RequestInfo | URL) => {
    const path = String(input)
    const body = files[path]
    return body === undefined ? new Response('', { status: 404 }) : new Response(body)
  })
}

describe('guided demo loader', () => {
  it('parses every bundled genuine analyzer artifact with the frontend v1 contract', () => {
    const bundled = [
      [baselineAnalysis, baselineXray],
      [aes128Analysis, aes128Xray],
      [aes256Analysis, aes256Xray],
      [noPfsAnalysis, noPfsXray],
      [videoAnalysis, videoXray],
    ]
    for (const [analysis, xray] of bundled) {
      expect(parseAnalysisEnvelope({ analysis, xray }).analysis.summary.status).toBe('COMPLETE')
    }
  })

  it('validates the v1 manifest and loads a digest-verified analysis envelope', async () => {
    const data = await fixture()
    const mockFetch = fetcher({
      '/demos/manifest.json': JSON.stringify(data.manifest),
      '/demos/secure-baseline/analysis.json': data.analysis,
      '/demos/secure-baseline/xray.json': data.xray,
    })

    const manifest = await loadDemoManifest(mockFetch)
    expect(manifest.demos[0].source.run_id).toBe('run_000001')
    const loaded = await loadDemo('secure-baseline', mockFetch)
    expect(loaded).toEqual(data.envelope)
  })

  it('rejects unknown demos before requesting artifacts', async () => {
    const data = await fixture()
    const mockFetch = fetcher({ '/demos/manifest.json': JSON.stringify(data.manifest) })
    await expect(loadDemo('no-pfs', mockFetch)).rejects.toThrow(/unknown demo/i)
    expect(mockFetch).toHaveBeenCalledTimes(1)
  })

  it('rejects an artifact whose bytes do not match the manifest digest', async () => {
    const data = await fixture()
    const mockFetch = fetcher({
      '/demos/manifest.json': JSON.stringify(data.manifest),
      '/demos/secure-baseline/analysis.json': `${data.analysis} `,
      '/demos/secure-baseline/xray.json': data.xray,
    })
    await expect(loadDemo('secure-baseline', mockFetch)).rejects.toThrow(/digest/i)
  })
})
