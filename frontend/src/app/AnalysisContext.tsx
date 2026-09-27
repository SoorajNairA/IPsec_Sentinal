/* oxlint-disable react/only-export-components -- provider contract intentionally co-locates its hook and public state types */
import { createContext, type ReactNode, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'

import { parseAnalysisEnvelope } from '../lib/analysis-contract/load'
import type { AnalysisEnvelope } from '../lib/analysis-contract/types'
import { loadDemo as loadDemoArtifact, loadDemoManifest, type DemoId, type DemoManifest } from '../lib/demo-data/manifest'

export type AnalysisStatus = 'EMPTY' | 'DEMO_CHOOSER' | 'ANALYZING' | 'READY' | 'ERROR' | 'UNSUPPORTED'
export type AnalysisView = 'overview' | 'tunnel' | 'traffic' | 'security' | 'evidence' | 'report'
export type LanguageMode = 'PLAIN' | 'TECHNICAL'

export const ANALYSIS_STAGES = [
  'Reading capture',
  'Detecting IPsec',
  'Parsing IKE',
  'Reconstructing Security Associations',
  'Analyzing ESP behavior',
  'Running traffic intelligence',
  'Evaluating security posture',
] as const

class AnalysisRequestError extends Error {
  readonly code: string

  constructor(code: string, message: string) {
    super(message)
    this.code = code
  }
}

async function analyzeCapture(file: File): Promise<unknown> {
  const response = await fetch('/api/analyze', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/octet-stream',
      'X-Capture-Filename': file.name,
    },
    body: file,
  })
  const payload = await response.json() as {
    error?: { code?: string; message?: string }
  }
  if (!response.ok) {
    throw new AnalysisRequestError(
      payload.error?.code ?? 'ANALYSIS_FAILED',
      payload.error?.message ?? 'The local analyzer could not process this capture.',
    )
  }
  return payload
}

export interface AnalysisServices {
  loadManifest: () => Promise<DemoManifest>
  loadDemo: (id: DemoId) => Promise<unknown>
  analyzeCapture: (file: File) => Promise<unknown>
}

interface AnalysisContextValue {
  status: AnalysisStatus
  envelope: AnalysisEnvelope | null
  demos: DemoManifest | null
  stageIndex: number
  error: { code: string; message: string } | null
  selectedEvidenceId: string | null
  evidenceRequest: { ids: string[]; valueLabel?: string } | null
  languageMode: LanguageMode
  openDemoChooser: () => Promise<void>
  closeDemoChooser: () => void
  loadDemo: (id: DemoId) => Promise<void>
  analyzeFile: (file: File) => Promise<void>
  reset: () => void
  navigate: (view: AnalysisView) => void
  selectEvidence: (id: string | null) => void
  inspectEvidence: (ids: readonly string[], valueLabel?: string) => void
  closeEvidence: () => void
  setLanguageMode: (mode: LanguageMode) => void
}

const AnalysisContext = createContext<AnalysisContextValue | null>(null)

const defaultServices: AnalysisServices = {
  loadManifest: loadDemoManifest,
  loadDemo: loadDemoArtifact,
  analyzeCapture,
}

const unsupportedCodes = new Set(['UNSUPPORTED_PCAPNG', 'UNSUPPORTED_LAYOUT', 'UNSUPPORTED_MEDIA_TYPE'])

function classifyError(error: unknown): { status: 'ERROR' | 'UNSUPPORTED'; code: string; message: string } {
  if (error instanceof AnalysisRequestError) {
    return {
      status: unsupportedCodes.has(error.code) ? 'UNSUPPORTED' : 'ERROR',
      code: error.code,
      message: error.message,
    }
  }
  return {
    status: 'ERROR',
    code: 'ANALYSIS_FAILED',
    message: error instanceof Error ? error.message : 'The local analyzer could not process this capture.',
  }
}

export function AnalysisProvider({
  children,
  services: serviceOverrides = {},
}: {
  children: ReactNode
  services?: Partial<AnalysisServices>
}) {
  const routerNavigate = useNavigate()
  const services = useMemo(() => ({ ...defaultServices, ...serviceOverrides }), [serviceOverrides])
  const [status, setStatus] = useState<AnalysisStatus>('EMPTY')
  const [envelope, setEnvelope] = useState<AnalysisEnvelope | null>(null)
  const [demos, setDemos] = useState<DemoManifest | null>(null)
  const [stageIndex, setStageIndex] = useState(0)
  const [error, setError] = useState<{ code: string; message: string } | null>(null)
  const [selectedEvidenceId, selectEvidence] = useState<string | null>(null)
  const [evidenceRequest, setEvidenceRequest] = useState<{ ids: string[]; valueLabel?: string } | null>(null)
  const [languageMode, setLanguageMode] = useState<LanguageMode>('PLAIN')
  const evidenceTrigger = useRef<HTMLElement | null>(null)

  useEffect(() => {
    if (status !== 'ANALYZING') return undefined
    const timer = window.setInterval(() => {
      setStageIndex((current) => Math.min(current + 1, ANALYSIS_STAGES.length - 1))
    }, 700)
    return () => window.clearInterval(timer)
  }, [status])

  useEffect(() => {
    if (evidenceRequest === null && evidenceTrigger.current) {
      evidenceTrigger.current.focus()
      evidenceTrigger.current = null
    }
  }, [evidenceRequest])

  const beginAnalysis = useCallback(() => {
    setStatus('ANALYZING')
    setStageIndex(0)
    setError(null)
    selectEvidence(null)
    setEvidenceRequest(null)
  }, [])

  const acceptEnvelope = useCallback((input: unknown) => {
    const validated = parseAnalysisEnvelope(input)
    setEnvelope(validated)
    setStatus('READY')
    routerNavigate('/analysis/overview')
  }, [routerNavigate])

  const fail = useCallback((caught: unknown) => {
    const failure = classifyError(caught)
    setError({ code: failure.code, message: failure.message })
    setStatus(failure.status)
    routerNavigate('/')
  }, [routerNavigate])

  const openDemoChooser = useCallback(async () => {
    setStatus('DEMO_CHOOSER')
    setError(null)
    try {
      setDemos(await services.loadManifest())
    } catch (caught) {
      fail(caught)
    }
  }, [fail, services])

  const closeDemoChooser = useCallback(() => {
    setStatus((current) => current === 'DEMO_CHOOSER' ? 'EMPTY' : current)
  }, [])

  const loadDemo = useCallback(async (id: DemoId) => {
    beginAnalysis()
    try {
      acceptEnvelope(await services.loadDemo(id))
    } catch (caught) {
      fail(caught)
    }
  }, [acceptEnvelope, beginAnalysis, fail, services])

  const analyzeFile = useCallback(async (file: File) => {
    if (file.name.toLowerCase().endsWith('.pcapng')) {
      fail(new AnalysisRequestError('UNSUPPORTED_PCAPNG', 'PCAPNG is detected but not supported yet. Export a classic PCAP file.'))
      return
    }
    beginAnalysis()
    try {
      acceptEnvelope(await services.analyzeCapture(file))
    } catch (caught) {
      fail(caught)
    }
  }, [acceptEnvelope, beginAnalysis, fail, services])

  const reset = useCallback(() => {
    setStatus('EMPTY')
    setEnvelope(null)
    setDemos(null)
    setError(null)
    setStageIndex(0)
    selectEvidence(null)
    setEvidenceRequest(null)
    routerNavigate('/')
  }, [routerNavigate])

  const navigate = useCallback((view: AnalysisView) => {
    routerNavigate(`/analysis/${view}`)
  }, [routerNavigate])

  const inspectEvidence = useCallback((ids: readonly string[], valueLabel?: string) => {
    evidenceTrigger.current = document.activeElement instanceof HTMLElement ? document.activeElement : null
    setEvidenceRequest({ ids: [...ids], ...(valueLabel ? { valueLabel } : {}) })
  }, [])

  const closeEvidence = useCallback(() => setEvidenceRequest(null), [])

  const value = useMemo<AnalysisContextValue>(() => ({
    status,
    envelope,
    demos,
    stageIndex,
    error,
    selectedEvidenceId,
    evidenceRequest,
    languageMode,
    openDemoChooser,
    closeDemoChooser,
    loadDemo,
    analyzeFile,
    reset,
    navigate,
    selectEvidence,
    inspectEvidence,
    closeEvidence,
    setLanguageMode,
  }), [
    status, envelope, demos, stageIndex, error, selectedEvidenceId, evidenceRequest, languageMode,
    openDemoChooser, closeDemoChooser, loadDemo, analyzeFile, reset, navigate, inspectEvidence, closeEvidence,
  ])

  return <AnalysisContext.Provider value={value}>{children}</AnalysisContext.Provider>
}

export function useAnalysis(): AnalysisContextValue {
  const value = useContext(AnalysisContext)
  if (!value) throw new Error('useAnalysis must be used within AnalysisProvider')
  return value
}
