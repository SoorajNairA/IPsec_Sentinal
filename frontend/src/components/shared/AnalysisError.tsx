import { AlertTriangle, RotateCcw } from 'lucide-react'
import { safeAnalysisError } from './errorStates'

export function AnalysisError({ code, unsafeMessage: _unsafeMessage, onReset }: { code: string; unsafeMessage?: string; onReset: () => void }) {
  const state = safeAnalysisError(code)
  return (
    <section className="analysis-error" role="alert">
      <AlertTriangle size={18} aria-hidden="true" />
      <div><strong>{state.title}</strong><p>{state.message}</p><span>{state.nextAction}</span></div>
      <code>{code}</code>
      <button type="button" onClick={onReset}><RotateCcw size={14} />Choose another capture</button>
    </section>
  )
}
