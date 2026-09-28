import { Eye, RefreshCcw, RotateCw, Search, Unplug } from 'lucide-react'

import type { LiveSession } from '../../lib/live/types'

export function SecurityActions({
  session, onRekey, onRefresh, onAnalyze, onReveal, onDisconnect,
}: {
  session: LiveSession
  onRekey: () => void
  onRefresh: () => void
  onAnalyze: () => void
  onReveal: () => void
  onDisconnect: () => void
}) {
  const allowed = new Set(session.allowed_actions)
  return (
    <section className="live-control-card" aria-labelledby="security-actions-heading">
      <header><span>CONTROL PLANE</span><h2 id="security-actions-heading">Security actions</h2></header>
      <div className="security-action-list">
        <button type="button" disabled={!allowed.has('REKEY')} onClick={onRekey}><RotateCw size={15} />Trigger Rekey</button>
        <button type="button" disabled={!allowed.has('REFRESH')} onClick={onRefresh}><RefreshCcw size={15} />Refresh SA State</button>
        <button type="button" disabled={!allowed.has('ANALYZE')} onClick={onAnalyze}><Search size={15} />Analyze Session</button>
        {session.mystery && !session.revealed && <button type="button" disabled={!allowed.has('REVEAL')} onClick={onReveal}><Eye size={15} />Reveal Ground Truth</button>}
        <button type="button" className="disconnect-action" disabled={!allowed.has('DISCONNECT')} onClick={onDisconnect}><Unplug size={15} />Disconnect</button>
      </div>
    </section>
  )
}
