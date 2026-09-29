import { Radio, Shield } from 'lucide-react'

import type { LiveEvent, LiveSession } from '../../lib/live/types'

function endpoint(events: LiveEvent[]): string {
  const active = [...events].reverse().find((event) => event.type === 'tunnel.active' || event.type === 'endpoint.ready')
  const nested = active?.data.endpoint
  if (nested && typeof nested === 'object' && !Array.isArray(nested)) {
    const address = (nested as Record<string, unknown>).address
    if (typeof address === 'string') return address
  }
  const address = active?.data.address
  return typeof address === 'string' ? address : 'Pending'
}

export function LiveSessionHeader({ session, events }: { session: LiveSession; events: LiveEvent[] }) {
  return (
    <header className="live-session-header">
      <div className="live-session-title"><Radio size={17} /><span>LIVE LAB</span><strong>{session.display_name}</strong></div>
      <dl>
        <div><dt>Session</dt><dd>{session.session_id}</dd></div>
        <div><dt>Endpoint</dt><dd>{endpoint(events)}</dd></div>
        <div><dt>Tunnel</dt><dd className={session.tunnel_status === 'ACTIVE' ? 'is-good' : ''}>{session.tunnel_status}</dd></div>
        <div><dt>Capture</dt><dd className={session.capture_status === 'RUNNING' ? 'is-good' : ''}>{session.capture_status}</dd></div>
      </dl>
      {session.mystery && !session.revealed && <span className="mystery-chip"><Shield size={13} />Configuration hidden</span>}
    </header>
  )
}
