import { Check, LoaderCircle, XCircle } from 'lucide-react'

import type { LiveEvent } from '../../lib/live/types'

function eventLabel(event: LiveEvent): string {
  const labels: Partial<Record<LiveEvent['type'], string>> = {
    'session.created': 'Session created',
    'sandbox.preparing': 'Preparing isolated sandbox',
    'sandbox.prepared': 'Sandbox created',
    'endpoint.ready': 'VPN gateway reachable',
    'capture.started': 'Packet capture running',
    'ike.sa_init.request': 'IKE SA INIT request sent',
    'ike.sa_init.response': 'IKE SA INIT response received',
    'ike.proposal.selected': 'IKE proposal selected',
    'ike.auth.request': 'Authentication request sent',
    'ike.auth.response': 'Authentication response received',
    'ike.sa.verified': 'IKE SA independently verified',
    'child_sa.verified': 'CHILD SA established',
    'xfrm.verified': 'XFRM policies installed',
    'tunnel.active': 'Tunnel active',
    'traffic.started': `${String(event.data.workload ?? 'Traffic')} workload started`,
    'esp.observed': `${Number(event.data.packet_delta ?? 0).toLocaleString()} new ESP packets observed`,
    'traffic.completed': `${String(event.data.workload ?? 'Traffic')} workload completed`,
    'rekey.started': 'CHILD SA rekey requested',
    'child_sa.rekeyed': 'New CHILD SA and PFS evidence observed',
    'analysis.completed': 'Session analysis completed',
    'cleanup.completed': 'Session cleanup completed',
  }
  return labels[event.type] ?? event.reason
}

export function ConnectionTimeline({ events }: { events: LiveEvent[] }) {
  return (
    <section className="connection-timeline" aria-labelledby="event-feed-heading">
      <header><span>EVENT STREAM</span><h2 id="event-feed-heading">Live evidence</h2></header>
      {events.length === 0 ? <p className="timeline-empty">Backend events will appear here. No progress is simulated.</p> : (
        <ol aria-live="polite">
          {events.map((event) => (
            <li key={event.event_id} className={event.type.endsWith('failed') ? 'is-failed' : ''}>
              <time dateTime={event.timestamp}>{new Date(event.timestamp).toLocaleTimeString([], { hour12: false })}</time>
              <span className="timeline-icon" aria-hidden="true">
                {event.type.endsWith('failed') ? <XCircle size={13} /> : event.type.endsWith('started') || event.type.endsWith('preparing') || event.type.endsWith('negotiating') ? <LoaderCircle size={13} /> : <Check size={13} />}
              </span>
              <div><strong>{eventLabel(event)}</strong><small>{event.state.replaceAll('_', ' ')}</small></div>
            </li>
          ))}
        </ol>
      )}
    </section>
  )
}
