import { FileDown, Mail, MessageSquare, MonitorPlay, Phone, RadioTower, Send } from 'lucide-react'

import type { LiveSession } from '../../lib/live/types'

const controls = [
  ['icmp', 'Ping Server', RadioTower],
  ['web', 'Browse Test Site', MonitorPlay],
  ['video', 'Start Video Stream', MonitorPlay],
  ['voip', 'Simulate VoIP', Phone],
  ['email', 'Send Email', Mail],
  ['messaging', 'Send Messages', MessageSquare],
  ['file_transfer', 'Transfer File', FileDown],
] as const

export function TrafficControls({ session, workloads, onRun }: { session: LiveSession; workloads: string[]; onRun: (id: string) => void }) {
  const enabled = session.allowed_actions.includes('TRAFFIC')
  return (
    <section className="live-control-card" aria-labelledby="traffic-controls-heading">
      <header><span>VPN SANDBOX</span><h2 id="traffic-controls-heading">Generate traffic</h2></header>
      <div className="control-grid">
        {controls.filter(([id]) => workloads.includes(id)).map(([id, label, Icon]) => (
          <button type="button" key={id} disabled={!enabled} onClick={() => onRun(id)}>
            <Icon size={16} /><span>{label}</span><Send size={12} />
          </button>
        ))}
      </div>
    </section>
  )
}
