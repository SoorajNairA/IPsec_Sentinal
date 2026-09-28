import { useState } from 'react'
import { EyeOff, ShieldCheck } from 'lucide-react'

import type { LabScenario } from '../../lib/live/types'

export function ScenarioPicker({ scenarios, onCreate }: { scenarios: LabScenario[]; onCreate: (id: string) => void }) {
  const [selected, setSelected] = useState(scenarios[0]?.id ?? '')
  return (
    <section className="scenario-picker" aria-labelledby="scenario-heading">
      <div className="live-section-heading">
        <span>01 / VPN PROFILE</span>
        <h2 id="scenario-heading">Choose a controlled scenario</h2>
        <p>Every option establishes a real local IKEv2/IPsec tunnel inside an isolated sandbox.</p>
      </div>
      <div className="scenario-grid" role="group" aria-label="VPN scenarios">
        {scenarios.map((scenario) => (
          <button
            type="button"
            className={`scenario-option ${selected === scenario.id ? 'is-selected' : ''}`}
            aria-label={scenario.display_name}
            aria-pressed={selected === scenario.id}
            key={scenario.id}
            onClick={() => setSelected(scenario.id)}
          >
            {scenario.mystery ? <EyeOff size={18} /> : <ShieldCheck size={18} />}
            <strong>{scenario.display_name}</strong>
            <span>{scenario.mystery ? 'Configuration withheld until reveal' : 'Known controlled configuration'}</span>
          </button>
        ))}
      </div>
      <button className="button button-primary scenario-create" type="button" disabled={!selected} onClick={() => onCreate(selected)}>
        Create lab session
      </button>
    </section>
  )
}
