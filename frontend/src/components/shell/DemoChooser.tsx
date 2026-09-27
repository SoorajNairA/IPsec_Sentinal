import * as Dialog from '@radix-ui/react-dialog'
import { ArrowRight, Database, X } from 'lucide-react'

import { useAnalysis } from '../../app/AnalysisContext'

export function DemoChooser() {
  const { closeDemoChooser, demos, loadDemo, status } = useAnalysis()
  return (
    <Dialog.Root open={status === 'DEMO_CHOOSER'} onOpenChange={(open) => { if (!open) closeDemoChooser() }}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <Dialog.Content className="demo-dialog" aria-describedby="demo-description">
          <div className="dialog-kicker"><Database size={14} /> Genuine retained captures</div>
          <Dialog.Title>Choose a guided demo</Dialog.Title>
          <Dialog.Description id="demo-description">
            Each scenario is a checksummed analyzer result generated from real retained capture evidence.
          </Dialog.Description>
          <div className="demo-list">
            {demos ? demos.demos.map((demo) => (
              <button key={demo.id} type="button" className="demo-option" onClick={() => void loadDemo(demo.id)}>
                <span><strong>{demo.label}</strong><small>{demo.description}</small></span>
                <ArrowRight size={16} aria-hidden="true" />
              </button>
            )) : <div className="demo-loading" role="status">Loading verified demos…</div>}
          </div>
          <Dialog.Close className="dialog-close" aria-label="Close guided demos"><X size={18} /></Dialog.Close>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
