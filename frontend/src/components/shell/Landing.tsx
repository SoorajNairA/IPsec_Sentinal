import { useRef, type DragEvent, type KeyboardEvent } from 'react'
import { Activity, ArrowUpRight, EyeOff, LockKeyhole, Play, ScanSearch, Upload } from 'lucide-react'
import { Link } from 'react-router-dom'

import { useAnalysis } from '../../app/AnalysisContext'
import { AnalysisProgress } from './AnalysisProgress'
import { DemoChooser } from './DemoChooser'
import { AnalysisError } from '../shared/AnalysisError'
import '../shared/shared.css'

const TRUST_INDICATORS = [
  { icon: LockKeyhole, label: 'Local Analysis', detail: 'Capture stays on this device' },
  { icon: EyeOff, label: 'Payload Decryption: Never', detail: 'ESP contents remain encrypted' },
  { icon: ScanSearch, label: 'Evidence-Aware Results', detail: 'Every claim shows its source' },
]

export function Landing() {
  const { analyzeFile, error, openDemoChooser, reset, status } = useAnalysis()
  const inputRef = useRef<HTMLInputElement>(null)
  const isAnalyzing = status === 'ANALYZING'

  const submit = (file?: File) => {
    if (file) void analyzeFile(file)
  }
  const drop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault()
    submit(event.dataTransfer.files[0])
  }
  const activateDropzone = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault()
      inputRef.current?.click()
    }
  }

  if (isAnalyzing) return <AnalysisProgress />

  return (
    <div className="app-canvas">
      <header className="topbar">
        <a className="brand" href="/" aria-label="IPsec Sentinel home">
          <span className="brand-mark" aria-hidden="true"><Activity size={17} strokeWidth={1.8} /></span>
          <span>IPsec Sentinel</span>
        </a>
        <span className="prototype-label">Interactive security lab · Local</span>
      </header>

      <main className="landing">
        <section className="hero" aria-labelledby="product-title">
          <div className="eyebrow"><span />Live encrypted traffic intelligence</div>
          <h1 id="product-title">IPsec Sentinel</h1>
          <p className="hero-statement">Build the tunnel. Generate traffic. Watch Sentinel explain it.</p>
          <p className="hero-copy">
            Establish a real isolated IPsec session, observe IKE and ESP as they happen, then test traffic intelligence and forward-secrecy evidence yourself.
          </p>

          <div className="hero-actions">
            <Link className="button button-primary" to="/live">
              <Activity size={17} />
              Start Live Lab
              <ArrowUpRight className="button-trailing" size={15} />
            </Link>
            <button className="button button-secondary" type="button" onClick={() => inputRef.current?.click()}>
              <Upload size={17} />
              Offline PCAP Analysis
            </button>
            <button className="button button-secondary" type="button" onClick={() => void openDemoChooser()}>
              <Play size={16} fill="currentColor" />
              Run Guided Demo
            </button>
          </div>
          <input
            ref={inputRef}
            className="visually-hidden"
            type="file"
            accept=".pcap,.pcapng,application/vnd.tcpdump.pcap"
            aria-label="Choose a classic PCAP capture"
            onChange={(event) => submit(event.currentTarget.files?.item(0) ?? undefined)}
          />
          {(status === 'ERROR' || status === 'UNSUPPORTED') && error && <AnalysisError code={error.code} unsafeMessage={error.message} onReset={reset} />}
        </section>

        <div
          className="intake-preview"
          role="button"
          tabIndex={0}
          aria-label="Drop a packet capture here or choose a file"
          onClick={() => inputRef.current?.click()}
          onKeyDown={activateDropzone}
          onDragOver={(event) => event.preventDefault()}
          onDrop={drop}
        >
          <div className="intake-grid" aria-hidden="true" />
          <div className="intake-header">
            <span>CAPTURE INTAKE</span>
            <span className="live-dot">READY</span>
          </div>
          <div className="intake-tunnel" aria-hidden="true">
            <span className="endpoint endpoint-left" />
            <span className="tunnel-line" />
            <span className="packet packet-one" />
            <span className="packet packet-two" />
            <span className="endpoint endpoint-right" />
          </div>
          <div className="intake-body">
            <p>Drop a packet capture here</p>
            <span>Classic PCAP · Ethernet / IPv4</span>
          </div>
          <div className="intake-footer">
            <span>IKE</span><strong>NEGOTIATION</strong>
            <span>ESP</span><strong>BEHAVIOR</strong>
            <span>SA</span><strong>CHRONOLOGY</strong>
          </div>
        </div>
      </main>

      <footer className="trust-strip" aria-label="Analysis trust indicators">
        {TRUST_INDICATORS.map(({ icon: Icon, label, detail }) => (
          <div className="trust-item" key={label}>
            <Icon size={17} strokeWidth={1.7} aria-hidden="true" />
            <span><strong>{label}</strong><small>{detail}</small></span>
          </div>
        ))}
      </footer>
      <DemoChooser />
    </div>
  )
}
