import { Activity, ArrowUpRight, EyeOff, LockKeyhole, Play, ScanSearch, Upload } from 'lucide-react'

const TRUST_INDICATORS = [
  { icon: LockKeyhole, label: 'Local Analysis', detail: 'Capture stays on this device' },
  { icon: EyeOff, label: 'Payload Decryption: Never', detail: 'ESP contents remain encrypted' },
  { icon: ScanSearch, label: 'Evidence-Aware Results', detail: 'Every claim shows its source' },
]

export function App() {
  return (
    <div className="app-canvas">
      <header className="topbar">
        <a className="brand" href="/" aria-label="IPsec Sentinel home">
          <span className="brand-mark" aria-hidden="true"><Activity size={17} strokeWidth={1.8} /></span>
          <span>IPsec Sentinel</span>
        </a>
        <span className="prototype-label">Forensic workspace · Local</span>
      </header>

      <main className="landing">
        <section className="hero" aria-labelledby="product-title">
          <div className="eyebrow"><span />Encrypted traffic intelligence</div>
          <h1 id="product-title">IPsec Sentinel</h1>
          <p className="hero-statement">See what your encrypted tunnel actually reveals.</p>
          <p className="hero-copy">
            Reconstruct IKE negotiation, trace Security Associations, and analyze ESP behavior—without decrypting a single payload.
          </p>

          <div className="hero-actions">
            <button className="button button-primary" type="button">
              <Upload size={17} />
              Analyze Capture
              <ArrowUpRight className="button-trailing" size={15} />
            </button>
            <button className="button button-secondary" type="button">
              <Play size={16} fill="currentColor" />
              Run Guided Demo
            </button>
          </div>
        </section>

        <aside className="intake-preview" aria-label="Analysis intake preview">
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
        </aside>
      </main>

      <footer className="trust-strip" aria-label="Analysis trust indicators">
        {TRUST_INDICATORS.map(({ icon: Icon, label, detail }) => (
          <div className="trust-item" key={label}>
            <Icon size={17} strokeWidth={1.7} aria-hidden="true" />
            <span><strong>{label}</strong><small>{detail}</small></span>
          </div>
        ))}
      </footer>
    </div>
  )
}

