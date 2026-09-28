import { AlertTriangle, BrainCircuit, LockKeyhole, PlugZap } from 'lucide-react'

import { useLiveLab } from '../LiveLabContext'
import { ConnectionTimeline } from '../../components/live/ConnectionTimeline'
import { LiveSessionHeader } from '../../components/live/LiveSessionHeader'
import { ScenarioPicker } from '../../components/live/ScenarioPicker'
import { SecurityActions } from '../../components/live/SecurityActions'
import { TrafficControls } from '../../components/live/TrafficControls'
import { LiveEventTunnel } from '../../components/tunnel/LiveTunnel'
import '../../components/live/live.css'

function MysteryComparison({ events }: { events: ReturnType<typeof useLiveLab>['events'] }) {
  const reveal = [...events].reverse().find((event) => event.type === 'mystery.revealed')
  if (!reveal) return null
  const groundTruth = reveal.data.ground_truth
  if (!groundTruth || typeof groundTruth !== 'object' || Array.isArray(groundTruth)) return null
  const truth = groundTruth as Record<string, unknown>
  return (
    <section className="mystery-comparison" role="region" aria-label="Mystery VPN comparison">
      <span>GROUND TRUTH REVEALED</span>
      <h2>Sentinel result vs controlled configuration</h2>
      <dl>
        <div><dt>Scenario</dt><dd>{String(truth.display_name ?? truth.scenario_id ?? 'Unknown')}</dd></div>
        <div><dt>Encryption</dt><dd>{String(truth.encryption ?? 'Unknown')}</dd></div>
        <div><dt>CHILD SA PFS</dt><dd>{String(truth.pfs ?? 'Unknown')}</dd></div>
      </dl>
    </section>
  )
}

export function LiveLabView() {
  const live = useLiveLab()
  const { catalogue, session, events, analysis, problem } = live
  if (!session) {
    return (
      <div className="live-lab-start">
        <header className="live-lab-intro">
          <p className="eyebrow"><span />Interactive IPsec experimentation</p>
          <h1>Start Live Lab</h1>
          <p>Establish a real isolated VPN, generate protected traffic, trigger a CHILD SA rekey, and watch Sentinel derive each result from live evidence.</p>
          <div className="live-trust"><LockKeyhole size={15} />Local namespace sandbox · No system-wide VPN routing</div>
        </header>
        {problem && <div className="live-problem" role="alert"><AlertTriangle size={16} /><span><strong>{problem.code}</strong>{problem.message}</span></div>}
        {catalogue ? <ScenarioPicker scenarios={catalogue.scenarios} onCreate={(id) => void live.createSession(id)} /> : <p className="live-agent-waiting">Waiting for the loopback Sentinel Agent...</p>}
      </div>
    )
  }

  const predictedClass = analysis?.analysis.traffic_intelligence.predicted_class
  const score = analysis?.analysis.security_score.total
  const connecting = session.active_action === 'CONNECT' || !['IDLE', 'TUNNEL_ACTIVE', 'TRAFFIC_RUNNING', 'REKEYING', 'ANALYZING', 'READY', 'COMPLETE', 'FAILED'].includes(session.state)

  return (
    <div className="live-lab-view">
      <LiveSessionHeader session={session} events={events} />
      {problem && <div className="live-problem" role="alert"><AlertTriangle size={16} /><span><strong>{problem.code}</strong>{problem.message}</span></div>}

      {session.state === 'IDLE' && (
        <section className="connect-panel">
          <div><span>SESSION READY</span><h1>{session.display_name}</h1><p>The sandbox is reserved. Connection work begins only when you click Connect.</p></div>
          <button className="button button-primary" type="button" disabled={!session.allowed_actions.includes('CONNECT')} onClick={() => void live.connect()}><PlugZap size={17} />Connect</button>
        </section>
      )}

      <div className="live-primary-grid">
        <div className="live-main-column">
          <LiveEventTunnel session={session} events={events} />
          <div className="progressive-results" aria-live="polite">
            <section>
              <span>Traffic intelligence</span>
              {predictedClass ? <><strong>{predictedClass.toUpperCase()}</strong><small>{((analysis?.analysis.traffic_intelligence.raw_confidence ?? 0) * 100).toFixed(1)}% raw confidence · AI-INFERRED</small></> : <strong className="is-waiting">Waiting for completed workload analysis</strong>}
            </section>
            <section>
              <span>Security posture</span>
              {score === undefined ? <strong className="is-waiting">Collecting evidence...</strong> : <><strong>{score}/100</strong><small>Rule assessment complete</small></>}
            </section>
            <section>
              <span>Payload visibility</span><strong>0%</strong><small>Payload decrypted: NO</small>
            </section>
          </div>
          {session.tunnel_status === 'ACTIVE' && (
            <div className="live-controls-layout">
              <TrafficControls session={session} workloads={catalogue?.workloads ?? []} onRun={(id) => void live.runTraffic(id)} />
              <SecurityActions
                session={session}
                onRekey={() => void live.triggerRekey()}
                onRefresh={() => void live.refresh()}
                onAnalyze={() => void live.analyze()}
                onReveal={() => void live.reveal()}
                onDisconnect={() => void live.disconnect()}
              />
            </div>
          )}
          {session.state === 'READY' && session.tunnel_status !== 'ACTIVE' && (
            <SecurityActions
              session={session}
              onRekey={() => void live.triggerRekey()}
              onRefresh={() => void live.refresh()}
              onAnalyze={() => void live.analyze()}
              onReveal={() => void live.reveal()}
              onDisconnect={() => void live.disconnect()}
            />
          )}
          <MysteryComparison events={events} />
        </div>
        <ConnectionTimeline events={events} />
      </div>
      {connecting && <p className="visually-hidden" aria-live="polite">{session.state_reason}</p>}
      {analysis && (
        <footer className="live-analysis-ready"><BrainCircuit size={16} /><span>Validated session analysis is ready in Tunnel, Traffic, Security, Evidence, and Report.</span></footer>
      )}
    </div>
  )
}
