import { Printer, ScanSearch } from 'lucide-react'

import type { AnalysisV1 } from '../../lib/analysis-contract/types'
import type { AnalysisView } from '../../lib/presentation/analysisView'
import { explain, type ExplanationMode } from '../../lib/presentation/plainEnglish'
import { ProvenanceMark } from '../evidence/ProvenanceMark'
import './report.css'

export function AnalysisReport({ analysis, analysisView, mode, onInspectEvidence }: { analysis: AnalysisV1; analysisView: AnalysisView; mode: ExplanationMode; onInspectEvidence: (ids: readonly string[], valueLabel?: string) => void }) {
  const pfs = analysis.pfs
  const activeFindings = analysisView.findings.filter((finding) => finding.status !== 'PASS')
  return (
    <article className="analysis-report">
      <div className="report-masthead">
        <div><span>IPSEC SENTINEL / ANALYSIS REPORT</span><strong>{analysis.capture.path.split('/').at(-1)}</strong></div>
        <button type="button" className="screen-only" onClick={() => window.print()} aria-label="Print report"><Printer size={15} />Print report</button>
      </div>
      <section><h2>Executive Summary</h2><p className="report-lead">{analysis.summary.message}</p><p>{analysisView.score.postureLabel}. Analysis found {analysis.protocols.ike_version} with {analysis.esp.packet_count.toLocaleString()} ESP packets and no payload decryption.</p></section>
      <section><h2>Security Score</h2><div className="report-score"><strong>{analysisView.score.total}</strong><span>/ {analysisView.score.maximum}</span><p>{analysisView.score.coverage}% assessed · {analysisView.score.unassessed}% unassessed</p></div><small>{analysis.security_score.method}</small></section>
      <section><h2>Protocol Configuration</h2><dl className="report-grid"><div><dt>IKE</dt><dd>{analysis.ike.version}</dd></div><div><dt>Encryption</dt><dd>{String(analysis.ike.encryption.normalized)} <ProvenanceMark provenance={analysis.ike.encryption.provenance} compact /></dd></div><div><dt>Integrity</dt><dd>{String(analysis.ike.integrity.normalized)}</dd></div><div><dt>DH group</dt><dd>{String(analysis.ike.dh_group.normalized)}</dd></div><div><dt>PFS</dt><dd>{pfs?.state ?? 'unknown'} <ProvenanceMark provenance={pfs?.provenance ?? 'UNKNOWN'} compact /></dd></div></dl>{pfs && <p>{explain(pfs.state === 'disabled' ? 'pfs_disabled' : 'pfs_enabled', mode, pfs.explanation)}</p>}</section>
      <section><h2>Traffic Intelligence</h2><div className="report-callout"><strong>{analysisView.traffic.predictedClass.replace('_', ' ')}</strong><span>{analysisView.traffic.confidenceLabel}</span><ProvenanceMark provenance={analysis.traffic_intelligence.provenance} /></div><p>{explain('raw_confidence', mode, 'The displayed confidence is raw and uncalibrated.')}</p><p>{analysisView.traffic.payloadLabel}. {explain('metadata_exposure', mode, 'ESP conceals payload while exposing timing, captured length, and direction.')}</p></section>
      <section><h2>Key Findings</h2><div className="report-findings">{analysisView.findings.map((finding) => <article key={finding.rule_id}><span>{finding.severity} / {finding.status}</span><strong>{finding.title}</strong><p>{finding.summary}</p><ProvenanceMark provenance={finding.provenance} compact />{finding.evidence_ids.length > 0 && <button className="screen-only" type="button" onClick={() => onInspectEvidence(finding.evidence_ids, finding.title)}><ScanSearch size={13} />Evidence</button>}</article>)}</div></section>
      <section><h2>Risk Summary</h2><p>{activeFindings.length ? `${activeFindings.length} non-passing analyzer finding${activeFindings.length === 1 ? '' : 's'} require review.` : 'No non-passing analyzer findings were reported.'}</p></section>
      <section><h2>Evidence Coverage</h2><p>{analysis.evidence.length} evidence records support this analysis. {analysisView.score.coverage}% of the weighted posture was assessed; unknown evidence remains unassessed rather than penalized.</p></section>
      <section><h2>Recommendations</h2><ol>{analysisView.findings.map((finding) => <li key={`recommendation-${finding.rule_id}`}>{finding.recommendation}</li>)}</ol></section>
      <section><h2>Limitations</h2><ul>{analysis.limitations.map((limitation) => <li key={limitation.code}><code>{limitation.code}</code><span>{limitation.description}</span></li>)}</ul></section>
    </article>
  )
}
