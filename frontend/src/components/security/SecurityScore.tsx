import type { AnalysisV1 } from '../../lib/analysis-contract/types'
import './security.css'

type Score = AnalysisV1['security_score']
type Finding = AnalysisV1['findings'][number]

export function SecurityScore({
  score,
  findings,
  onSelectDeduction,
}: {
  score: Score
  findings: Finding[]
  onSelectDeduction: (ids: readonly string[], valueLabel?: string) => void
}) {
  const findingByRule = new Map(findings.map((finding) => [finding.rule_id, finding]))
  return (
    <section className="security-score" aria-labelledby="security-score-heading">
      <header>
        <span className="section-kicker">Security posture</span>
        <h2 id="security-score-heading">Transparent score</h2>
      </header>
      <div className="score-lead">
        <div className="score-number"><strong>{score.total}</strong><span>/ {score.maximum}</span></div>
        <div className="coverage-composition" role="progressbar" aria-valuenow={score.assessed_weight} aria-valuemin={0} aria-valuemax={100} aria-label={`${score.assessed_weight}% evidence coverage and ${score.unassessed_weight}% unassessed`}>
          <span style={{ width: `${score.assessed_weight}%` }} />
        </div>
        <div className="coverage-labels"><strong>{score.assessed_weight}% evidence coverage</strong><span>{score.unassessed_weight}% unassessed</span></div>
      </div>
      <div className="score-categories">
        {score.categories.map((category) => (
          <article key={category.name}>
            <div className="category-heading"><span>{category.name}</span><strong>{category.achieved_score}/{category.maximum_score}</strong></div>
            <div className="category-track"><span style={{ width: `${category.maximum_score ? category.achieved_score / category.maximum_score * 100 : 0}%` }} /></div>
            {category.deductions.map((deduction) => (
              <button
                key={`${deduction.rule_id}-${deduction.points}`}
                type="button"
                className="deduction"
                aria-label={`Inspect ${deduction.points} point deduction for ${deduction.rule_id}`}
                onClick={() => onSelectDeduction(deduction.evidence_ids, `${deduction.points} point deduction`)}
              >
                <span>−{deduction.points}</span>{findingByRule.get(deduction.rule_id)?.title ?? deduction.rule_id}
              </button>
            ))}
          </article>
        ))}
      </div>
      <p className="score-method">{score.method}</p>
    </section>
  )
}
