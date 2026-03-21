import type { PackageAnalysis } from "@binshield/analysis-types";

import { RiskBadge } from "./risk-badge";

export function AnalysisCard({ analysis }: { analysis: PackageAnalysis }) {
  return (
    <article className="analysis-card">
      <div className="analysis-card__header">
        <div>
          <p className="eyebrow">{analysis.ecosystem}</p>
          <h3>
            {analysis.packageName}@{analysis.version}
          </h3>
        </div>
        <RiskBadge level={analysis.riskLevel} score={analysis.riskScore} />
      </div>
      <p>{analysis.summary}</p>
      <dl className="analysis-card__meta">
        <div>
          <dt>Binaries</dt>
          <dd>{analysis.binaryCount}</dd>
        </div>
        <div>
          <dt>Confidence</dt>
          <dd>{analysis.sourceMatchConfidence}</dd>
        </div>
        <div>
          <dt>Model</dt>
          <dd>{analysis.aiModel}</dd>
        </div>
      </dl>
    </article>
  );
}
