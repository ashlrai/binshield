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
        <div>
          <dt>Status</dt>
          <dd>{analysis.status}</dd>
        </div>
        <div>
          <dt>Updated</dt>
          <dd>{new Date(analysis.createdAt).toLocaleDateString("en-US", { month: "short", day: "numeric" })}</dd>
        </div>
        <div>
          <dt>Risk</dt>
          <dd>{analysis.riskLevel}</dd>
        </div>
      </dl>
    </article>
  );
}
