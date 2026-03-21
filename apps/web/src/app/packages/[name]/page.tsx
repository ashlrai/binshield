import { notFound } from "next/navigation";

import { AnalysisCard } from "../../../components/analysis-card";
import { RiskBadge } from "../../../components/risk-badge";
import { getPackageAnalysis, getPackageDiff } from "../../../lib/data";

export default async function PackagePage({ params }: { params: Promise<{ name: string }> }) {
  const { name } = await params;
  const analysis = await getPackageAnalysis(name);

  if (!analysis) {
    notFound();
  }

  const diff = await getPackageDiff(name);

  return (
    <main className="detail-page">
      <section className="detail-hero">
        <AnalysisCard analysis={analysis} />
      </section>

      <section className="detail-grid">
        <article className="panel">
          <div className="panel__heading">
            <h2>Binaries</h2>
            <span>{analysis.binaryCount} discovered</span>
          </div>
          <div className="binary-list">
            {analysis.binaries.map((binary) => (
              <article key={binary.id} className="binary-row">
                <div>
                  <h3>{binary.filename}</h3>
                  <p>
                    {binary.architecture} • {binary.format} • {binary.functionCount} functions
                  </p>
                </div>
                <RiskBadge level={binary.riskLevel} score={binary.riskScore} />
                <p>{binary.aiExplanation}</p>
                <code>{binary.decompiledPreview}</code>
              </article>
            ))}
          </div>
        </article>

        <article className="panel">
          <div className="panel__heading">
            <h2>Version diff</h2>
            <span>
              {diff.fromVersion} to {diff.toVersion}
            </span>
          </div>
          <p>{diff.summary}</p>
          <div className="tag-list">
            {diff.addedBehaviors.map((change) => (
              <span key={change} className="tag">
                Added: {change}
              </span>
            ))}
            {diff.removedBehaviors.map((change) => (
              <span key={change} className="tag tag-muted">
                Removed: {change}
              </span>
            ))}
          </div>
        </article>
      </section>
    </main>
  );
}
