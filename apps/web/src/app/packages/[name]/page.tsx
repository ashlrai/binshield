import Link from "next/link";
import { notFound } from "next/navigation";

import { AnalysisCard } from "../../../components/analysis-card";
import { MetricCard } from "../../../components/metric-card";
import { PageHeader } from "../../../components/page-header";
import { RiskBadge } from "../../../components/risk-badge";
import { getPackageSummaryStats, getPackageWorkspace } from "../../../lib/site-data";

export default async function PackagePage({
  params,
  searchParams
}: {
  params: Promise<{ name: string }>;
  searchParams: Promise<{ version?: string }>;
}) {
  const { name } = await params;
  const { version } = await searchParams;
  const workspace = await getPackageWorkspace(name, version);

  if (!workspace.found) {
    notFound();
  }

  const stats = getPackageSummaryStats(workspace.selected);

  return (
    <main className="detail-page">
      <PageHeader
        eyebrow="Package detail"
        title={`${workspace.packageName}@${workspace.selected.version}`}
        description="Inspect the package-level summary, then drill into the binaries, findings, and version history behind the score."
        actions={
          <Link href="/packages" className="button-link">
            Back to browser
          </Link>
        }
      />

      <section className="detail-hero">
        <AnalysisCard analysis={workspace.selected} />
        <div className="detail-hero__aside">
          {stats.map((stat) => (
            <MetricCard key={stat.label} label={stat.label} value={stat.value} detail={stat.detail} />
          ))}
        </div>
      </section>

      <section className="surface-grid surface-grid--split">
        <div className="panel">
          <div className="panel__heading">
            <h2>Version history</h2>
            <span>{workspace.versions.length} analyzed versions</span>
          </div>
          <div className="version-pills">
            {workspace.versions.map((analysis) => (
              <Link
                key={analysis.version}
                href={`/packages/${workspace.packageName}?version=${encodeURIComponent(analysis.version)}`}
                className={`version-pill ${analysis.version === workspace.selected.version ? "version-pill--active" : ""}`}
              >
                <strong>{analysis.version}</strong>
                <span>{analysis.riskLevel}</span>
              </Link>
            ))}
          </div>
          <ul className="timeline timeline--compact">
            <li>Confidence: {workspace.selected.sourceMatchConfidence}</li>
            <li>Analysis model: {workspace.selected.aiModel}</li>
            <li>Data mode: {workspace.mode === "live" ? "Connected to API" : "Demo fallback"}</li>
          </ul>
        </div>

        <div className="panel">
          <div className="panel__heading">
            <h2>Behavior drift</h2>
            <span>{workspace.diff.fromVersion} to {workspace.diff.toVersion}</span>
          </div>
          <p>{workspace.diff.summary}</p>
          <div className="tag-list">
            {workspace.diff.addedBehaviors.map((change) => (
              <span key={change} className="tag">
                Added: {change}
              </span>
            ))}
            {workspace.diff.removedBehaviors.map((change) => (
              <span key={change} className="tag tag-muted">
                Removed: {change}
              </span>
            ))}
          </div>
        </div>
      </section>

      <section className="surface-grid surface-grid--split">
        <div className="panel">
          <div className="panel__heading">
            <h2>Binaries</h2>
            <span>{workspace.selected.binaryCount} native artifacts</span>
          </div>
          <div className="binary-list">
            {workspace.selected.binaries.map((binary) => (
              <article key={binary.id} className="binary-row">
                <div className="binary-row__heading">
                  <div>
                    <h3>{binary.filename}</h3>
                    <p>
                      {binary.architecture} • {binary.format} • {binary.functionCount} functions • {Math.round(binary.fileSize / 1024)} KB
                    </p>
                  </div>
                  <RiskBadge level={binary.riskLevel} score={binary.riskScore} />
                </div>
                <p>{binary.aiExplanation}</p>
                <code>{binary.decompiledPreview}</code>
                <div className="binary-grid">
                  <div>
                    <strong>Imports</strong>
                    <p>{binary.imports.join(", ")}</p>
                  </div>
                  <div>
                    <strong>Interesting strings</strong>
                    <p>{binary.strings.join(", ")}</p>
                  </div>
                </div>
                <div className="tag-list">
                  {Object.entries(binary.behaviors).map(([key, signal]) =>
                    signal.detected ? (
                      <span key={key} className="tag">
                        {key}
                      </span>
                    ) : null
                  )}
                </div>
              </article>
            ))}
          </div>
        </div>

        <div className="panel">
          <div className="panel__heading">
            <h2>Related packages</h2>
            <span>Similar signal surface</span>
          </div>
          <div className="stack-list">
            {workspace.related.length ? (
              workspace.related.map((item) => (
                <Link key={item.packageName} href={`/packages/${item.packageName}`} className="stack-item stack-item--link">
                  <div>
                    <p className="eyebrow">{item.ecosystem}</p>
                    <strong>{item.packageName}</strong>
                    <p>{item.summary}</p>
                  </div>
                  <RiskBadge level={item.riskLevel} score={item.riskScore} />
                </Link>
              ))
            ) : (
              <p className="empty-state">No related packages surfaced from the current dataset.</p>
            )}
          </div>
        </div>
      </section>
    </main>
  );
}
