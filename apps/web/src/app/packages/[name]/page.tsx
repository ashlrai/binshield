import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";

import { BehaviorFlow } from "../../../components/behavior-flow";
import { CallGraph } from "../../../components/call-graph";
import { CodeViewer } from "../../../components/code-viewer";
import { MetricCard } from "../../../components/metric-card";
import { MethodologyPanel } from "../../../components/methodology-panel";
import { PageHeader } from "../../../components/page-header";
import { RiskBadge } from "../../../components/risk-badge";
import { RiskTimeline } from "../../../components/risk-timeline";
import { getPackageSummaryStats, getPackageWorkspace } from "../../../lib/site-data";

export async function generateMetadata({
  params,
  searchParams
}: {
  params: Promise<{ name: string }>;
  searchParams: Promise<{ version?: string }>;
}): Promise<Metadata> {
  const { name } = await params;
  const { version } = await searchParams;
  const workspace = await getPackageWorkspace(name, version);

  if (!workspace.found) {
    return {
      title: `${decodeURIComponent(name)} — Not Found`
    };
  }

  const riskLabel = workspace.selected.riskLevel.charAt(0).toUpperCase() + workspace.selected.riskLevel.slice(1);

  return {
    title: `${workspace.packageName} Binary Analysis`,
    description: `${riskLabel} risk (score ${workspace.selected.riskScore}/100) — ${workspace.selected.summary}. ${workspace.selected.binaryCount} native binaries analyzed by BinShield.`,
    alternates: {
      canonical: `https://binshield.dev/packages/${encodeURIComponent(workspace.packageName)}`
    },
    openGraph: {
      title: `${workspace.packageName} Binary Analysis | BinShield`,
      description: `${riskLabel} risk (score ${workspace.selected.riskScore}/100). ${workspace.selected.binaryCount} native binaries decompiled and classified.`,
      url: `https://binshield.dev/packages/${encodeURIComponent(workspace.packageName)}`
    }
  };
}

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
        description="Treat this as an investigation surface: start with package posture, then inspect binary evidence, finding clusters, and version drift before approving rollout."
        actions={
          <>
            <Link href="/packages" className="button-link">
              Back to browser
            </Link>
            <Link href={`#binary-${workspace.evidenceCards[0]?.id ?? "evidence"}`} className="button-link button-link--ghost">
              Jump to evidence
            </Link>
          </>
        }
      />

      <section className="detail-hero">
        <article className="analysis-card analysis-card--investigation">
          <div className="analysis-card__header">
            <div>
              <p className="eyebrow">{workspace.selected.ecosystem}</p>
              <h3>
                {workspace.selected.packageName}@{workspace.selected.version}
              </h3>
            </div>
            <RiskBadge level={workspace.selected.riskLevel} score={workspace.selected.riskScore} />
          </div>
          <p>{workspace.selected.summary}</p>
          <div className="signal-grid">
            {workspace.packageSignals.map((signal) => (
              <article key={signal.label} className="signal-card">
                <span>{signal.label}</span>
                <strong>{signal.value}</strong>
                <p>{signal.detail}</p>
              </article>
            ))}
          </div>
        </article>
        <div className="detail-hero__aside">
          {stats.map((stat) => (
            <MetricCard key={stat.label} label={stat.label} value={stat.value} detail={stat.detail} />
          ))}
        </div>
      </section>

      <section className="surface-grid surface-grid--split">
        <div className="panel">
          <div className="panel__heading">
            <h2>Analyst takeaways</h2>
            <span>{workspace.evidenceSummary.length} evidence summaries</span>
          </div>
          <div className="evidence-summary-list">
            {workspace.evidenceSummary.map((item) => (
              <article key={item.title} className={`evidence-summary evidence-summary--${item.tone}`}>
                <strong>{item.title}</strong>
                <p>{item.detail}</p>
              </article>
            ))}
          </div>
        </div>

        <div className="panel">
          <div className="panel__heading">
            <h2>Version history</h2>
            <span>{workspace.versionTimeline.length} analyzed versions</span>
          </div>
          <RiskTimeline
            points={workspace.versionTimeline.map((entry) => ({
              version: entry.version,
              riskScore: entry.riskScore,
              riskLevel: entry.riskLevel,
              binaryCount: entry.binaryCount,
              active: entry.active
            }))}
          />
          <div className="version-pills">
            {workspace.versionTimeline.map((analysis) => (
              <Link
                key={analysis.version}
                href={`/packages/${workspace.packageName}?version=${encodeURIComponent(analysis.version)}`}
                className={`version-pill ${analysis.active ? "version-pill--active" : ""}`}
              >
                <strong>{analysis.version}</strong>
                <span>
                  {analysis.riskLevel} ({analysis.riskScore})
                </span>
                <small>{analysis.changedLabel}</small>
              </Link>
            ))}
          </div>
          <ul className="timeline timeline--compact">
            <li>Confidence: {workspace.selected.sourceMatchConfidence}</li>
            <li>Analysis model: {workspace.selected.aiModel}</li>
            <li>Data mode: {workspace.mode === "live" ? "Connected to API" : "Demo fallback"}</li>
          </ul>
        </div>
      </section>

      <section className="surface-grid surface-grid--split">
        <div className="panel">
          <div className="panel__heading">
            <h2>Version drift</h2>
            <span>
              {workspace.diff.fromVersion} to {workspace.diff.toVersion}
            </span>
          </div>
          <p>{workspace.diffNarrative.headline}</p>
          <p className="panel__supporting-copy">{workspace.diffNarrative.analystNote}</p>
          <div className="impact-banner">
            <strong>{workspace.diffNarrative.impactLabel}</strong>
            <span>Use this as triage guidance, then validate against binary evidence below.</span>
          </div>
          <div className="tag-list">
            {workspace.diffNarrative.addedBehaviors.map((change) => (
              <span key={change} className="tag">
                Added: {change}
              </span>
            ))}
            {workspace.diffNarrative.removedBehaviors.map((change) => (
              <span key={change} className="tag tag-muted">
                Removed: {change}
              </span>
            ))}
          </div>
          <ol className="timeline">
            {workspace.diffNarrative.reviewChecklist.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ol>
        </div>

        <div className="panel">
          <div className="panel__heading">
            <h2>Finding clusters</h2>
            <span>{workspace.findingsBySeverity.reduce((total, bucket) => total + bucket.findings.length, 0)} findings</span>
          </div>
          {workspace.findingsBySeverity.length ? (
            <div className="finding-groups">
              {workspace.findingsBySeverity.map((bucket) => (
                <article key={bucket.severity} className="finding-group">
                  <div className="finding-group__header">
                    <strong>{bucket.severity.toUpperCase()}</strong>
                    <span>{bucket.findings.length} items</span>
                  </div>
                  <div className="finding-list">
                    {bucket.findings.map((finding) => (
                      <div key={`${bucket.severity}-${finding.title}-${finding.location ?? "root"}`} className="finding-row">
                        <h3>{finding.title}</h3>
                        <p>{finding.description}</p>
                        <small>{finding.recommendation}</small>
                      </div>
                    ))}
                  </div>
                </article>
              ))}
            </div>
          ) : (
            <p className="empty-state">No escalated findings were emitted for this package version.</p>
          )}
        </div>
      </section>

      <section className="surface-grid surface-grid--split">
        <div className="panel">
          <div className="panel__heading">
            <h2>Binary evidence</h2>
            <span>{workspace.selected.binaryCount} native artifacts</span>
          </div>
          <div className="binary-list">
            {workspace.evidenceCards.map((binary) => (
              <article key={binary.id} id={`binary-${binary.id}`} className={`binary-row binary-row--${binary.tone}`}>
                <div className="binary-row__heading">
                  <div>
                    <h3>{binary.filename}</h3>
                    <p>
                      {binary.architecture} • {binary.format} • {binary.sizeLabel}
                    </p>
                  </div>
                  <RiskBadge level={binary.riskLevel} score={binary.riskScore} />
                </div>
                <p>{binary.headline}</p>
                <p className="panel__supporting-copy">{binary.explanation}</p>
                <div className="tag-list">
                  {binary.behaviors.map((behavior) => (
                    <span key={`${binary.id}-${behavior.name}`} className={`tag tag--${behavior.tone}`}>
                      {behavior.name}: {behavior.summary}
                    </span>
                  ))}
                </div>
                <div className="evidence-checklist">
                  {binary.evidenceChecklist.map((item) => (
                    <span key={`${binary.id}-${item}`}>{item}</span>
                  ))}
                </div>
                <div className="surface-grid surface-grid--split">
                  <BehaviorFlow
                    behaviors={workspace.selected.binaries.find((b) => b.id === binary.id)?.behaviors ?? {
                      network: { detected: false, details: [] },
                      filesystem: { detected: false, details: [] },
                      process: { detected: false, details: [] },
                      crypto: { detected: false, details: [] },
                      obfuscation: { detected: false, details: [] },
                      dataExfiltration: { detected: false, details: [] }
                    }}
                    binaryName={binary.filename}
                  />
                  <CallGraph
                    imports={binary.imports}
                    callTargets={binary.imports.slice(0, 6)}
                    binaryName={binary.filename}
                    functionCount={workspace.selected.binaries.find((b) => b.id === binary.id)?.functionCount ?? 0}
                  />
                </div>
                <CodeViewer source={binary.decompiledPreview} language="c" />
                <div className="binary-grid">
                  <div>
                    <strong>Imports</strong>
                    <p>{binary.imports.length ? binary.imports.join(", ") : "No imports surfaced in the preview."}</p>
                  </div>
                  <div>
                    <strong>Interesting strings</strong>
                    <p>{binary.strings.length ? binary.strings.join(", ") : "No high-signal strings surfaced."}</p>
                  </div>
                </div>
                {binary.findings.length ? (
                  <div className="finding-list">
                    {binary.findings.map((finding) => (
                      <div key={`${binary.id}-${finding.title}`} className="finding-row">
                        <h3>{finding.title}</h3>
                        <p>{finding.description}</p>
                        <small>{finding.recommendation}</small>
                      </div>
                    ))}
                  </div>
                ) : null}
                <Link
                  href={`/packages/${workspace.packageName}/binaries/${binary.id}?version=${encodeURIComponent(workspace.selected.version)}`}
                  className="binary-row__link"
                >
                  Open binary evidence view
                </Link>
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
                    <small className="stack-item__meta">
                      {item.topBehaviors.length ? item.topBehaviors.join(", ") : "No strong behavior signal"} • {item.sourceMatchConfidence} confidence
                    </small>
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

      <MethodologyPanel currentScore={workspace.selected.riskScore} currentLevel={workspace.selected.riskLevel} />
    </main>
  );
}
