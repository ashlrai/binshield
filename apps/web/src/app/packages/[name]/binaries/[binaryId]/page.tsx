import Link from "next/link";
import { notFound } from "next/navigation";

import { BehaviorFlow } from "../../../../../components/behavior-flow";
import { CallGraph } from "../../../../../components/call-graph";
import { CodeViewer } from "../../../../../components/code-viewer";
import { MetricCard } from "../../../../../components/metric-card";
import { MethodologyPanel } from "../../../../../components/methodology-panel";
import { PageHeader } from "../../../../../components/page-header";
import { RiskBadge } from "../../../../../components/risk-badge";
import { getBinaryWorkspace } from "../../../../../lib/site-data";

export default async function BinaryPage({
  params,
  searchParams
}: {
  params: Promise<{ name: string; binaryId: string }>;
  searchParams: Promise<{ version?: string }>;
}) {
  const { name, binaryId } = await params;
  const { version } = await searchParams;
  const workspace = await getBinaryWorkspace(name, binaryId, version);

  if (!workspace) {
    notFound();
  }

  return (
    <main className="detail-page">
      <nav className="breadcrumb-trail" aria-label="Breadcrumb">
        {workspace.breadcrumbs.map((item) => (
          <Link key={item.href} href={item.href}>
            {item.label}
          </Link>
        ))}
      </nav>

      <PageHeader
        eyebrow="Binary detail"
        title={workspace.binary.filename}
        description="Review one native artifact in depth: evidence checklist, surfaced imports and strings, grouped findings, and package-level context for approval decisions."
        actions={
          <Link
            href={`/packages/${workspace.packageName}?version=${encodeURIComponent(workspace.selectedVersion)}`}
            className="button-link"
          >
            Back to package
          </Link>
        }
      />

      <section className="detail-hero">
        <article className={`analysis-card analysis-card--investigation binary-card binary-card--${workspace.binary.tone}`}>
          <div className="analysis-card__header">
            <div>
              <p className="eyebrow">Binary evidence</p>
              <h3>{workspace.binary.filename}</h3>
            </div>
            <RiskBadge level={workspace.binary.riskLevel} score={workspace.binary.riskScore} />
          </div>
          <p>{workspace.binary.headline}</p>
          <p className="panel__supporting-copy">{workspace.binary.explanation}</p>
          <div className="tag-list">
            {workspace.binary.behaviors.map((behavior) => (
              <span key={behavior.name} className={`tag tag--${behavior.tone}`}>
                {behavior.name}: {behavior.summary}
              </span>
            ))}
          </div>
          <div className="evidence-checklist">
            {workspace.binary.evidenceChecklist.map((item) => (
              <span key={item}>{item}</span>
            ))}
          </div>
        </article>
        <div className="detail-hero__aside">
          <MetricCard label="Architecture" value={workspace.binary.architecture} detail="Recovered from artifact metadata" />
          <MetricCard label="Format" value={workspace.binary.format} detail="Executable/container format" />
          <MetricCard label="Size" value={workspace.binary.sizeLabel} detail="Binary payload size" />
          <MetricCard label="Package version" value={workspace.selectedVersion} detail={`${workspace.packageName} investigation target`} />
        </div>
      </section>

      <section className="surface-grid surface-grid--split">
        <div className="panel">
          <div className="panel__heading">
            <h2>Recovered evidence</h2>
            <span>Imports, strings, and decompile preview</span>
          </div>
          <div className="binary-grid">
            <div>
              <strong>Imports</strong>
              <p>{workspace.binary.imports.length ? workspace.binary.imports.join(", ") : "No imports surfaced in this preview."}</p>
            </div>
            <div>
              <strong>Interesting strings</strong>
              <p>{workspace.binary.strings.length ? workspace.binary.strings.join(", ") : "No high-signal strings surfaced."}</p>
            </div>
          </div>
          <CodeViewer source={workspace.binary.decompiledPreview} language="c" />
        </div>

        <div className="panel">
          <div className="panel__heading">
            <h2>Package context</h2>
            <span>Keep artifact review tied to package posture</span>
          </div>
          <div className="signal-grid">
            {workspace.packageSignals.map((signal) => (
              <article key={signal.label} className="signal-card">
                <span>{signal.label}</span>
                <strong>{signal.value}</strong>
                <p>{signal.detail}</p>
              </article>
            ))}
          </div>
          <div className="impact-banner">
            <strong>{workspace.diffNarrative.impactLabel}</strong>
            <span>{workspace.diffNarrative.headline}</span>
          </div>
        </div>
      </section>

      <section className="surface-grid surface-grid--split">
        <BehaviorFlow
          behaviors={workspace.rawBinary.behaviors}
          binaryName={workspace.binary.filename}
        />
        <CallGraph
          imports={workspace.binary.imports}
          callTargets={workspace.binary.imports.slice(0, 8)}
          binaryName={workspace.binary.filename}
          functionCount={workspace.rawBinary.functionCount}
        />
      </section>

      <section className="surface-grid surface-grid--split">
        <div className="panel">
          <div className="panel__heading">
            <h2>Findings</h2>
            <span>{workspace.binary.findings.length} surfaced for this artifact</span>
          </div>
          {workspace.binary.findings.length ? (
            <div className="finding-list">
              {workspace.binary.findings.map((finding) => (
                <div key={finding.title} className="finding-row">
                  <h3>{finding.title}</h3>
                  <p>{finding.description}</p>
                  <small>{finding.recommendation}</small>
                </div>
              ))}
            </div>
          ) : (
            <p className="empty-state">No findings were surfaced for this artifact beyond behavioral evidence.</p>
          )}
        </div>

        <div className="panel">
          <div className="panel__heading">
            <h2>Reviewer checklist</h2>
            <span>Before approving rollout</span>
          </div>
          <ol className="timeline">
            <li>Validate whether imports align with the package’s expected runtime purpose.</li>
            <li>Review any surfaced strings for outbound domains, command execution, or path access.</li>
            <li>Compare this artifact’s behavior to the package-level drift summary before shipping.</li>
          </ol>
        </div>
      </section>

      <MethodologyPanel currentScore={workspace.binary.riskScore} currentLevel={workspace.binary.riskLevel} />
    </main>
  );
}
