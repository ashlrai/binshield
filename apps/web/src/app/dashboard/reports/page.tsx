import type { Metadata } from "next";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { MetricCard } from "../../../components/metric-card";
import { PageHeader } from "../../../components/page-header";
import { ReportGenerator } from "../../../components/report-generator";
import { getComplianceReports } from "../../../lib/site-data";
import { createServerClient, getOrgContext } from "../../../lib/supabase";

export const metadata: Metadata = { title: "Compliance Reports", description: "Generate audit-ready security reports for SOC 2, ISO 27001, and EU CRA compliance." };

export default async function ReportsPage() {
  const cookieStore = await cookies();
  const supabase = createServerClient(cookieStore);
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const orgCtx = await getOrgContext(user.id);
  const reports = await getComplianceReports(orgCtx?.orgId);
  const orgId = orgCtx?.orgId ?? "";

  return (
    <>
      <PageHeader eyebrow="Compliance" title="Security Reports" description="Generate audit-ready compliance reports with binary-level evidence for SOC 2, ISO 27001, and EU Cyber Resilience Act." />
      <section className="metrics-grid">
        <MetricCard label="Reports generated" value={String(reports.length)} detail="Compliance documents" />
        <MetricCard label="Avg compliance" value={reports.length ? String(Math.round(reports.reduce((s, r) => s + (r.status === "complete" ? 85 : 50), 0) / reports.length)) : "0"} detail="Score out of 100" tone="accent" />
        <MetricCard label="Frameworks" value="3" detail="SOC 2, ISO 27001, EU CRA" tone="warning" />
      </section>
      <section className="featured-section">
        <div className="panel__heading"><h2>Generate report</h2><span>Select a framework</span></div>
        <ReportGenerator orgId={orgId} />
      </section>
      <section className="featured-section">
        <div className="panel__heading"><h2>Report history</h2><span>{reports.length} reports</span></div>
        <table className="data-table">
          <thead><tr><th>Title</th><th>Framework</th><th>Status</th><th>Generated</th></tr></thead>
          <tbody>
            {reports.map((r) => (
              <tr key={r.id}>
                <td><strong>{r.title}</strong></td>
                <td><span className="tag tag--review">{r.reportType}</span></td>
                <td><span className={`status-pill status-pill--${r.status === "complete" ? "healthy" : "watch"}`}>{r.status}</span></td>
                <td>{new Date(r.generatedAt).toLocaleDateString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </>
  );
}
