import type { Metadata } from "next";

import { MetricCard } from "../../../components/metric-card";
import { PageHeader } from "../../../components/page-header";

export const metadata: Metadata = { title: "Compliance Reports", description: "Generate audit-ready security reports for SOC 2, ISO 27001, and EU CRA compliance." };

const reportTypes = [
  { id: "soc2", label: "SOC 2 Type II", desc: "Binary supply chain controls evidence for Trust Service Criteria (CC6, CC7, CC8)." },
  { id: "iso27001", label: "ISO 27001", desc: "Asset inventory and vulnerability management documentation (A.8, A.12, A.14, A.18)." },
  { id: "cra", label: "EU CRA", desc: "Software bill of materials and risk assessment for Cyber Resilience Act (Art. 10, 11)." },
  { id: "custom", label: "Custom Report", desc: "Generate a security assessment with your own scope and parameters." }
];
const demoReports = [
  { id: "rpt_1", type: "soc2", title: "SOC 2 Q1 2026 — Binary Supply Chain", status: "ready", date: "2026-03-20", pkgs: 23, score: 87 },
  { id: "rpt_2", type: "iso27001", title: "ISO 27001 Asset Inventory — Native Deps", status: "ready", date: "2026-03-15", pkgs: 18, score: 92 },
  { id: "rpt_3", type: "cra", title: "EU CRA SBOM Assessment — Production", status: "ready", date: "2026-03-10", pkgs: 31, score: 79 }
];

export default function ReportsPage() {
  return (
    <>
      <PageHeader eyebrow="Compliance" title="Security Reports" description="Generate audit-ready compliance reports with binary-level evidence for SOC 2, ISO 27001, and EU Cyber Resilience Act." />
      <section className="metrics-grid">
        <MetricCard label="Reports generated" value={String(demoReports.length)} detail="Compliance documents" />
        <MetricCard label="Avg compliance" value={String(Math.round(demoReports.reduce((s, r) => s + r.score, 0) / demoReports.length))} detail="Score out of 100" tone="accent" />
        <MetricCard label="Frameworks" value="3" detail="SOC 2, ISO 27001, EU CRA" tone="warning" />
      </section>
      <section className="featured-section">
        <div className="panel__heading"><h2>Generate report</h2><span>Select a framework</span></div>
        <div className="browse-grid">
          {reportTypes.map((rt) => (
            <article key={rt.id} className="package-tile package-tile--stacked">
              <div className="package-tile__header"><div><p className="eyebrow">Report template</p><h3>{rt.label}</h3></div></div>
              <p>{rt.desc}</p>
              <div className="package-tile__footer"><button className="button-link" type="button">Generate</button></div>
            </article>
          ))}
        </div>
      </section>
      <section className="featured-section">
        <div className="panel__heading"><h2>Report history</h2><span>{demoReports.length} reports</span></div>
        <table className="data-table">
          <thead><tr><th>Title</th><th>Framework</th><th>Packages</th><th>Score</th><th>Status</th><th>Generated</th></tr></thead>
          <tbody>
            {demoReports.map((r) => (
              <tr key={r.id}>
                <td><strong>{r.title}</strong></td>
                <td><span className="tag tag--review">{r.type.toUpperCase()}</span></td>
                <td>{r.pkgs}</td>
                <td><span className={`risk-badge ${r.score >= 80 ? "risk-low" : r.score >= 50 ? "risk-medium" : "risk-high"}`}>{r.score}/100</span></td>
                <td><span className="status-pill status-pill--healthy">{r.status}</span></td>
                <td>{r.date}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </>
  );
}
