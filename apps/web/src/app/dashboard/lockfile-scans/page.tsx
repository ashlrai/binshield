import type { Metadata } from "next";

import { MetricCard } from "../../../components/metric-card";
import { PageHeader } from "../../../components/page-header";

export const metadata: Metadata = { title: "Lockfile Scanner", description: "Upload a lockfile to scan all native dependencies for supply chain risks." };

const demoScans = [
  { id: "scan_1", filename: "package-lock.json", format: "npm", totalDeps: 847, nativeDeps: 12, riskScore: 34, riskLevel: "medium", status: "complete", date: "2026-03-23" },
  { id: "scan_2", filename: "yarn.lock", format: "yarn-v1", totalDeps: 1203, nativeDeps: 18, riskScore: 52, riskLevel: "medium", status: "complete", date: "2026-03-20" },
  { id: "scan_3", filename: "pnpm-lock.yaml", format: "pnpm", totalDeps: 412, nativeDeps: 6, riskScore: 15, riskLevel: "low", status: "complete", date: "2026-03-18" }
];
const riskClasses: Record<string, string> = { none: "risk-none", low: "risk-low", medium: "risk-medium", high: "risk-high", critical: "risk-critical" };

export default function LockfileScanPage() {
  return (
    <>
      <PageHeader eyebrow="Supply chain" title="Lockfile Scanner" description="Upload a package-lock.json, yarn.lock, or pnpm-lock.yaml to identify all native binary dependencies and assess their risk." />
      <section className="metrics-grid">
        <MetricCard label="Scans run" value={String(demoScans.length)} detail="Lockfiles analyzed" />
        <MetricCard label="Native deps found" value={String(demoScans.reduce((s, d) => s + d.nativeDeps, 0))} detail="Across all scans" tone="warning" />
        <MetricCard label="Avg risk score" value={String(Math.round(demoScans.reduce((s, d) => s + d.riskScore, 0) / demoScans.length))} detail="Aggregate supply chain risk" tone="accent" />
      </section>
      <section className="featured-section">
        <div className="panel__heading"><h2>Upload lockfile</h2><span>Supported: npm, yarn, pnpm</span></div>
        <div className="panel" style={{ padding: "var(--gap-lg)", textAlign: "center" }}>
          <p style={{ marginBottom: "var(--gap-md)", color: "var(--text-muted)" }}>Drag and drop a lockfile or click to browse. Supported formats: package-lock.json, yarn.lock, pnpm-lock.yaml</p>
          <label className="button-link" style={{ cursor: "pointer", display: "inline-block" }}>Select lockfile<input type="file" accept=".json,.lock,.yaml,.yml" style={{ display: "none" }} /></label>
        </div>
      </section>
      <section className="featured-section">
        <div className="panel__heading"><h2>Scan history</h2><span>{demoScans.length} scans</span></div>
        <table className="data-table">
          <thead><tr><th>Filename</th><th>Format</th><th>Total deps</th><th>Native deps</th><th>Risk</th><th>Status</th><th>Date</th></tr></thead>
          <tbody>
            {demoScans.map((s) => (
              <tr key={s.id}>
                <td><strong>{s.filename}</strong></td>
                <td><span className="tag tag-muted">{s.format}</span></td>
                <td>{s.totalDeps}</td>
                <td>{s.nativeDeps}</td>
                <td><span className={`risk-badge ${riskClasses[s.riskLevel]}`}>{s.riskLevel.toUpperCase()} ({s.riskScore})</span></td>
                <td><span className="status-pill status-pill--healthy">{s.status}</span></td>
                <td>{s.date}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </>
  );
}
