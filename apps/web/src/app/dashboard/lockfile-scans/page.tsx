import type { Metadata } from "next";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { LockfileUpload } from "../../../components/lockfile-upload";
import { MetricCard } from "../../../components/metric-card";
import { PageHeader } from "../../../components/page-header";
import { getLockfileScans } from "../../../lib/site-data";
import { createServerClient, getOrgContext } from "../../../lib/supabase";

export const metadata: Metadata = { title: "Lockfile Scanner", description: "Upload a lockfile to scan all native dependencies for supply chain risks." };

const riskClasses: Record<string, string> = { none: "risk-none", low: "risk-low", medium: "risk-medium", high: "risk-high", critical: "risk-critical" };

export default async function LockfileScanPage() {
  const cookieStore = await cookies();
  const supabase = createServerClient(cookieStore);
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const orgCtx = await getOrgContext(user.id);
  const scans = await getLockfileScans(orgCtx?.orgId);

  return (
    <>
      <PageHeader eyebrow="Supply chain" title="Lockfile Scanner" description="Upload a package-lock.json, yarn.lock, or pnpm-lock.yaml to identify all native binary dependencies and assess their risk." />
      <section className="metrics-grid">
        <MetricCard label="Scans run" value={String(scans.length)} detail="Lockfiles analyzed" />
        <MetricCard label="Native deps found" value={String(scans.reduce((s, d) => s + d.nativeDeps, 0))} detail="Across all scans" tone="warning" />
        <MetricCard label="Avg risk score" value={scans.length ? String(Math.round(scans.reduce((s, d) => s + d.riskScore, 0) / scans.length)) : "0"} detail="Aggregate supply chain risk" tone="accent" />
      </section>
      <section className="featured-section">
        <div className="panel__heading"><h2>Upload lockfile</h2><span>Supported: npm, yarn, pnpm</span></div>
        <LockfileUpload apiBase={process.env.BINSHIELD_API_BASE_URL ?? process.env.NEXT_PUBLIC_BINSHIELD_API_BASE_URL ?? ""} />
      </section>
      <section className="featured-section">
        <div className="panel__heading"><h2>Scan history</h2><span>{scans.length} scans</span></div>
        <table className="data-table">
          <thead><tr><th>Filename</th><th>Format</th><th>Total deps</th><th>Native deps</th><th>Risk</th><th>Status</th><th>Date</th></tr></thead>
          <tbody>
            {scans.map((s) => (
              <tr key={s.id}>
                <td><strong>{s.filename}</strong></td>
                <td><span className="tag tag-muted">{s.format}</span></td>
                <td>{s.totalDeps}</td>
                <td>{s.nativeDeps}</td>
                <td><span className={`risk-badge ${riskClasses[s.riskLevel]}`}>{s.riskLevel.toUpperCase()} ({s.riskScore})</span></td>
                <td><span className={`status-pill status-pill--${s.status === "complete" ? "healthy" : "watch"}`}>{s.status}</span></td>
                <td>{new Date(s.scannedAt).toLocaleDateString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </>
  );
}
