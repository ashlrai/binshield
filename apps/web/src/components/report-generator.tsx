"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

import { apiFetch } from "../lib/api-client";

const reportTypes = [
  { id: "soc2", label: "SOC 2 Type II", desc: "Binary supply chain controls evidence for Trust Service Criteria (CC6, CC7, CC8)." },
  { id: "iso27001", label: "ISO 27001", desc: "Asset inventory and vulnerability management documentation (A.8, A.12, A.14, A.18)." },
  { id: "cra", label: "EU CRA", desc: "Software bill of materials and risk assessment for Cyber Resilience Act (Art. 10, 11)." },
  { id: "custom", label: "Custom Report", desc: "Generate a security assessment with your own scope and parameters." }
];

export function ReportGenerator({ orgId }: { orgId: string }) {
  const [generating, setGenerating] = useState<string | null>(null);
  const [result, setResult] = useState<{ type: string; html: string } | null>(null);
  const router = useRouter();

  async function generate(reportType: string) {
    setGenerating(reportType);
    setResult(null);
    try {
      const res = await apiFetch(`/orgs/${orgId}/reports`, {
        method: "POST",
        body: JSON.stringify({ reportType }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.html) {
          setResult({ type: reportType, html: data.html });
          router.refresh();
        }
      }
    } catch { /* ignore */ }
    setGenerating(null);
  }

  if (result) {
    return (
      <div>
        <div style={{ display: "flex", gap: "var(--gap-sm)", marginBottom: "var(--gap-md)" }}>
          <button className="button-link" onClick={() => {
            const blob = new Blob([result.html], { type: "text/html" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `binshield-${result.type}-report.html`;
            a.click();
            URL.revokeObjectURL(url);
          }}>Download HTML</button>
          <button className="button-link" onClick={() => setResult(null)}>Generate another</button>
        </div>
        <p style={{ color: "var(--accent)" }}>Report generated successfully. Click Download to save.</p>
      </div>
    );
  }

  return (
    <div className="browse-grid">
      {reportTypes.map((rt) => (
        <article key={rt.id} className="package-tile package-tile--stacked">
          <div className="package-tile__header"><div><p className="eyebrow">Report template</p><h3>{rt.label}</h3></div></div>
          <p>{rt.desc}</p>
          <div className="package-tile__footer">
            <button className="button-link" type="button" onClick={() => generate(rt.id)} disabled={generating !== null}>
              {generating === rt.id ? "Generating..." : "Generate"}
            </button>
          </div>
        </article>
      ))}
    </div>
  );
}
