import Link from "next/link";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Compliance Evidence — BinShield Use Cases",
  description:
    "Generate binary-level CycloneDX SBOMs for SOC 2, ISO 27001, EU Cyber Resilience Act, and Biden EO compliance. Audit-ready documentation from BinShield.",
  alternates: { canonical: "https://binshield.dev/use-cases/compliance" }
};

const regulations = [
  {
    name: "EU Cyber Resilience Act",
    detail:
      "Requires machine-readable SBOMs for all products with digital elements sold in the EU. BinShield adds binary-level component detail that source-only tools miss."
  },
  {
    name: "SOC 2 Type II",
    detail:
      "Auditors need evidence that third-party software components are inventoried and risk-assessed. BinShield SBOMs document every native binary and its behavior classification."
  },
  {
    name: "ISO 27001:2022",
    detail:
      "Annex A.8.28 requires secure coding practices including dependency analysis. BinShield extends that analysis to compiled artifacts."
  },
  {
    name: "Biden Executive Order 14028",
    detail:
      "Mandates SBOMs for all software sold to the US federal government. BinShield produces CycloneDX 1.5 output that meets NTIA minimum element requirements — including binaries."
  }
];

export default function ComplianceUseCasePage() {
  return (
    <main>
      <div className="surface-grid">
        <div className="page-header">
          <div>
            <p className="eyebrow">Use case</p>
            <h1>Compliance Evidence</h1>
            <p className="page-copy">
              Generate binary-level SBOMs that satisfy auditors, regulators, and enterprise procurement teams.
            </p>
          </div>
        </div>

        <section className="surface-grid surface-grid--split">
          <div className="panel">
            <div className="panel__heading">
              <h2>The Problem</h2>
            </div>
            <p>
              Auditors need binary-level SBOMs, but current tools only document JavaScript
              dependencies. They cannot tell you what the compiled binaries inside those
              dependencies actually do. When your SOC 2 auditor asks for a software bill of
              materials, the <code>package-lock.json</code> is not enough.
            </p>
          </div>

          <div className="panel">
            <div className="panel__heading">
              <h2>The Solution</h2>
            </div>
            <p>
              BinShield produces CycloneDX 1.5 SBOMs with binary-level component detail, behavior
              classifications, and risk scores. Every native artifact is inventoried, decompiled,
              and classified — giving your compliance team the evidence they need.
            </p>
          </div>
        </section>

        <div className="panel">
          <div className="panel__heading">
            <h2>Regulations Covered</h2>
            <span>Binary-level compliance for modern frameworks</span>
          </div>
          <div className="featured-grid">
            {regulations.map((reg) => (
              <div key={reg.name} className="panel" style={{ background: "var(--card-strong)" }}>
                <div className="panel__heading">
                  <h3>{reg.name}</h3>
                </div>
                <p style={{ fontSize: "0.9rem" }}>{reg.detail}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="panel">
          <div className="panel__heading">
            <h2>Export an SBOM</h2>
            <span>One curl command to audit-ready output</span>
          </div>
          <pre style={{ background: "var(--card-strong)", padding: "1.5rem", borderRadius: "var(--radius-sm)", overflow: "auto", fontSize: "0.85rem", lineHeight: 1.7 }}>
{`# Export a CycloneDX 1.5 SBOM for bcrypt
curl -H "Authorization: Bearer $BINSHIELD_API_KEY" \\
  https://api.binshield.dev/packages/npm/bcrypt/versions/6.0.0/sbom

# Response includes binary-level components:
# {
#   "bomFormat": "CycloneDX",
#   "specVersion": "1.5",
#   "components": [
#     {
#       "type": "library",
#       "name": "bcrypt_lib.node",
#       "purl": "pkg:npm/bcrypt@6.0.0#prebuilds/linux-x64/bcrypt_lib.node",
#       "properties": [
#         { "name": "binshield:risk-score", "value": "52" },
#         { "name": "binshield:behaviors", "value": "crypto,filesystem" }
#       ]
#     }
#   ]
# }`}
          </pre>
        </div>

        <div className="page-header" style={{ textAlign: "center" }}>
          <div>
            <h2>Get audit-ready in minutes</h2>
            <p className="page-copy">
              Free tier includes SBOM exports for public packages. Pro plans add private packages and scheduled exports.
            </p>
            <div style={{ display: "flex", gap: "1rem", justifyContent: "center", marginTop: "1.5rem" }}>
              <Link href="/login" className="button-link">
                Start free trial
              </Link>
              <Link href="/docs/sbom" className="button-link" style={{ background: "transparent", border: "1px solid var(--border)" }}>
                SBOM docs
              </Link>
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}
