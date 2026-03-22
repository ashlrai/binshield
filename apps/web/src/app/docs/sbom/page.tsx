import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "SBOM Export",
  description:
    "Generate CycloneDX 1.5 software bills of materials with binary-level detail for compliance and audit workflows.",
  alternates: { canonical: "https://binshield.dev/docs/sbom" }
};

const API = "https://binshieldapi-production.up.railway.app";

const codeStyle = {
  margin: 0,
  padding: "14px 16px",
  borderRadius: "var(--radius-sm)",
  background: "var(--card-strong)",
  border: "1px solid var(--border)",
  overflowX: "auto" as const,
  fontSize: "0.85rem",
  lineHeight: 1.5
};

export default function SbomExportPage() {
  return (
    <main>
      <div className="surface-grid">
        <div className="page-header">
          <div>
            <p className="eyebrow">Guide</p>
            <h1>SBOM Export</h1>
            <p className="page-copy">
              Generate CycloneDX 1.5 software bills of materials with binary-level detail for compliance and audit workflows.
            </p>
          </div>
        </div>

        {/* What is CycloneDX? */}
        <div className="panel" style={{ display: "grid", gap: "24px" }}>
          <div className="panel__heading">
            <h2>What is CycloneDX?</h2>
          </div>
          <p style={{ margin: 0, color: "var(--muted)" }}>
            CycloneDX is an OWASP-standardized format for software bills of materials (SBOMs). It provides a
            machine-readable inventory of every component in a software artifact — including libraries, frameworks,
            and compiled native binaries. BinShield produces CycloneDX 1.5 documents enriched with binary-level
            metadata: detected symbols, linked libraries, compiler toolchains, and risk assessments that traditional
            SBOM generators cannot capture.
          </p>
        </div>

        {/* How to export */}
        <div className="panel" style={{ display: "grid", gap: "24px" }}>
          <div className="panel__heading">
            <h2>How to Export</h2>
          </div>

          <div style={{ display: "grid", gap: "16px" }}>
            <p style={{ margin: 0, color: "var(--muted)" }}>
              Request an SBOM for any analyzed package version via the <code>/sbom</code> endpoint:
            </p>
            <pre style={codeStyle}>
              <code>{`curl -s \\
  "${API}/packages/npm/bcrypt/versions/6.0.0/sbom" \\
  | jq .`}</code>
            </pre>
          </div>

          <div style={{ display: "grid", gap: "16px" }}>
            <p style={{ margin: 0, color: "var(--muted)" }}>
              Save directly to a file for audit records:
            </p>
            <pre style={codeStyle}>
              <code>{`curl -s \\
  "${API}/packages/npm/bcrypt/versions/6.0.0/sbom" \\
  -o bcrypt-6.0.0-sbom.json`}</code>
            </pre>
          </div>

          <div style={{ display: "grid", gap: "16px" }}>
            <p style={{ margin: 0, color: "var(--muted)" }}>
              The endpoint pattern is:
            </p>
            <pre style={codeStyle}>
              <code>{`GET /packages/:ecosystem/:name/versions/:version/sbom`}</code>
            </pre>
          </div>
        </div>

        {/* Response format */}
        <div className="panel" style={{ display: "grid", gap: "24px" }}>
          <div className="panel__heading">
            <h2>Response Format</h2>
          </div>
          <p style={{ margin: 0, color: "var(--muted)" }}>
            The response is a CycloneDX 1.5 JSON document. Here is the structure of a typical response:
          </p>
          <pre style={codeStyle}>
            <code>{`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "timestamp": "2026-03-20T12:00:00Z",
    "tools": [
      {
        "vendor": "BinShield",
        "name": "binshield-api",
        "version": "1.0.0"
      }
    ],
    "component": {
      "type": "library",
      "name": "bcrypt",
      "version": "6.0.0",
      "purl": "pkg:npm/bcrypt@6.0.0"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "bcrypt_lib.node",
      "version": "6.0.0",
      "description": "Native N-API addon — bcrypt binding",
      "properties": [
        { "name": "binshield:binary:format", "value": "ELF x86_64" },
        { "name": "binshield:binary:compiler", "value": "GCC 12.2" },
        { "name": "binshield:risk:level", "value": "low" },
        { "name": "binshield:risk:score", "value": "12" }
      ]
    },
    {
      "type": "library",
      "name": "libcrypto.so.3",
      "version": "3.0.9",
      "description": "OpenSSL cryptographic library (linked)",
      "properties": [
        { "name": "binshield:linkage", "value": "dynamic" }
      ]
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:npm/bcrypt@6.0.0",
      "dependsOn": [
        "bcrypt_lib.node",
        "libcrypto.so.3"
      ]
    }
  ]
}`}</code>
          </pre>
        </div>

        {/* Integration with compliance tools */}
        <div className="panel" style={{ display: "grid", gap: "24px" }}>
          <div className="panel__heading">
            <h2>Integration with Compliance Tools</h2>
          </div>

          <div style={{ display: "grid", gap: "16px" }}>
            <p style={{ margin: 0, color: "var(--muted)" }}>
              CycloneDX SBOMs from BinShield are compatible with the broader compliance ecosystem. Common integrations include:
            </p>
            <ul style={{ margin: 0, paddingLeft: "20px", color: "var(--muted)", display: "grid", gap: "8px" }}>
              <li><strong>Dependency-Track</strong> -- Import SBOMs into OWASP Dependency-Track for continuous vulnerability monitoring and policy enforcement.</li>
              <li><strong>Grype / Trivy</strong> -- Feed SBOMs into vulnerability scanners for CVE matching against binary components.</li>
              <li><strong>SOC 2 / ISO 27001 audits</strong> -- Attach SBOMs as evidence artifacts demonstrating supply-chain visibility.</li>
              <li><strong>NTIA minimum elements</strong> -- BinShield SBOMs satisfy NTIA minimum element requirements including supplier, component name, version, dependency relationships, and timestamp.</li>
            </ul>
          </div>

          <div style={{ display: "grid", gap: "16px" }}>
            <h3 style={{ margin: 0 }}>Example: Import into Dependency-Track</h3>
            <pre style={codeStyle}>
              <code>{`# Export SBOM and upload to Dependency-Track
curl -s "${API}/packages/npm/bcrypt/versions/6.0.0/sbom" \\
  -o bcrypt-sbom.json

curl -X POST "https://your-dtrack-instance/api/v1/bom" \\
  -H "X-Api-Key: \$DTRACK_API_KEY" \\
  -H "Content-Type: multipart/form-data" \\
  -F "project=<project-uuid>" \\
  -F "bom=@bcrypt-sbom.json"`}</code>
            </pre>
          </div>
        </div>
      </div>
    </main>
  );
}
