import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "GitHub Action",
  description:
    "BinShield GitHub Action — scan native binaries on every pull request with configurable risk thresholds and PR comments.",
  alternates: { canonical: "https://binshield.dev/docs/github-action" }
};

const quickStartYaml = `name: Binary Dependency Check
on: [pull_request]

jobs:
  binshield:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ashlrai/binshield-action@v1
        with:
          fail-on: high
          github-token: \${{ secrets.GITHUB_TOKEN }}`;

const inputsTable = [
  { input: "api-base-url", description: "BinShield API URL", default: "https://binshieldapi-production.up.railway.app" },
  { input: "api-key", description: "API key for authenticated scans", default: "-" },
  { input: "github-token", description: "Token for PR comments", default: "-" },
  { input: "working-directory", description: "Repo path to inspect", default: "." },
  { input: "scan-mode", description: "native-only or all-dependencies", default: "native-only" },
  { input: "fail-on", description: "Risk threshold: critical, high, medium, low, never", default: "high" },
  { input: "comment-mode", description: "summary, pr-comment, both, off", default: "summary" },
  { input: "include-dev-dependencies", description: "Scan devDependencies too", default: "false" },
  { input: "poll-interval-ms", description: "Polling delay in ms", default: "1500" },
  { input: "timeout-ms", description: "Polling timeout in ms", default: "120000" },
  { input: "max-targets", description: "Max packages to scan", default: "50" }
];

const riskLevels = [
  { level: "none", score: "0", meaning: "No binaries or behaviors detected" },
  { level: "low", score: "1-29", meaning: "Expected behaviors only" },
  { level: "medium", score: "30-59", meaning: "Review-worthy behaviors present" },
  { level: "high", score: "60-79", meaning: "Multiple risk signals, manual review required" },
  { level: "critical", score: "80-100", meaning: "Severe indicators, block until validated" }
];

const examplePrComment = `## BinShield -- Binary Dependency Scan

3 native binaries found in 2 packages

| Package        | Risk     | Evidence                    |
|----------------|----------|-----------------------------|
| bcrypt@6.0.0   | MEDIUM   | 10 binaries, crypto, fs     |
| sharp@0.34.5   | LOW      | 1 binary, filesystem        |

All binaries passed the HIGH threshold.`;

export default function GitHubActionPage() {
  return (
    <main>
      <div className="surface-grid">
        <div className="page-header">
          <div>
            <p className="eyebrow">CI/CD</p>
            <h1>GitHub Action</h1>
            <p className="page-copy">
              Drop a single YAML step into your workflow to scan native binaries on every pull request.
            </p>
          </div>
        </div>

        {/* Quick Start */}
        <div className="panel" style={{ display: "grid", gap: "16px" }}>
          <div className="panel__heading">
            <h2>Quick Start</h2>
            <span>Add to your workflow file</span>
          </div>
          <pre
            style={{
              margin: 0,
              padding: "16px",
              borderRadius: "var(--radius-sm)",
              background: "var(--card-strong)",
              border: "1px solid var(--border)",
              overflowX: "auto",
              fontSize: "0.85rem",
              lineHeight: 1.6
            }}
          >
            <code>{quickStartYaml}</code>
          </pre>
        </div>

        {/* Inputs */}
        <div className="panel" style={{ display: "grid", gap: "16px" }}>
          <div className="panel__heading">
            <h2>Inputs</h2>
            <span>All action inputs and their defaults</span>
          </div>
          <div style={{ overflowX: "auto" }}>
            <table
              style={{
                width: "100%",
                borderCollapse: "collapse",
                fontSize: "0.88rem"
              }}
            >
              <thead>
                <tr style={{ borderBottom: "1px solid var(--border)" }}>
                  <th style={{ textAlign: "left", padding: "10px 12px", color: "var(--accent)" }}>Input</th>
                  <th style={{ textAlign: "left", padding: "10px 12px", color: "var(--accent)" }}>Description</th>
                  <th style={{ textAlign: "left", padding: "10px 12px", color: "var(--accent)" }}>Default</th>
                </tr>
              </thead>
              <tbody>
                {inputsTable.map((row) => (
                  <tr key={row.input} style={{ borderBottom: "1px solid var(--border)" }}>
                    <td style={{ padding: "10px 12px", fontFamily: "var(--font-mono)", fontSize: "0.82rem" }}>
                      {row.input}
                    </td>
                    <td style={{ padding: "10px 12px", color: "var(--muted)" }}>{row.description}</td>
                    <td style={{ padding: "10px 12px", fontFamily: "var(--font-mono)", fontSize: "0.82rem" }}>
                      {row.default}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Scan Modes */}
        <div className="panel" style={{ display: "grid", gap: "16px" }}>
          <div className="panel__heading">
            <h2>Scan Modes</h2>
          </div>
          <div style={{ display: "grid", gap: "12px" }}>
            <div>
              <h3 style={{ margin: "0 0 4px", fontFamily: "var(--font-mono)", fontSize: "0.9rem" }}>
                <span className="tag tag--review">native-only</span>{" "}
                <span style={{ color: "var(--muted)", fontSize: "0.82rem" }}>default</span>
              </h3>
              <p style={{ margin: 0, color: "var(--muted)" }}>
                Only scan packages identified as native binary candidates. Fast, focused on the highest-risk
                dependencies.
              </p>
            </div>
            <div>
              <h3 style={{ margin: "0 0 4px", fontFamily: "var(--font-mono)", fontSize: "0.9rem" }}>
                <span className="tag tag--review">all-dependencies</span>
              </h3>
              <p style={{ margin: 0, color: "var(--muted)" }}>
                Scan every dependency in the lockfile. Use for compliance audits where full coverage is required.
              </p>
            </div>
          </div>
        </div>

        {/* Risk Levels */}
        <div className="panel" style={{ display: "grid", gap: "16px" }}>
          <div className="panel__heading">
            <h2>Risk Levels</h2>
            <span>How BinShield classifies binary behavior risk</span>
          </div>
          <div style={{ overflowX: "auto" }}>
            <table
              style={{
                width: "100%",
                borderCollapse: "collapse",
                fontSize: "0.88rem"
              }}
            >
              <thead>
                <tr style={{ borderBottom: "1px solid var(--border)" }}>
                  <th style={{ textAlign: "left", padding: "10px 12px", color: "var(--accent)" }}>Level</th>
                  <th style={{ textAlign: "left", padding: "10px 12px", color: "var(--accent)" }}>Score</th>
                  <th style={{ textAlign: "left", padding: "10px 12px", color: "var(--accent)" }}>Meaning</th>
                </tr>
              </thead>
              <tbody>
                {riskLevels.map((row) => (
                  <tr key={row.level} style={{ borderBottom: "1px solid var(--border)" }}>
                    <td style={{ padding: "10px 12px", fontFamily: "var(--font-mono)", fontSize: "0.82rem" }}>
                      {row.level}
                    </td>
                    <td style={{ padding: "10px 12px" }}>{row.score}</td>
                    <td style={{ padding: "10px 12px", color: "var(--muted)" }}>{row.meaning}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Example PR Comment */}
        <div className="panel" style={{ display: "grid", gap: "16px" }}>
          <div className="panel__heading">
            <h2>Example PR Comment</h2>
            <span>What your team sees on each pull request</span>
          </div>
          <pre
            style={{
              margin: 0,
              padding: "16px",
              borderRadius: "var(--radius-sm)",
              background: "var(--card-strong)",
              border: "1px solid var(--border)",
              overflowX: "auto",
              fontSize: "0.85rem",
              lineHeight: 1.6
            }}
          >
            <code>{examplePrComment}</code>
          </pre>
        </div>
      </div>
    </main>
  );
}
