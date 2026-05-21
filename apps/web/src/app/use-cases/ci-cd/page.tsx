import Link from "next/link";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "CI/CD Gatekeeper — BinShield Use Cases",
  description:
    "Block risky native binaries in pull requests with the BinShield GitHub Action. Automated binary scanning and policy enforcement for your CI/CD pipeline.",
  alternates: { canonical: "https://binshield.dev/use-cases/ci-cd" }
};

export default function CiCdUseCasePage() {
  return (
    <main>
      <div className="surface-grid">
        <div className="page-header">
          <div>
            <p className="eyebrow">Use case</p>
            <h1>CI/CD Gatekeeper</h1>
            <p className="page-copy">
              Block risky native binaries in pull requests before they reach production.
            </p>
          </div>
        </div>

        <section className="surface-grid surface-grid--split">
          <div className="panel">
            <div className="panel__heading">
              <h2>The Problem</h2>
            </div>
            <p>
              No CI tool checks native binaries. Your pipeline scans JavaScript source code, runs
              SAST tools, and checks known CVE databases — but the compiled <code>.node</code>,{" "}
              <code>.so</code>, and <code>.dylib</code> files inside your dependencies are completely
              invisible. A compromised build pipeline could inject a backdoor into a binary, and your
              CI would give it a green checkmark.
            </p>
          </div>

          <div className="panel">
            <div className="panel__heading">
              <h2>The Solution</h2>
            </div>
            <p>
              The BinShield GitHub Action adds binary-level scanning to every pull request. It
              decompiles native artifacts, classifies their behavior with AI, and enforces
              configurable risk thresholds — all in a single YAML step.
            </p>
          </div>
        </section>

        <div className="panel">
          <div className="panel__heading">
            <h2>How It Works</h2>
            <span>Three steps to binary-aware CI</span>
          </div>
          <ol className="timeline">
            <li>
              <strong>Add the Action</strong> — Drop the BinShield step into your GitHub Actions
              workflow. It runs after <code>npm install</code> and before your test suite.
            </li>
            <li>
              <strong>Set your policy</strong> — Configure a risk threshold (e.g., block PRs with
              any binary scoring above 60). Customize which behavior families trigger failures.
            </li>
            <li>
              <strong>Review and merge</strong> — BinShield posts a PR comment with a summary of
              every native binary, its risk score, and detected behaviors. Safe PRs pass
              automatically.
            </li>
          </ol>
        </div>

        <div className="panel">
          <div className="panel__heading">
            <h2>GitHub Action Configuration</h2>
            <span>Example workflow step</span>
          </div>
          <pre style={{ background: "var(--card-strong)", padding: "1.5rem", borderRadius: "var(--radius-sm)", overflow: "auto", fontSize: "0.85rem", lineHeight: 1.7 }}>
{`# .github/workflows/binshield.yml
name: BinShield Binary Scan

on:
  pull_request:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npm ci

      - name: BinShield Scan
        uses: ashlrai/binshield/apps/github-action@v1
        with:
          api-key: \${{ secrets.BINSHIELD_API_KEY }}
          risk-threshold: 60
          fail-on-high: true
          comment-on-pr: true`}
          </pre>
        </div>

        <div className="panel">
          <div className="panel__heading">
            <h2>Example PR Comment</h2>
            <span>What your team sees on every pull request</span>
          </div>
          <div style={{ background: "var(--card-strong)", padding: "1.5rem", borderRadius: "var(--radius-sm)", fontSize: "0.9rem", lineHeight: 1.8 }}>
            <p style={{ fontWeight: 600, marginBottom: "0.5rem" }}>BinShield Scan Results</p>
            <p>Scanned <strong>3 packages</strong> with native binaries. <strong>1 flagged.</strong></p>
            <table style={{ width: "100%", borderCollapse: "collapse", marginTop: "0.75rem" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid var(--border)", textAlign: "left" }}>
                  <th style={{ padding: "0.4rem 0.75rem" }}>Package</th>
                  <th style={{ padding: "0.4rem 0.75rem" }}>Risk</th>
                  <th style={{ padding: "0.4rem 0.75rem" }}>Behaviors</th>
                </tr>
              </thead>
              <tbody>
                <tr style={{ borderBottom: "1px solid var(--border)" }}>
                  <td style={{ padding: "0.4rem 0.75rem" }}>bcrypt@6.0.0</td>
                  <td style={{ padding: "0.4rem 0.75rem", color: "var(--warning)" }}>52 MEDIUM</td>
                  <td style={{ padding: "0.4rem 0.75rem" }}>crypto, filesystem</td>
                </tr>
                <tr style={{ borderBottom: "1px solid var(--border)" }}>
                  <td style={{ padding: "0.4rem 0.75rem" }}>sharp@0.33.2</td>
                  <td style={{ padding: "0.4rem 0.75rem", color: "var(--accent)" }}>28 LOW</td>
                  <td style={{ padding: "0.4rem 0.75rem" }}>image processing</td>
                </tr>
                <tr>
                  <td style={{ padding: "0.4rem 0.75rem" }}>usb@2.14.0</td>
                  <td style={{ padding: "0.4rem 0.75rem", color: "var(--danger)" }}>68 HIGH</td>
                  <td style={{ padding: "0.4rem 0.75rem" }}>network, process spawn</td>
                </tr>
              </tbody>
            </table>
            <p style={{ marginTop: "0.75rem", color: "var(--danger)" }}>
              Blocked: usb@2.14.0 exceeds risk threshold of 60.
            </p>
          </div>
        </div>

        <div className="page-header" style={{ textAlign: "center" }}>
          <div>
            <h2>Start scanning binaries in CI today</h2>
            <p className="page-copy">
              Free for public repos. Pro plans include private repo scanning and custom policies.
            </p>
            <div style={{ display: "flex", gap: "1rem", justifyContent: "center", marginTop: "1.5rem" }}>
              <Link href="/login" className="button-link">
                Get started
              </Link>
              <Link href="/docs/github-action" className="button-link" style={{ background: "transparent", border: "1px solid var(--border)" }}>
                Read the docs
              </Link>
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}
