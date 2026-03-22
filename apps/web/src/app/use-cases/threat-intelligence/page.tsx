import Link from "next/link";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Threat Intelligence — BinShield Use Cases",
  description:
    "Monitor npm packages for behavioral changes in compiled code. Get version diff alerts and watchlist notifications when binaries change unexpectedly.",
  alternates: { canonical: "https://binshield.dev/use-cases/threat-intelligence" }
};

export default function ThreatIntelUseCasePage() {
  return (
    <main>
      <div className="surface-grid">
        <div className="page-header">
          <div>
            <p className="eyebrow">Use case</p>
            <h1>Threat Intelligence</h1>
            <p className="page-copy">
              Monitor npm packages for behavioral changes in compiled code and catch threats early.
            </p>
          </div>
        </div>

        <section className="surface-grid surface-grid--split">
          <div className="panel">
            <div className="panel__heading">
              <h2>The Problem</h2>
            </div>
            <p>
              Package updates can silently change binary behavior. A maintainer account takeover, a
              compromised build pipeline, or even a well-intentioned refactor can introduce network
              calls, process spawning, or data exfiltration into compiled code — and no existing
              tool will notice.
            </p>
          </div>

          <div className="panel">
            <div className="panel__heading">
              <h2>The Solution</h2>
            </div>
            <p>
              BinShield tracks binary behavior across versions and alerts you when something
              changes. Set up watchlists for critical packages, configure risk thresholds, and
              receive email or webhook notifications the moment a new version introduces unexpected
              behavior.
            </p>
          </div>
        </section>

        <div className="panel">
          <div className="panel__heading">
            <h2>How Risk Scoring Works</h2>
            <span>Deterministic, transparent, auditable</span>
          </div>
          <ol className="timeline">
            <li>
              <strong>Binary extraction</strong> — Every <code>.node</code>, <code>.so</code>,{" "}
              <code>.dylib</code>, and <code>.wasm</code> file is identified and isolated from the
              package tarball.
            </li>
            <li>
              <strong>Decompilation</strong> — Ghidra decompiles each binary and extracts symbol
              tables, imported functions, string literals, and control flow graphs.
            </li>
            <li>
              <strong>AI classification</strong> — An LLM analyzes the decompiled output and
              classifies behaviors into families: network, filesystem, process, crypto, obfuscation,
              and data exfiltration.
            </li>
            <li>
              <strong>Deterministic scoring</strong> — A rules engine produces a 0-100 risk score
              based on the number, severity, and combination of detected behaviors. The same binary
              always gets the same score.
            </li>
            <li>
              <strong>Version diffing</strong> — When a new version is scanned, BinShield compares
              the behavior profile against the previous version and flags any changes.
            </li>
          </ol>
        </div>

        <div className="panel">
          <div className="panel__heading">
            <h2>Real Example: bcrypt 5.1.0 to 6.0.0</h2>
            <span>Behavioral diff between versions</span>
          </div>
          <div style={{ background: "var(--card-strong)", padding: "1.5rem", borderRadius: "var(--radius-sm)", fontSize: "0.9rem", lineHeight: 1.8 }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid var(--border)", textAlign: "left" }}>
                  <th style={{ padding: "0.4rem 0.75rem" }}>Attribute</th>
                  <th style={{ padding: "0.4rem 0.75rem" }}>v5.1.0</th>
                  <th style={{ padding: "0.4rem 0.75rem" }}>v6.0.0</th>
                </tr>
              </thead>
              <tbody>
                <tr style={{ borderBottom: "1px solid var(--border)" }}>
                  <td style={{ padding: "0.4rem 0.75rem" }}>Native binaries</td>
                  <td style={{ padding: "0.4rem 0.75rem" }}>8</td>
                  <td style={{ padding: "0.4rem 0.75rem" }}>10</td>
                </tr>
                <tr style={{ borderBottom: "1px solid var(--border)" }}>
                  <td style={{ padding: "0.4rem 0.75rem" }}>Risk score</td>
                  <td style={{ padding: "0.4rem 0.75rem", color: "var(--warning)" }}>48</td>
                  <td style={{ padding: "0.4rem 0.75rem", color: "var(--warning)" }}>52</td>
                </tr>
                <tr style={{ borderBottom: "1px solid var(--border)" }}>
                  <td style={{ padding: "0.4rem 0.75rem" }}>New behaviors</td>
                  <td style={{ padding: "0.4rem 0.75rem" }}>—</td>
                  <td style={{ padding: "0.4rem 0.75rem", color: "var(--accent-strong)" }}>+filesystem write</td>
                </tr>
                <tr style={{ borderBottom: "1px solid var(--border)" }}>
                  <td style={{ padding: "0.4rem 0.75rem" }}>Removed behaviors</td>
                  <td style={{ padding: "0.4rem 0.75rem" }}>—</td>
                  <td style={{ padding: "0.4rem 0.75rem" }}>none</td>
                </tr>
                <tr>
                  <td style={{ padding: "0.4rem 0.75rem" }}>Platform coverage</td>
                  <td style={{ padding: "0.4rem 0.75rem" }}>linux-x64, darwin-x64</td>
                  <td style={{ padding: "0.4rem 0.75rem" }}>+linux-arm64, +darwin-arm64</td>
                </tr>
              </tbody>
            </table>
            <p style={{ marginTop: "1rem", color: "var(--muted)", fontSize: "0.85rem" }}>
              The jump from 8 to 10 binaries reflects new ARM64 prebuild targets. The new filesystem
              write behavior comes from an updated temp-file strategy in the hashing routine. Both
              changes are expected — but without BinShield, your team would never know they happened.
            </p>
          </div>
        </div>

        <div className="page-header" style={{ textAlign: "center" }}>
          <div>
            <h2>Start monitoring your dependencies</h2>
            <p className="page-copy">
              Create watchlists for your critical packages and get notified when binary behavior changes.
            </p>
            <div style={{ display: "flex", gap: "1rem", justifyContent: "center", marginTop: "1.5rem" }}>
              <Link href="/login" className="button-link">
                Get started
              </Link>
              <Link href="/dashboard/watchlists" className="button-link" style={{ background: "transparent", border: "1px solid var(--border)" }}>
                Watchlist docs
              </Link>
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}
