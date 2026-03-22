import Link from "next/link";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "We Decompiled 23 npm Packages — Here's What Their Native Binaries Actually Do",
  description:
    "Every npm install downloads compiled machine code that no security tool checks. We analyzed 23 popular npm packages that ship native binaries and scored their risk.",
  alternates: { canonical: "https://binshield.dev/blog/decompiled-npm-packages" }
};

export default function DecompiledNpmPackagesPost() {
  return (
    <main>
      <div className="surface-grid" style={{ maxWidth: "48rem", margin: "0 auto" }}>
        <div className="page-header">
          <div>
            <p className="eyebrow">Research &middot; 2026-03-21</p>
            <h1>We Decompiled 23 npm Packages — Here{"'"}s What Their Native Binaries Actually Do</h1>
            <p className="page-copy">
              Every <code>npm install</code> downloads compiled machine code that no security tool checks.
            </p>
          </div>
        </div>

        <article className="panel" style={{ lineHeight: 1.8, fontSize: "0.95rem" }}>
          <p>
            When you install <code>bcrypt</code>, you get a pre-compiled <code>.node</code> binary.
            When you install <code>sharp</code>, you get platform-specific shared libraries. These
            binaries execute directly on your servers — but Snyk, Socket, and npm audit only analyze
            JavaScript source code and package metadata.
          </p>
          <p>
            We built BinShield to answer a simple question: <strong>what do these binaries actually do?</strong>
          </p>

          <h2>What We Found</h2>
          <p>
            We analyzed 23 of the most popular npm packages that ship native binaries, running each
            through our AI-powered decompilation pipeline. Here are the results:
          </p>

          <h3 style={{ color: "var(--danger)" }}>High Risk: usb@2.14.0</h3>
          <p>
            <strong>Risk Score: 68/100 (HIGH)</strong> — 12 native binaries detected
          </p>
          <p>
            The <code>usb</code> package ships 12 compiled binaries across platforms. Our analysis
            flagged network-capable symbols, process spawning indicators, and filesystem access
            patterns that go beyond expected USB device communication. This doesn{"'"}t mean it{"'"}s
            malicious — but it means your CI pipeline should be aware of what it{"'"}s doing.
          </p>

          <h3 style={{ color: "var(--warning)" }}>Medium Risk Packages</h3>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", margin: "1rem 0" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid var(--border)", textAlign: "left" }}>
                  <th style={{ padding: "0.5rem 0.75rem" }}>Package</th>
                  <th style={{ padding: "0.5rem 0.75rem" }}>Binaries</th>
                  <th style={{ padding: "0.5rem 0.75rem" }}>Risk Score</th>
                  <th style={{ padding: "0.5rem 0.75rem" }}>Key Behaviors</th>
                </tr>
              </thead>
              <tbody>
                {[
                  { pkg: "node-screenshots@0.2.8", bins: 1, score: 58, behaviors: "Screen capture, process access" },
                  { pkg: "ffi-napi@4.0.3", bins: 15, score: 56, behaviors: "Foreign function interface, arbitrary native calls" },
                  { pkg: "bcrypt@6.0.0", bins: 10, score: 52, behaviors: "Crypto operations, filesystem (expected)" },
                  { pkg: "argon2@0.44.0", bins: 11, score: 51, behaviors: "Memory-hard hashing, entropy access" },
                  { pkg: "fsevents@2.3.3", bins: 1, score: 45, behaviors: "macOS filesystem monitoring" },
                  { pkg: "utf-8-validate@6.0.5", bins: 5, score: 43, behaviors: "WebSocket validation" },
                  { pkg: "sodium-native@5.1.0", bins: 10, score: 42, behaviors: "Libsodium crypto bindings" },
                  { pkg: "bufferutil@4.0.9", bins: 4, score: 38, behaviors: "WebSocket buffer operations" },
                ].map((row) => (
                  <tr key={row.pkg} style={{ borderBottom: "1px solid var(--border)" }}>
                    <td style={{ padding: "0.5rem 0.75rem", fontFamily: "var(--font-mono)", fontSize: "0.85rem" }}>{row.pkg}</td>
                    <td style={{ padding: "0.5rem 0.75rem" }}>{row.bins}</td>
                    <td style={{ padding: "0.5rem 0.75rem", color: "var(--warning)" }}>{row.score}</td>
                    <td style={{ padding: "0.5rem 0.75rem" }}>{row.behaviors}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <h3 style={{ color: "var(--accent)" }}>Low Risk</h3>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", margin: "1rem 0" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid var(--border)", textAlign: "left" }}>
                  <th style={{ padding: "0.5rem 0.75rem" }}>Package</th>
                  <th style={{ padding: "0.5rem 0.75rem" }}>Risk Score</th>
                  <th style={{ padding: "0.5rem 0.75rem" }}>Notes</th>
                </tr>
              </thead>
              <tbody>
                <tr style={{ borderBottom: "1px solid var(--border)" }}>
                  <td style={{ padding: "0.5rem 0.75rem", fontFamily: "var(--font-mono)", fontSize: "0.85rem" }}>node-sass@9.0.0</td>
                  <td style={{ padding: "0.5rem 0.75rem", color: "var(--accent)" }}>7</td>
                  <td style={{ padding: "0.5rem 0.75rem" }}>LibSass binding, minimal surface</td>
                </tr>
              </tbody>
            </table>
          </div>

          <h2>Key Insight: Most Risk Is Expected — But You Should Know</h2>
          <p>
            The majority of these packages do exactly what they claim. <code>bcrypt</code> does
            password hashing. <code>sharp</code> does image processing. The risk scores reflect the{" "}
            <em>attack surface</em> of the binary, not malicious intent.
          </p>
          <p>
            But here{"'"}s the problem: <strong>you have zero visibility into this today.</strong> If
            a package maintainer{"'"}s build pipeline was compromised and a backdoor was injected into
            the compiled binary, no existing tool would catch it. The JavaScript source could look
            clean while the binary exfiltrates data.
          </p>

          <h2>How BinShield Works</h2>
          <ol className="timeline">
            <li><strong>Download</strong> — We fetch the actual platform-specific binaries that <code>npm install</code> downloads.</li>
            <li><strong>Extract</strong> — We identify every <code>.node</code>, <code>.so</code>, <code>.dylib</code>, and <code>.wasm</code> file in the package.</li>
            <li><strong>Classify</strong> — Our AI analyzes each binary for: network calls, filesystem access, process spawning, crypto operations, obfuscation, and data exfiltration patterns.</li>
            <li><strong>Score</strong> — A deterministic risk engine produces a 0-100 score based on findings and behaviors.</li>
            <li><strong>Report</strong> — Results are available via web UI, API, GitHub Action, and CycloneDX SBOM export.</li>
          </ol>

          <h2>Try It Now</h2>
          <ul style={{ listStyle: "none", padding: 0 }}>
            <li style={{ margin: "0.5rem 0" }}>
              <Link href="/" style={{ color: "var(--accent)" }}>Browse the database</Link> — Search and explore analyzed packages.
            </li>
            <li style={{ margin: "0.5rem 0" }}>
              <Link href="/use-cases/ci-cd" style={{ color: "var(--accent)" }}>Add to your CI</Link> — Install the BinShield GitHub Action.
            </li>
            <li style={{ margin: "0.5rem 0" }}>
              <strong>Export SBOMs</strong> — <code style={{ fontSize: "0.85rem" }}>curl https://api.binshield.dev/packages/npm/bcrypt/versions/6.0.0/sbom</code>
            </li>
          </ul>

          <h2>Why This Matters for Compliance</h2>
          <p>
            The EU Cyber Resilience Act and Biden{"'"}s Executive Order on Cybersecurity both require
            machine-readable SBOMs from software suppliers. But current SBOM tools only document
            JavaScript dependencies — they can{"'"}t tell you what the compiled binaries inside those
            dependencies actually do.
          </p>
          <p>
            BinShield produces CycloneDX 1.5 SBOMs with binary-level component detail, behavior
            classifications, and risk scores. This is the evidence your auditors are asking for.
          </p>

          <hr style={{ border: "none", borderTop: "1px solid var(--border)", margin: "2rem 0" }} />

          <p style={{ color: "var(--muted)", fontStyle: "italic" }}>
            BinShield is built by Ashlr AI. We{"'"}re offering free Pro trials to the first 20 teams
            that sign up.{" "}
            <Link href="/login" style={{ color: "var(--accent)" }}>
              Get started at binshield.dev
            </Link>
          </p>
        </article>
      </div>
    </main>
  );
}
