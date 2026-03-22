import Link from "next/link";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "About BinShield",
  description:
    "Ashlr AI builds BinShield — binary-level supply-chain security for the open-source ecosystem.",
  alternates: { canonical: "https://binshield.dev/about" }
};

export default function AboutPage() {
  return (
    <main>
      <div className="surface-grid">
        <div className="page-header">
          <div>
            <p className="eyebrow">Company</p>
            <h1>About BinShield</h1>
            <p className="page-copy">
              We believe developers deserve visibility into the compiled code their dependencies execute.
            </p>
          </div>
        </div>

        {/* Mission */}
        <div className="panel" style={{ display: "grid", gap: "24px" }}>
          <div className="panel__heading">
            <h2>Our Mission</h2>
          </div>
          <p style={{ margin: 0, color: "var(--muted)", lineHeight: 1.7 }}>
            BinShield is built by <strong>Ashlr AI</strong> with a single goal: give every developer and
            security team deep visibility into the native binaries hidden inside open-source packages.
            We believe developers deserve to know exactly what compiled code their dependencies execute —
            not just the JavaScript or Python source, but the .node addons, shared libraries, and
            pre-built binaries that run with full system access.
          </p>
        </div>

        {/* The Problem */}
        <div className="panel" style={{ display: "grid", gap: "24px" }}>
          <div className="panel__heading">
            <h2>The Problem</h2>
          </div>
          <p style={{ margin: 0, color: "var(--muted)", lineHeight: 1.7 }}>
            99.8% of npm malware that achieves real-world impact uses compiled native components —
            pre-built binaries, native addons, or compiled extensions that bypass source-level analysis.
            Traditional security scanners read source code. They parse JavaScript, match CVE databases,
            and flag known-bad patterns. But none of them look inside the <code>.node</code> files,
            the <code>.so</code> libraries, or the pre-built executables bundled in packages.
          </p>
          <p style={{ margin: 0, color: "var(--muted)", lineHeight: 1.7 }}>
            This blind spot is massive. Packages like <code>bcrypt</code>, <code>sharp</code>,
            and <code>sqlite3</code> ship native binaries that make network calls, access the filesystem,
            and link against system libraries — and until BinShield, no tool checked what was inside them.
          </p>
        </div>

        {/* Team */}
        <div className="panel" style={{ display: "grid", gap: "24px" }}>
          <div className="panel__heading">
            <h2>Team</h2>
          </div>
          <p style={{ margin: 0, color: "var(--muted)", lineHeight: 1.7 }}>
            BinShield is founded and built by <strong>Mason Wyatt</strong>. We are focused on
            making binary-level supply-chain security accessible to every development team.
          </p>
        </div>

        {/* Contact & Links */}
        <div className="panel" style={{ display: "grid", gap: "24px" }}>
          <div className="panel__heading">
            <h2>Contact</h2>
          </div>
          <div style={{ display: "grid", gap: "12px" }}>
            <p style={{ margin: 0, color: "var(--muted)" }}>
              Email: <a href="mailto:mason@ashlr.ai" style={{ color: "var(--accent)" }}>mason@ashlr.ai</a>
            </p>
            <p style={{ margin: 0, color: "var(--muted)" }}>
              GitHub:{" "}
              <a
                href="https://github.com/ashlrai"
                target="_blank"
                rel="noopener noreferrer"
                style={{ color: "var(--accent)" }}
              >
                github.com/ashlrai
              </a>
            </p>
            <p style={{ margin: 0, color: "var(--muted)" }}>
              Documentation:{" "}
              <Link href="/docs" style={{ color: "var(--accent)" }}>
                binshield.dev/docs
              </Link>
            </p>
          </div>
        </div>
      </div>
    </main>
  );
}
