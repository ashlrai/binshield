import Link from "next/link";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Open Source Trust — BinShield Use Cases",
  description:
    "Prove published binaries match source code. Build verifiable trust with downstream consumers of your open-source packages using binary-level evidence.",
  alternates: { canonical: "https://binshield.dev/use-cases/open-source-trust" }
};

const trustSignals = [
  {
    name: "Binary-source alignment",
    detail:
      "BinShield decompiles your published .node, .so, and .wasm files and compares the recovered behavior against your source code. High confidence alignment proves the binary wasn't tampered with after compilation."
  },
  {
    name: "Behavioral transparency",
    detail:
      "Every behavior detected in a binary — network calls, filesystem access, crypto operations, process spawning — is documented with evidence. Consumers can verify that your package does exactly what its README says."
  },
  {
    name: "CycloneDX SBOM attestation",
    detail:
      "Generate a machine-readable SBOM that lists every native artifact, its hash, and its classified behavior. Attach it to your release as a verifiable attestation of binary contents."
  },
  {
    name: "Version drift monitoring",
    detail:
      "Track how binary behavior changes across releases. If a new version introduces unexpected network access or obfuscation patterns, BinShield flags it before your users discover it."
  }
];

export default function OpenSourceTrustPage() {
  return (
    <main>
      <div className="surface-grid">
        <div className="page-header">
          <div>
            <p className="eyebrow">Open source trust</p>
            <h1>Prove your binaries are clean</h1>
            <p>
              Open-source maintainers publish compiled native code that millions of developers install without inspection.
              BinShield gives you the tools to prove what your binaries actually do — building trust that source review alone cannot provide.
            </p>
          </div>
          <Link href="/use-cases" className="button-link button-link--ghost">
            All use cases
          </Link>
        </div>
      </div>

      <section className="surface-grid">
        <div className="panel">
          <div className="panel__heading">
            <h2>The problem</h2>
          </div>
          <p>
            When you publish a package with native binaries, your users have no way to verify that the compiled code matches your source.
            Pre-built binaries are opaque — they could contain anything from legitimate optimizations to supply-chain backdoors.
            Tools like npm audit and Snyk only check known CVEs and source patterns. They never look inside the .node file that actually executes on your users' servers.
          </p>
          <p>
            For foundation projects and widely-depended-upon packages, this trust gap is a liability.
            One compromised binary in a popular package like bcrypt, sharp, or sqlite3 could affect millions of downstream applications.
          </p>
        </div>
      </section>

      <section className="surface-grid">
        <div className="panel__heading">
          <h2>How BinShield builds trust</h2>
          <span>{trustSignals.length} trust signals</span>
        </div>
        <div className="browse-grid">
          {trustSignals.map((signal) => (
            <article key={signal.name} className="package-tile package-tile--stacked">
              <div className="package-tile__header">
                <div>
                  <p className="eyebrow">Trust signal</p>
                  <h3>{signal.name}</h3>
                </div>
              </div>
              <p>{signal.detail}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="surface-grid">
        <div className="panel">
          <div className="panel__heading">
            <h2>For maintainers</h2>
          </div>
          <p>
            Add BinShield to your CI pipeline to automatically verify every release.
            The GitHub Action scans your published binaries, generates a behavioral SBOM,
            and can be configured to fail the build if unexpected behaviors appear in your compiled artifacts.
          </p>
          <p>
            Attach the SBOM to your GitHub Release as a transparency attestation.
            Consumers who depend on your package can independently verify what the binary does before upgrading.
          </p>
          <div style={{ marginTop: "var(--gap-md)", display: "flex", gap: "var(--gap-sm)" }}>
            <Link href="/docs/github-action" className="button-link">GitHub Action setup</Link>
            <Link href="/docs/sbom" className="button-link button-link--ghost">SBOM export docs</Link>
          </div>
        </div>
      </section>

      <section className="surface-grid">
        <div className="panel">
          <div className="panel__heading">
            <h2>For consumers</h2>
          </div>
          <p>
            Before adding a native dependency to your project, check its BinShield analysis.
            Review the behavior classification, inspect the decompiled evidence, and verify that
            the binary does only what the package documentation claims.
          </p>
          <div style={{ marginTop: "var(--gap-md)", display: "flex", gap: "var(--gap-sm)" }}>
            <Link href="/packages" className="button-link">Browse analyzed packages</Link>
            <Link href="/advisories" className="button-link button-link--ghost">View advisories</Link>
          </div>
        </div>
      </section>
    </main>
  );
}
