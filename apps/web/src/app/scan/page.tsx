import type { Metadata } from "next";
import Link from "next/link";

import { PageHeader } from "../../components/page-header";
import { PublicScanForm } from "../../components/public-scan-form";

export const metadata: Metadata = {
  title: "Scan a Package — BinShield",
  description:
    "Instantly check any npm package for hidden native binaries, install-script threats, and risk findings — no sign-up required.",
  alternates: {
    canonical: "https://binshield.dev/scan"
  }
};

export default function ScanPage() {
  const apiBase = process.env.NEXT_PUBLIC_BINSHIELD_API_BASE_URL ?? "";

  return (
    <main className="browse-page">
      <PageHeader
        eyebrow="No account required"
        title="Scan a package"
        description="Enter any npm package name and version to get an instant risk verdict — install-script threats, binary behaviour, and top findings."
        actions={
          <Link href="/packages" className="button-link button-link--ghost">
            Browse database
          </Link>
        }
      />

      <section className="surface-grid surface-grid--center">
        <div className="panel panel--wide">
          <div className="panel__heading">
            <h2>Package scanner</h2>
            <span>Public · no API key needed</span>
          </div>
          <PublicScanForm apiBase={apiBase} />
        </div>
      </section>

      <section className="surface-grid surface-grid--split" style={{ marginTop: "var(--gap-xl)" }}>
        <div className="panel">
          <div className="panel__heading">
            <h2>What we check</h2>
          </div>
          <ul className="stack-list">
            <li className="stack-item">
              <strong>Native binaries</strong>
              <p>.node, .so, .dylib, .wasm files decompiled and classified</p>
            </li>
            <li className="stack-item">
              <strong>Install-script behaviour</strong>
              <p>preinstall / postinstall hooks analysed for suspicious commands</p>
            </li>
            <li className="stack-item">
              <strong>AI risk classification</strong>
              <p>Behaviour patterns scored with a deterministic risk engine + Grok</p>
            </li>
          </ul>
        </div>

        <div className="panel">
          <div className="panel__heading">
            <h2>Want continuous monitoring?</h2>
          </div>
          <p style={{ color: "var(--muted)", marginBottom: "var(--gap-md)" }}>
            Connect your GitHub repos, watch specific packages, and get alerted the moment a version you depend on changes risk profile.
          </p>
          <div style={{ display: "flex", gap: "var(--gap-sm)", flexWrap: "wrap" }}>
            <Link href="/auth/signup" className="button-link">
              Create free account
            </Link>
            <Link href="/docs" className="button-link button-link--ghost">
              Read the docs
            </Link>
          </div>
        </div>
      </section>
    </main>
  );
}
