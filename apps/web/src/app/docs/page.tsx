import Link from "next/link";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Documentation",
  description:
    "BinShield documentation hub — API reference, GitHub Action guide, integration patterns, and SBOM export.",
  alternates: { canonical: "https://binshield.dev/docs" }
};

const sections = [
  {
    title: "API Reference",
    href: "/docs/api",
    description:
      "Explore every public endpoint — packages, scans, organizations, and billing — with example curl commands and response shapes."
  },
  {
    title: "GitHub Action Guide",
    href: "/docs/github-action",
    description:
      "Drop a single YAML step into your workflow to scan native binaries on every pull request. Configurable risk thresholds, PR comments, and SBOM output."
  },
  {
    title: "Integration Guide",
    href: "/docs/integration",
    description:
      "End-to-end recipes for JavaScript, Python, and CI/CD pipelines — from package search to watchlist alerting."
  },
  {
    title: "SBOM Export",
    href: "/docs/sbom",
    description:
      "Generate CycloneDX 1.5 software bills of materials with binary-level detail for compliance and audit workflows."
  }
];

export default function DocsPage() {
  return (
    <main>
      <div className="surface-grid">
        <div className="page-header">
          <div>
            <p className="eyebrow">Developer resources</p>
            <h1>Documentation</h1>
            <p className="page-copy">
              Everything you need to integrate BinShield into your supply-chain security workflow.
            </p>
          </div>
        </div>

        <div className="featured-grid">
          {sections.map((section) => (
            <Link key={section.href} href={section.href} className="panel" style={{ textDecoration: "none" }}>
              <div className="panel__heading">
                <h2>{section.title}</h2>
              </div>
              <p>{section.description}</p>
              <span className="button-link" style={{ marginTop: "auto", alignSelf: "flex-start" }}>
                View docs
              </span>
            </Link>
          ))}
        </div>
      </div>
    </main>
  );
}
