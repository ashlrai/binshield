import Link from "next/link";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Use Cases — BinShield",
  description:
    "Discover how BinShield protects your software supply chain — from CI/CD gating and compliance SBOMs to threat intelligence and open-source trust.",
  alternates: { canonical: "https://binshield.dev/use-cases" }
};

const useCases = [
  {
    title: "CI/CD Gatekeeper",
    href: "/use-cases/ci-cd",
    audience: "DevSecOps engineers, platform teams",
    benefit: "Automated policy enforcement",
    description:
      "Block risky native binaries in pull requests. Add a single GitHub Action step to scan every dependency's compiled code before it reaches production."
  },
  {
    title: "Compliance Evidence",
    href: "/use-cases/compliance",
    audience: "Security teams, CISOs, compliance officers",
    benefit: "Audit-ready documentation",
    description:
      "Generate binary-level SBOMs for SOC 2, ISO 27001, and the EU Cyber Resilience Act. Give auditors the evidence they actually need."
  },
  {
    title: "Threat Intelligence",
    href: "/use-cases/threat-intelligence",
    audience: "Security researchers, SOC teams",
    benefit: "Early threat detection",
    description:
      "Monitor npm packages for behavioral changes in compiled code. Get alerted when a version update silently changes what a binary does."
  },
  {
    title: "Open Source Trust",
    href: "/use-cases/open-source-trust",
    audience: "Package maintainers, foundation projects",
    benefit: "Supply chain transparency",
    description:
      "Prove published binaries match source code. Build verifiable trust with downstream consumers of your open-source packages."
  }
];

export default function UseCasesPage() {
  return (
    <main>
      <div className="surface-grid">
        <div className="page-header">
          <div>
            <p className="eyebrow">Solutions</p>
            <h1>Use Cases</h1>
            <p className="page-copy">
              BinShield gives your team binary-level visibility across every stage of the software supply chain.
            </p>
          </div>
        </div>

        <div className="featured-grid">
          {useCases.map((uc) => (
            <Link key={uc.href} href={uc.href} className="panel" style={{ textDecoration: "none" }}>
              <div className="panel__heading">
                <h2>{uc.title}</h2>
                <span className="tag tag--review">{uc.benefit}</span>
              </div>
              <p>{uc.description}</p>
              <p style={{ color: "var(--muted)", fontSize: "0.85rem" }}>
                For: {uc.audience}
              </p>
              <span className="button-link" style={{ marginTop: "auto", alignSelf: "flex-start" }}>
                Learn more
              </span>
            </Link>
          ))}
        </div>
      </div>
    </main>
  );
}
