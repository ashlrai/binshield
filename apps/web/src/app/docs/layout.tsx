import Link from "next/link";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Documentation",
  description:
    "BinShield documentation — API reference, GitHub Action guide, integration patterns, and SBOM export."
};

const sidebarItems = [
  { href: "/docs", label: "Overview" },
  { href: "/docs/api", label: "API Reference" },
  { href: "/docs/github-action", label: "GitHub Action" },
  { href: "/docs/integration", label: "Integration Guide" },
  { href: "/docs/sbom", label: "SBOM Export" }
];

export default function DocsLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="dashboard-layout">
      <aside className="dashboard-sidebar">
        <div className="dashboard-sidebar__hero">
          <p className="eyebrow">Reference</p>
          <h1>Documentation</h1>
          <p>Guides, API reference, and integration patterns for BinShield.</p>
        </div>

        <nav className="dashboard-nav">
          {sidebarItems.map((item) => (
            <Link key={item.href} href={item.href} className="dashboard-nav__link">
              {item.label}
            </Link>
          ))}
        </nav>
      </aside>

      <section className="dashboard-content">{children}</section>
    </div>
  );
}
