import Link from "next/link";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Blog — BinShield",
  description:
    "Research, analysis, and product updates from the BinShield team. Binary supply-chain security insights.",
  alternates: { canonical: "https://binshield.dev/blog" }
};

const posts = [
  {
    title: "We Decompiled 23 npm Packages — Here's What Their Native Binaries Actually Do",
    href: "/blog/decompiled-npm-packages",
    date: "2026-03-21",
    summary:
      "Every npm install downloads compiled machine code that no security tool checks. We analyzed 23 of the most popular npm packages that ship native binaries and scored their risk.",
    tag: "Research"
  }
];

export default function BlogPage() {
  return (
    <main>
      <div className="surface-grid">
        <div className="page-header">
          <div>
            <p className="eyebrow">Insights</p>
            <h1>Blog</h1>
            <p className="page-copy">
              Research, analysis, and product updates from the BinShield team.
            </p>
          </div>
        </div>

        <div className="featured-grid">
          {posts.map((post) => (
            <Link key={post.href} href={post.href} className="panel" style={{ textDecoration: "none" }}>
              <div className="panel__heading">
                <h2>{post.title}</h2>
                <span className="tag tag--review">{post.tag}</span>
              </div>
              <p>{post.summary}</p>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "auto" }}>
                <span style={{ color: "var(--muted)", fontSize: "0.85rem" }}>{post.date}</span>
                <span className="button-link">Read post</span>
              </div>
            </Link>
          ))}
        </div>
      </div>
    </main>
  );
}
