import Link from "next/link";

const linkColumns = [
  {
    heading: "Product",
    links: [
      { label: "Database", href: "/packages" },
      { label: "GitHub Action", href: "/docs" },
      { label: "Pricing", href: "/pricing" },
      { label: "Docs", href: "/docs" }
    ]
  },
  {
    heading: "Company",
    links: [
      { label: "About", href: "https://ashlr.ai" },
      { label: "Blog", href: "/blog" },
      { label: "Contact", href: "mailto:mason@ashlr.ai" }
    ]
  },
  {
    heading: "Legal",
    links: [
      { label: "Privacy", href: "/privacy" },
      { label: "Terms", href: "/terms" }
    ]
  }
];

export function Footer() {
  return (
    <footer className="site-footer">
      <div className="site-footer__inner">
        <div className="site-footer__brand">
          <span className="wordmark" style={{ fontSize: "0.88rem" }}>
            <span className="wordmark__icon">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </span>
            BinShield
          </span>
          <p className="site-footer__attribution">
            Built by{" "}
            <a href="https://ashlr.ai" style={{ color: "var(--accent)" }}>
              Ashlr AI
            </a>
          </p>
        </div>

        <nav className="site-footer__columns">
          {linkColumns.map((col) => (
            <div key={col.heading} className="site-footer__column">
              <p className="site-footer__column-heading">{col.heading}</p>
              <ul>
                {col.links.map((link) => (
                  <li key={link.label}>
                    <Link href={link.href}>{link.label}</Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>
      </div>

      <div className="site-footer__bottom">
        <p>&copy; {new Date().getFullYear()} Ashlr AI (Evero LLC). All rights reserved.</p>
      </div>
    </footer>
  );
}
