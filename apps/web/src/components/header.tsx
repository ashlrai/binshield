import Link from "next/link";

import { getDataMode } from "../lib/site-data";

export async function Header() {
  const mode = await getDataMode();

  return (
    <header className="site-header">
      <div className="site-header__brand">
        <Link href="/" className="wordmark">
          <span className="wordmark__icon" aria-hidden="true">
            <svg width="28" height="28" viewBox="0 0 32 32" fill="none">
              <rect x="2" y="2" width="28" height="28" rx="5" stroke="currentColor" strokeWidth="1.5" />
              <rect x="7" y="7" width="7" height="5" rx="1.5" fill="currentColor" opacity="0.5" />
              <rect x="18" y="7" width="7" height="5" rx="1.5" fill="currentColor" opacity="0.5" />
              <rect x="7" y="15" width="7" height="5" rx="1.5" fill="currentColor" opacity="0.5" />
              <rect x="18" y="15" width="7" height="5" rx="1.5" fill="currentColor" opacity="0.5" />
              <circle cx="16" cy="16" r="4" fill="currentColor" />
              <path d="M16 13v6M13 16h6" stroke="#050d18" strokeWidth="1.5" strokeLinecap="round" />
              <rect x="7" y="23" width="18" height="2" rx="1" fill="currentColor" opacity="0.3" />
            </svg>
          </span>
          BinShield
        </Link>
        <span className={`status-indicator status-indicator--${mode === "live" ? "live" : "demo"}`}>
          <span className="status-indicator__dot" />
          {mode === "live" ? "Live" : "Demo"}
        </span>
      </div>
      <nav className="site-header__nav">
        <Link href="/packages" className="nav-link">Database</Link>
        <Link href="/advisories" className="nav-link">Advisories</Link>
        <Link href="/feed" className="nav-link">Feed</Link>
        <Link href="/pricing" className="nav-link">Pricing</Link>
        <Link href="/docs" className="nav-link">Docs</Link>
        <Link href="/login" className="nav-link nav-link--cta">Get started</Link>
      </nav>
    </header>
  );
}
