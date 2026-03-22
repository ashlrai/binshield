import Link from "next/link";

import { getDataMode } from "../lib/site-data";

export async function Header() {
  const mode = await getDataMode();

  return (
    <header className="site-header">
      <div className="site-header__brand">
        <Link href="/" className="wordmark">
          <span className="wordmark__icon" aria-hidden="true">
            <svg width="22" height="22" viewBox="0 0 22 22" fill="none">
              <rect x="1" y="1" width="20" height="20" rx="4" stroke="currentColor" strokeWidth="1.5" />
              <path d="M6 7h4v3H6zM12 7h4v3h-4zM6 12h4v3H6zM12 12h4v3h-4z" fill="currentColor" opacity="0.6" />
              <circle cx="11" cy="11" r="2" fill="currentColor" />
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
        <Link href="/search" className="nav-link">Search</Link>
        <Link href="/dashboard" className="nav-link">Dashboard</Link>
        <Link href="/login" className="nav-link nav-link--cta">Sign in</Link>
      </nav>
    </header>
  );
}
