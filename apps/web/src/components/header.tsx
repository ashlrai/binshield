import Link from "next/link";

import { getDataMode } from "../lib/site-data";

export function Header() {
  const mode = getDataMode();

  return (
    <header className="site-header">
      <div className="site-header__brand">
        <Link href="/" className="wordmark">
          BinShield
        </Link>
        <span className={`status-pill status-pill--${mode === "live" ? "healthy" : "watch"}`}>
          {mode === "live" ? "Connected" : "Demo fallback"}
        </span>
      </div>
      <nav className="site-header__nav">
        <Link href="/packages">Database</Link>
        <Link href="/search">Search</Link>
        <Link href="/dashboard">Dashboard</Link>
        <Link href="/dashboard/watchlists">Watchlists</Link>
        <Link href="/dashboard/billing">Billing</Link>
        <Link href="/dashboard/settings">Settings</Link>
      </nav>
    </header>
  );
}
