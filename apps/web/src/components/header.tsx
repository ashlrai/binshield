import Link from "next/link";

export function Header() {
  return (
    <header className="site-header">
      <Link href="/" className="wordmark">
        BinShield
      </Link>
      <nav>
        <Link href="/packages/bcrypt">Database</Link>
        <Link href="/dashboard">Dashboard</Link>
      </nav>
    </header>
  );
}
