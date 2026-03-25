import Link from "next/link";

export default function NotFound() {
  return (
    <main style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", minHeight: "60vh", textAlign: "center", padding: "var(--gap-lg)" }}>
      <p className="eyebrow" style={{ marginBottom: "var(--gap-sm)" }}>404</p>
      <h1 style={{ fontSize: "2rem", marginBottom: "var(--gap-md)" }}>Page not found</h1>
      <p style={{ color: "var(--muted)", maxWidth: "420px", marginBottom: "var(--gap-lg)" }}>
        The page you are looking for does not exist or has been moved.
      </p>
      <div style={{ display: "flex", gap: "var(--gap-sm)" }}>
        <Link href="/" className="button-link">Home</Link>
        <Link href="/packages" className="button-link button-link--ghost">Browse packages</Link>
      </div>
    </main>
  );
}
