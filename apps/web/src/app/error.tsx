"use client";

export default function ErrorPage({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <main style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", minHeight: "60vh", textAlign: "center", padding: "var(--gap-lg)" }}>
      <p className="eyebrow" style={{ marginBottom: "var(--gap-sm)" }}>Error</p>
      <h1 style={{ fontSize: "2rem", marginBottom: "var(--gap-md)" }}>Something went wrong</h1>
      <p style={{ color: "var(--muted)", maxWidth: "420px", marginBottom: "var(--gap-lg)" }}>
        {error.message || "An unexpected error occurred. Please try again."}
      </p>
      <div style={{ display: "flex", gap: "var(--gap-sm)" }}>
        <button className="button-link" onClick={reset} type="button">Try again</button>
        <a href="/" className="button-link button-link--ghost">Home</a>
      </div>
    </main>
  );
}
