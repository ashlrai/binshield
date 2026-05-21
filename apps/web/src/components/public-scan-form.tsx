"use client";

import { useState } from "react";
import Link from "next/link";

import type { Ecosystem, PackageAnalysis } from "@binshield/analysis-types";

type ScanStatus = "idle" | "submitting" | "polling" | "complete" | "error";

interface PublicScanFormProps {
  apiBase: string;
}

function getRiskClass(level: string) {
  return `risk-badge risk-${level}`;
}

export function PublicScanForm({ apiBase }: PublicScanFormProps) {
  const [packageName, setPackageName] = useState("");
  const [version, setVersion] = useState("");
  const [status, setStatus] = useState<ScanStatus>("idle");
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<PackageAnalysis | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);

  const base = apiBase.replace(/\/$/, "");

  async function pollJob(id: string) {
    const maxAttempts = 30;
    let attempts = 0;

    async function tick() {
      if (attempts >= maxAttempts) {
        setError("Analysis is taking longer than expected. Try refreshing or check back later.");
        setStatus("error");
        return;
      }
      attempts++;

      try {
        const res = await fetch(`${base}/public/scan`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          // Re-submit the same job to check existing results — in practice the
          // worker will complete and return 200 on the next poll.
          body: JSON.stringify({
            ecosystem: "npm" as Ecosystem,
            packageName,
            version: version.trim() || "latest"
          })
        });
        if (res.ok) {
          const job = await res.json();
          if (job.status === "complete" && job.result) {
            setResult(job.result as PackageAnalysis);
            setStatus("complete");
            return;
          }
        }
      } catch {
        // ignore transient errors during polling
      }

      // Fall back: poll the public read endpoint directly
      try {
        const v = version.trim() || "latest";
        const checkRes = await fetch(`${base}/packages/npm/${encodeURIComponent(packageName)}/versions/${encodeURIComponent(v)}`, {
          headers: { accept: "application/json" }
        });
        if (checkRes.ok) {
          const analysis = await checkRes.json() as PackageAnalysis;
          setResult(analysis);
          setStatus("complete");
          return;
        }
      } catch {
        // keep polling
      }

      setTimeout(tick, 3000);
    }

    void tick();
    void id; // suppress unused-var lint
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!packageName.trim()) return;

    setStatus("submitting");
    setError(null);
    setResult(null);
    setJobId(null);

    if (!base) {
      setError("API is not configured. Browse the public database instead.");
      setStatus("error");
      return;
    }

    try {
      const res = await fetch(`${base}/public/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ecosystem: "npm" as Ecosystem,
          packageName: packageName.trim(),
          version: version.trim() || "latest"
        })
      });

      if (res.status === 429) {
        setError("Too many requests. Please wait a moment and try again.");
        setStatus("error");
        return;
      }

      if (!res.ok) {
        const body = await res.json().catch(() => ({})) as { error?: string };
        setError(body.error ?? `Server error: ${res.status}`);
        setStatus("error");
        return;
      }

      const job = await res.json() as { id: string; status: string; result?: PackageAnalysis };

      if (job.status === "complete" && job.result) {
        setResult(job.result);
        setStatus("complete");
        return;
      }

      setJobId(job.id);
      setStatus("polling");
      pollJob(job.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Network error");
      setStatus("error");
    }
  }

  function handleReset() {
    setStatus("idle");
    setJobId(null);
    setError(null);
    setResult(null);
    setPackageName("");
    setVersion("");
  }

  if (status === "complete" && result) {
    // Top findings come from binaries (PackageAnalysis has no top-level findings field)
    const topFindings = result.binaries.flatMap((b) => b.findings).slice(0, 5);
    const manifest = result.manifestAnalysis;
    const installHooks = manifest ? Object.keys(manifest.lifecycleHooks) : [];

    return (
      <div className="scan-form scan-form--complete">
        <div className="scan-form__result-header">
          <div>
            <p className="eyebrow">Analysis complete</p>
            <h3>
              {result.packageName}@{result.version}
            </h3>
          </div>
          <span className={getRiskClass(result.riskLevel)}>
            {result.riskLevel.toUpperCase()} ({result.riskScore})
          </span>
        </div>

        <p style={{ color: "var(--muted)", margin: "var(--gap-sm) 0" }}>{result.summary}</p>

        <dl className="detail-grid-list" style={{ marginBottom: "var(--gap-md)" }}>
          <div>
            <dt>Binaries</dt>
            <dd>{result.binaryCount}</dd>
          </div>
          <div>
            <dt>Confidence</dt>
            <dd>{result.sourceMatchConfidence}</dd>
          </div>
          <div>
            <dt>Ecosystem</dt>
            <dd>{result.ecosystem}</dd>
          </div>
        </dl>

        {installHooks.length > 0 && (
          <div style={{ marginBottom: "var(--gap-md)" }}>
            <p className="eyebrow">Install-script hooks</p>
            <div className="tag-list">
              {installHooks.map((hook: string) => (
                <span key={hook} className="tag tag--warning">{hook}</span>
              ))}
            </div>
          </div>
        )}

        {topFindings.length > 0 && (
          <div style={{ marginBottom: "var(--gap-md)" }}>
            <p className="eyebrow">Top findings</p>
            <ul className="stack-list">
              {topFindings.map((f, i: number) => (
                <li key={i} className="stack-item">
                  <strong>{f.title}</strong>
                  <p>{f.description}</p>
                  <span className={`status-pill status-pill--${f.severity === "critical" || f.severity === "high" ? "alert" : "review"}`}>
                    {f.severity}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}

        <div className="scan-form__actions">
          <Link href={`/packages/${encodeURIComponent(result.packageName)}?version=${encodeURIComponent(result.version)}`} className="button-link">
            Full analysis
          </Link>
          <Link href="/auth/signup" className="button-link button-link--ghost">
            Monitor this package
          </Link>
          <button onClick={handleReset} className="button-link button-link--ghost" type="button">
            Scan another
          </button>
        </div>
      </div>
    );
  }

  if (status === "polling") {
    return (
      <div className="scan-form">
        <p className="eyebrow" style={{ textAlign: "center", margin: "var(--gap-lg) 0" }}>
          Analysis queued — checking results...
        </p>
        <p style={{ color: "var(--muted)", textAlign: "center", fontSize: "0.88rem" }}>
          This can take up to 60 seconds for new packages.
        </p>
        <div style={{ textAlign: "center", marginTop: "var(--gap-md)" }}>
          <button onClick={handleReset} className="button-link button-link--ghost" type="button">
            Cancel
          </button>
        </div>
        <p style={{ display: "none" }}>{jobId}</p>
      </div>
    );
  }

  return (
    <form className="scan-form" onSubmit={handleSubmit}>
      <div className="scan-form__fields">
        <div className="scan-form__field scan-form__field--name">
          <label htmlFor="pub-scan-pkg">Package name</label>
          <input
            id="pub-scan-pkg"
            type="text"
            placeholder="e.g. bcrypt, sharp, sqlite3"
            value={packageName}
            onChange={(e) => setPackageName(e.target.value)}
            disabled={status === "submitting"}
            autoComplete="off"
          />
        </div>
        <div className="scan-form__field scan-form__field--version">
          <label htmlFor="pub-scan-ver">Version</label>
          <input
            id="pub-scan-ver"
            type="text"
            placeholder="latest"
            value={version}
            onChange={(e) => setVersion(e.target.value)}
            disabled={status === "submitting"}
            autoComplete="off"
          />
        </div>
        <button
          type="submit"
          className="button-link"
          disabled={status === "submitting" || !packageName.trim()}
        >
          {status === "submitting" ? "Submitting..." : "Scan package"}
        </button>
      </div>
      {error && <p className="scan-form__error">{error}</p>}
      <p style={{ color: "var(--muted)", fontSize: "0.82rem", marginTop: "var(--gap-sm)" }}>
        No API key required. Rate-limited to 10 scans per minute per IP.
      </p>
    </form>
  );
}
