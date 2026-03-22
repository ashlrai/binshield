"use client";

import { useState } from "react";

import type { Ecosystem, PackageAnalysis } from "@binshield/analysis-types";

import { ScanProgress } from "./scan-progress";

interface ScanFormProps {
  apiBase: string;
  onComplete?: (result: PackageAnalysis) => void;
}

export function ScanForm({ apiBase, onComplete }: ScanFormProps) {
  const [packageName, setPackageName] = useState("");
  const [version, setVersion] = useState("");
  const [ecosystem] = useState<Ecosystem>("npm");
  const [status, setStatus] = useState<"idle" | "submitting" | "polling" | "complete" | "error">("idle");
  const [jobId, setJobId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<PackageAnalysis | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!packageName.trim()) return;

    setStatus("submitting");
    setError(null);
    setResult(null);

    try {
      const res = await fetch(`${apiBase}/scans/packages`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ecosystem,
          packageName: packageName.trim(),
          version: version.trim() || "latest"
        })
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        setError(body.error ?? `Server error: ${res.status}`);
        setStatus("error");
        return;
      }

      const job = await res.json();

      if (job.status === "complete" && job.result) {
        setResult(job.result);
        setStatus("complete");
        onComplete?.(job.result);
        return;
      }

      setJobId(job.id);
      setStatus("polling");
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
    return (
      <div className="scan-form scan-form--complete">
        <div className="scan-form__result-header">
          <div>
            <p className="eyebrow">Analysis complete</p>
            <h3>
              {result.packageName}@{result.version}
            </h3>
          </div>
          <span className={`risk-badge risk-${result.riskLevel}`}>
            {result.riskLevel.toUpperCase()} ({result.riskScore})
          </span>
        </div>
        <p>{result.summary}</p>
        <div className="scan-form__result-meta">
          <span>{result.binaryCount} {result.binaryCount === 1 ? "binary" : "binaries"}</span>
          <span>Confidence: {result.sourceMatchConfidence}</span>
          <span>Model: {result.aiModel}</span>
        </div>
        <div className="scan-form__actions">
          <a href={`/packages/${result.packageName}?version=${encodeURIComponent(result.version)}`} className="button-link">
            View full analysis
          </a>
          <button onClick={handleReset} className="button-link button-link--ghost" type="button">
            Scan another
          </button>
        </div>
      </div>
    );
  }

  if (status === "polling" && jobId) {
    return (
      <div className="scan-form">
        <ScanProgress
          jobId={jobId}
          apiBase={apiBase}
          onComplete={(data) => {
            setResult(data as PackageAnalysis);
            setStatus("complete");
            onComplete?.(data as PackageAnalysis);
          }}
          onError={(err) => {
            setError(err);
            setStatus("error");
          }}
        />
        <button onClick={handleReset} className="button-link button-link--ghost" type="button">
          Cancel
        </button>
      </div>
    );
  }

  return (
    <form className="scan-form" onSubmit={handleSubmit}>
      <div className="scan-form__fields">
        <div className="scan-form__field scan-form__field--name">
          <label htmlFor="scan-pkg">Package name</label>
          <input
            id="scan-pkg"
            type="text"
            placeholder="e.g. bcrypt, sharp, sqlite3"
            value={packageName}
            onChange={(e) => setPackageName(e.target.value)}
            disabled={status === "submitting"}
          />
        </div>
        <div className="scan-form__field scan-form__field--version">
          <label htmlFor="scan-ver">Version</label>
          <input
            id="scan-ver"
            type="text"
            placeholder="latest"
            value={version}
            onChange={(e) => setVersion(e.target.value)}
            disabled={status === "submitting"}
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
    </form>
  );
}
