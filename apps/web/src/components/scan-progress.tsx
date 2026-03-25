"use client";

import { useState, useEffect, useCallback } from "react";

import { apiFetch } from "../lib/api-client";

export type ScanStage = "queued" | "ingest" | "extract" | "decompile" | "classify" | "persist" | "complete" | "failed";

interface ScanProgressProps {
  jobId: string;
  apiBase?: string;
  onComplete?: (result: unknown) => void;
  onError?: (error: string) => void;
}

const stages: ScanStage[] = ["queued", "ingest", "extract", "decompile", "classify", "persist", "complete"];

const stageLabels: Record<ScanStage, string> = {
  queued: "Queued",
  ingest: "Downloading package",
  extract: "Extracting binaries",
  decompile: "Decompiling with Ghidra",
  classify: "Classifying with AI",
  persist: "Storing results",
  complete: "Analysis complete",
  failed: "Analysis failed"
};

function stageIndex(stage: ScanStage): number {
  const idx = stages.indexOf(stage);
  return idx === -1 ? 0 : idx;
}

export function ScanProgress({ jobId, apiBase = "", onComplete, onError }: ScanProgressProps) {
  const [currentStage, setCurrentStage] = useState<ScanStage>("queued");
  const [error, setError] = useState<string | null>(null);
  const [elapsedMs, setElapsedMs] = useState(0);

  const poll = useCallback(async () => {
    try {
      const res = await apiFetch(`/scans/${jobId}`);
      if (!res.ok) {
        setError(`Server error: ${res.status}`);
        onError?.(`Server error: ${res.status}`);
        return true;
      }
      const data = await res.json();
      const stage = (data.stage ?? data.status ?? "queued") as ScanStage;
      setCurrentStage(stage);

      if (stage === "complete") {
        onComplete?.(data.result);
        return true;
      }
      if (stage === "failed") {
        setError(data.error ?? "Analysis failed");
        onError?.(data.error ?? "Analysis failed");
        return true;
      }
      return false;
    } catch {
      return false;
    }
  }, [jobId, apiBase, onComplete, onError]);

  useEffect(() => {
    let cancelled = false;
    const startTime = Date.now();

    const interval = setInterval(async () => {
      if (cancelled) return;
      setElapsedMs(Date.now() - startTime);
      const done = await poll();
      if (done) clearInterval(interval);
    }, 2000);

    poll();

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [poll]);

  const progress = stageIndex(currentStage);
  const pct = (progress / (stages.length - 1)) * 100;
  const elapsed = (elapsedMs / 1000).toFixed(0);

  return (
    <div className={`scan-progress ${error ? "scan-progress--error" : ""}`}>
      <div className="scan-progress__header">
        <span className="scan-progress__label">
          {error ? "Failed" : stageLabels[currentStage]}
        </span>
        <span className="scan-progress__time">{elapsed}s</span>
      </div>

      <div className="scan-progress__bar">
        <div
          className={`scan-progress__fill ${error ? "scan-progress__fill--error" : ""}`}
          style={{ width: `${error ? 100 : pct}%` }}
        />
      </div>

      <div className="scan-progress__stages">
        {stages.map((stage, i) => (
          <span
            key={stage}
            className={`scan-progress__stage ${
              i < progress
                ? "scan-progress__stage--done"
                : i === progress
                  ? "scan-progress__stage--active"
                  : "scan-progress__stage--pending"
            }`}
          >
            {stageLabels[stage].split(" ")[0]}
          </span>
        ))}
      </div>

      {error && <p className="scan-progress__error">{error}</p>}
    </div>
  );
}
