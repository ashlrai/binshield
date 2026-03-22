"use client";

import { useState, useCallback, useRef, useEffect } from "react";

import type { PackageAnalysis, Ecosystem } from "@binshield/analysis-types";

export type LiveScanStatus = "idle" | "submitting" | "polling" | "complete" | "error";

interface LiveScanState {
  status: LiveScanStatus;
  jobId: string | null;
  stage: string | null;
  result: PackageAnalysis | null;
  error: string | null;
  elapsedMs: number;
}

export function useLiveScan(apiBase: string) {
  const [state, setState] = useState<LiveScanState>({
    status: "idle",
    jobId: null,
    stage: null,
    result: null,
    error: null,
    elapsedMs: 0
  });
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const startTimeRef = useRef<number>(0);

  const cleanup = useCallback(() => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
  }, []);

  useEffect(() => cleanup, [cleanup]);

  const submit = useCallback(
    async (ecosystem: Ecosystem, packageName: string, version: string, apiKey?: string) => {
      cleanup();
      startTimeRef.current = Date.now();

      setState({
        status: "submitting",
        jobId: null,
        stage: "queued",
        result: null,
        error: null,
        elapsedMs: 0
      });

      try {
        const headers: Record<string, string> = { "Content-Type": "application/json" };
        if (apiKey) headers["x-binshield-api-key"] = apiKey;

        const res = await fetch(`${apiBase}/scans/packages`, {
          method: "POST",
          headers,
          body: JSON.stringify({ ecosystem, packageName, version })
        });

        if (!res.ok) {
          const body = await res.json().catch(() => ({}));
          setState((prev) => ({
            ...prev,
            status: "error",
            error: body.error ?? `Submit failed: ${res.status}`
          }));
          return;
        }

        const job = await res.json();

        if (job.status === "complete" && job.result) {
          setState({
            status: "complete",
            jobId: job.id,
            stage: "complete",
            result: job.result,
            error: null,
            elapsedMs: Date.now() - startTimeRef.current
          });
          return;
        }

        setState((prev) => ({ ...prev, status: "polling", jobId: job.id }));

        intervalRef.current = setInterval(async () => {
          try {
            const pollRes = await fetch(`${apiBase}/scans/${job.id}`, { headers });
            if (!pollRes.ok) return;
            const pollData = await pollRes.json();

            setState((prev) => ({
              ...prev,
              stage: pollData.stage ?? pollData.status ?? prev.stage,
              elapsedMs: Date.now() - startTimeRef.current
            }));

            if (pollData.status === "complete") {
              cleanup();
              setState((prev) => ({
                ...prev,
                status: "complete",
                result: pollData.result,
                stage: "complete"
              }));
            } else if (pollData.status === "failed") {
              cleanup();
              setState((prev) => ({
                ...prev,
                status: "error",
                error: pollData.error ?? "Analysis failed"
              }));
            }
          } catch {
            /* retry on next interval */
          }
        }, 2500);
      } catch (err) {
        setState((prev) => ({
          ...prev,
          status: "error",
          error: err instanceof Error ? err.message : "Network error"
        }));
      }
    },
    [apiBase, cleanup]
  );

  const reset = useCallback(() => {
    cleanup();
    setState({
      status: "idle",
      jobId: null,
      stage: null,
      result: null,
      error: null,
      elapsedMs: 0
    });
  }, [cleanup]);

  return { ...state, submit, reset };
}
