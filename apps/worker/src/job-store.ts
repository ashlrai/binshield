import type { PackageAnalysis } from "@binshield/analysis-types";

import type { AnalysisJobRecord, JobEvent, JobStore, WorkerScanRequest } from "./types";

function now() {
  return new Date().toISOString();
}

function createJobId(request: WorkerScanRequest): string {
  return [
    request.ecosystem,
    request.packageName,
    request.version,
    Math.random().toString(36).slice(2, 10)
  ].join("-");
}

export class InMemoryJobStore implements JobStore {
  private readonly jobs = new Map<string, AnalysisJobRecord>();
  private readonly jobEvents = new Map<string, JobEvent[]>();

  submit(request: WorkerScanRequest, cacheKey: string): AnalysisJobRecord {
    const job: AnalysisJobRecord = {
      id: createJobId(request),
      request,
      status: "queued",
      requestedAt: now(),
      cacheKey,
      artifactHashes: [],
      retries: 0,
      fromCache: false
    };

    this.jobs.set(job.id, job);
    this.appendEvent(job.id, "queued", `Queued analysis for ${request.packageName}@${request.version}`);
    return job;
  }

  start(jobId: string): AnalysisJobRecord {
    const job = this.requireJob(jobId);
    const updated = {
      ...job,
      status: "analyzing" as const,
      startedAt: job.startedAt ?? now()
    };
    this.jobs.set(jobId, updated);
    this.appendEvent(jobId, "analyzing", "Worker picked up the job");
    return updated;
  }

  cache(jobId: string, analysis: PackageAnalysis, artifactHashes: string[], cacheKey?: string): AnalysisJobRecord {
    return this.complete(jobId, analysis, artifactHashes, cacheKey, true);
  }

  complete(jobId: string, analysis: PackageAnalysis, artifactHashes: string[], cacheKey?: string, fromCache = false): AnalysisJobRecord {
    const job = this.requireJob(jobId);
    const updated: AnalysisJobRecord = {
      ...job,
      cacheKey: cacheKey ?? job.cacheKey,
      status: "complete",
      completedAt: now(),
      artifactHashes,
      fromCache,
      error: undefined
    };
    this.jobs.set(jobId, updated);
    this.appendEvent(jobId, fromCache ? "cached" : "complete", `Analysis completed for ${job.request.packageName}@${job.request.version}`);
    return updated;
  }

  fail(jobId: string, error: unknown): AnalysisJobRecord {
    const job = this.requireJob(jobId);
    const message = error instanceof Error ? error.message : String(error);
    const updated: AnalysisJobRecord = {
      ...job,
      status: "failed",
      completedAt: now(),
      error: message
    };
    this.jobs.set(jobId, updated);
    this.appendEvent(jobId, "failed", message);
    return updated;
  }

  retry(jobId: string): AnalysisJobRecord {
    const job = this.requireJob(jobId);
    const updated: AnalysisJobRecord = {
      ...job,
      status: "queued",
      retries: job.retries + 1,
      error: undefined,
      completedAt: undefined,
      startedAt: undefined
    };
    this.jobs.set(jobId, updated);
    this.appendEvent(jobId, "retry", `Retry scheduled (${updated.retries})`);
    return updated;
  }

  get(jobId: string): AnalysisJobRecord | undefined {
    return this.jobs.get(jobId);
  }

  list(): AnalysisJobRecord[] {
    return Array.from(this.jobs.values());
  }

  events(jobId: string): JobEvent[] {
    return this.jobEvents.get(jobId) ?? [];
  }

  private requireJob(jobId: string): AnalysisJobRecord {
    const job = this.jobs.get(jobId);
    if (!job) {
      throw new Error(`Unknown job: ${jobId}`);
    }

    return job;
  }

  private appendEvent(jobId: string, status: JobEvent["status"], message?: string): void {
    const list = this.jobEvents.get(jobId) ?? [];
    list.push({ jobId, status, at: now(), message });
    this.jobEvents.set(jobId, list);
  }
}
