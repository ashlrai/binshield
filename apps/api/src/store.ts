import type { ApiListResponse, PackageAnalysis, RepoRecord, ScanJob, ScanRequest, SearchResult } from "@binshield/analysis-types";
import { getSampleAnalysis, sampleAnalyses, sampleDiff } from "@binshield/analysis-types";

class InMemoryStore {
  private analyses = new Map<string, PackageAnalysis>();
  private jobs = new Map<string, ScanJob>();
  private repos = new Map<string, RepoRecord>();

  constructor(seed: PackageAnalysis[]) {
    for (const analysis of seed) {
      this.analyses.set(this.analysisKey(analysis.packageName, analysis.version), analysis);
    }
  }

  private analysisKey(packageName: string, version: string) {
    return `${packageName}@${version}`;
  }

  search(query?: string): ApiListResponse<SearchResult> {
    const items = Array.from(this.analyses.values())
      .filter((analysis) => !query || analysis.packageName.includes(query))
      .map((analysis) => ({
        ecosystem: analysis.ecosystem,
        packageName: analysis.packageName,
        latestVersion: analysis.version,
        riskLevel: analysis.riskLevel,
        riskScore: analysis.riskScore,
        summary: analysis.summary,
        binaryCount: analysis.binaryCount
      }));

    return {
      items,
      total: items.length
    };
  }

  getPackage(packageName: string, version?: string) {
    return getSampleAnalysis(packageName, version) ?? this.analyses.get(this.analysisKey(packageName, version ?? ""));
  }

  getVersions(packageName: string) {
    return Array.from(this.analyses.values()).filter((analysis) => analysis.packageName === packageName);
  }

  getDiff() {
    return sampleDiff;
  }

  submitScan(request: ScanRequest): ScanJob {
    const existing = this.getPackage(request.packageName, request.version);
    const id = `job_${request.packageName}_${request.version}_${Date.now()}`;
    const job: ScanJob = {
      id,
      status: existing ? "complete" : "queued",
      requestedAt: new Date().toISOString(),
      completedAt: existing ? new Date().toISOString() : undefined,
      request,
      result: existing
    };
    this.jobs.set(id, job);
    return job;
  }

  getJob(id: string) {
    const job = this.jobs.get(id);
    if (!job) {
      return undefined;
    }

    if (job.status === "queued") {
      const fallback = sampleAnalyses[0];
      const completed: ScanJob = {
        ...job,
        status: "complete",
        completedAt: new Date().toISOString(),
        result: {
          ...fallback,
          id: `${fallback.id}_copy`,
          packageName: job.request.packageName,
          version: job.request.version
        }
      };
      this.jobs.set(id, completed);
      return completed;
    }

    return job;
  }

  listRepos(orgId: string) {
    return Array.from(this.repos.values()).filter((repo) => repo.orgId === orgId);
  }

  createRepo(orgId: string, githubRepo: string) {
    const repo: RepoRecord = {
      id: `repo_${this.repos.size + 1}`,
      orgId,
      githubRepo,
      nativeDependencyCount: 0,
      aggregateRiskScore: 0
    };
    this.repos.set(repo.id, repo);
    return repo;
  }
}

export const store = new InMemoryStore(sampleAnalyses);
