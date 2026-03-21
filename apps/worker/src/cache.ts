import type { AnalysisCache, AnalysisCacheEntry, WorkerScanRequest } from "./types";

export function buildCacheKey(request: WorkerScanRequest, artifactHashes: string[]): string {
  const parts = [request.ecosystem, request.packageName, request.version, ...artifactHashes.slice().sort()];
  return parts.join(":");
}

export class InMemoryAnalysisCache implements AnalysisCache {
  private readonly entries = new Map<string, AnalysisCacheEntry>();

  get(cacheKey: string): AnalysisCacheEntry | undefined {
    return this.entries.get(cacheKey);
  }

  set(entry: AnalysisCacheEntry): void {
    this.entries.set(entry.cacheKey, entry);
  }

  clear(): void {
    this.entries.clear();
  }
}
