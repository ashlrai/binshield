import { resolveApiKey, resolveApiUrl } from "./config.js";

// ---------------------------------------------------------------------------
// Lightweight type mirrors so the CLI has zero package dependencies.
// These match the shapes defined in @binshield/analysis-types.
// ---------------------------------------------------------------------------

export type RiskLevel = "none" | "low" | "medium" | "high" | "critical";
export type AnalysisStatus = "queued" | "analyzing" | "complete" | "failed";

export interface BehaviorSignal {
  detected: boolean;
  details: string[];
}

export interface BehaviorSummary {
  network: BehaviorSignal;
  filesystem: BehaviorSignal;
  process: BehaviorSignal;
  crypto: BehaviorSignal;
  obfuscation: BehaviorSignal;
  dataExfiltration: BehaviorSignal;
}

export interface Finding {
  severity: string;
  title: string;
  description: string;
  location?: string;
  recommendation: string;
}

export interface BinaryAnalysis {
  id: string;
  filename: string;
  architecture: string;
  format: string;
  fileSize: number;
  functionCount: number;
  importCount: number;
  riskScore: number;
  riskLevel: RiskLevel;
  decompiledPreview: string;
  aiExplanation: string;
  imports: string[];
  strings: string[];
  behaviors: BehaviorSummary;
  findings: Finding[];
}

export interface PackageAnalysis {
  id: string;
  ecosystem: string;
  packageName: string;
  version: string;
  status: AnalysisStatus;
  riskScore: number;
  riskLevel: RiskLevel;
  summary: string;
  sourceMatchConfidence: string;
  binaryCount: number;
  totalBinarySize: number;
  binaries: BinaryAnalysis[];
  createdAt: string;
}

export interface ScanJob {
  id: string;
  status: AnalysisStatus;
  stage?: string;
  result?: PackageAnalysis;
  error?: string;
}

export interface SearchResult {
  ecosystem: string;
  packageName: string;
  latestVersion: string;
  riskLevel: RiskLevel;
  riskScore: number;
  summary: string;
  binaryCount: number;
}

export interface ApiListResponse<T> {
  items: T[];
  total: number;
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

function authHeaders(apiKey?: string): Record<string, string> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  if (apiKey) {
    headers.Authorization = `Bearer ${apiKey}`;
  }

  return headers;
}

export class BinShieldClient {
  private readonly baseUrl: string;
  private readonly apiKey: string | undefined;

  constructor(options?: { baseUrl?: string; apiKey?: string }) {
    this.baseUrl = (options?.baseUrl ?? resolveApiUrl()).replace(/\/+$/, "");
    this.apiKey = options?.apiKey ?? resolveApiKey();
  }

  // -- Search ---------------------------------------------------------------

  async search(query: string): Promise<ApiListResponse<SearchResult>> {
    const url = `${this.baseUrl}/packages?q=${encodeURIComponent(query)}`;
    const res = await fetch(url, { headers: authHeaders(this.apiKey) });

    if (!res.ok) {
      throw new Error(`Search failed: ${res.status} ${res.statusText}`);
    }

    return (await res.json()) as ApiListResponse<SearchResult>;
  }

  // -- Scan -----------------------------------------------------------------

  async scan(ecosystem: string, name: string, version: string): Promise<ScanJob> {
    const res = await fetch(`${this.baseUrl}/scans/packages`, {
      method: "POST",
      headers: authHeaders(this.apiKey),
      body: JSON.stringify({
        ecosystem,
        packageName: name,
        version,
        source: "api",
      }),
    });

    if (!res.ok) {
      throw new Error(`Scan submission failed: ${res.status} ${res.statusText}`);
    }

    return (await res.json()) as ScanJob;
  }

  // -- Poll for scan result -------------------------------------------------

  async getScanJob(id: string): Promise<ScanJob> {
    const res = await fetch(`${this.baseUrl}/scans/${encodeURIComponent(id)}`, {
      headers: authHeaders(this.apiKey),
    });

    if (!res.ok) {
      throw new Error(`Failed to fetch scan job: ${res.status} ${res.statusText}`);
    }

    return (await res.json()) as ScanJob;
  }

  async waitForResult(
    job: ScanJob,
    opts: { timeoutMs?: number; onPoll?: (job: ScanJob) => void } = {},
  ): Promise<PackageAnalysis> {
    if (job.result) {
      return job.result;
    }

    const timeout = opts.timeoutMs ?? 120_000;
    const start = Date.now();
    let delay = 1000;
    let current = job;

    while (Date.now() - start < timeout) {
      await sleep(delay);
      current = await this.getScanJob(current.id);

      opts.onPoll?.(current);

      if (current.status === "failed") {
        throw new Error(current.error ?? `Scan ${current.id} failed`);
      }

      if (current.result) {
        return current.result;
      }

      delay = Math.min(Math.round(delay * 1.5), 5000);
    }

    throw new Error(`Timed out waiting for scan ${job.id} after ${timeout}ms`);
  }

  // -- SBOM -----------------------------------------------------------------

  async getSbom(ecosystem: string, name: string, version: string): Promise<string> {
    const url = `${this.baseUrl}/packages/${encodeURIComponent(ecosystem)}/${encodeURIComponent(name)}/${encodeURIComponent(version)}/sbom`;
    const res = await fetch(url, { headers: authHeaders(this.apiKey) });

    if (!res.ok) {
      throw new Error(`SBOM download failed: ${res.status} ${res.statusText}`);
    }

    return res.text();
  }
}
