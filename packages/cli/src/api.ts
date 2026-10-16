/**
 * BinShield API client — zero dependencies.
 *
 * Mirrors shapes from @binshield/analysis-types without importing them,
 * keeping the CLI self-contained and dependency-free.
 */

// ---------------------------------------------------------------------------
// Domain types (mirrored from @binshield/analysis-types)
// ---------------------------------------------------------------------------

export type RiskLevel = "none" | "low" | "medium" | "high" | "critical";
export type AnalysisStatus = "queued" | "analyzing" | "complete" | "failed";
export type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";

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
  severity: FindingSeverity;
  title: string;
  description: string;
  location?: string;
  recommendation: string;
}

export type ScriptThreatCategory =
  | "installHook"
  | "scriptInjection"
  | "environmentTheft"
  | "dependencyConfusion"
  | "wiper"
  | "reverseShell"
  | "remoteCodeExecution"
  | "obfuscation"
  | "knownMalware";

export interface ScriptFinding {
  category: ScriptThreatCategory;
  severity: FindingSeverity;
  title: string;
  description: string;
  filePath: string;
  evidence: string;
  lifecycleHook?: string;
  recommendation: string;
}

export interface ScriptThreatSummary {
  installHook: BehaviorSignal;
  scriptInjection: BehaviorSignal;
  environmentTheft: BehaviorSignal;
  dependencyConfusion: BehaviorSignal;
  wiper: BehaviorSignal;
  reverseShell: BehaviorSignal;
  remoteCodeExecution: BehaviorSignal;
}

export interface KnownMalwareMatch {
  advisoryId: string;
  source: string;
  summary: string;
  url?: string;
}

export interface ManifestAnalysis {
  id: string;
  ecosystem: string;
  lifecycleHooks: Record<string, string>;
  hasInstallScripts: boolean;
  analyzedFiles: string[];
  riskScore: number;
  riskLevel: RiskLevel;
  threats: ScriptThreatSummary;
  findings: ScriptFinding[];
  knownMalwareAdvisoryIds: string[];
  knownMalwareMatches?: KnownMalwareMatch[];
  aiExplanation?: string;
  sourceMatchConfidence: string;
  analyzedAt: string;
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
  manifestAnalysis?: ManifestAnalysis;
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

export interface LockfileScanJob {
  id: string;
  status: string;
  filename: string;
}

export interface LockfilePackageResult {
  ecosystem: string;
  packageName: string;
  version: string;
  riskLevel: RiskLevel;
  riskScore: number;
  status: string;
  analysisId?: string;
  hasInstallScript?: boolean;
}

export interface LockfileScanResult {
  id: string;
  filename: string;
  status: string;
  packages: LockfilePackageResult[];
  totalPackages: number;
  highRiskCount: number;
  criticalRiskCount: number;
  mediumRiskCount?: number;
  lowRiskCount?: number;
}

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

export type ApiErrorKind =
  | "auth"
  | "not_found"
  | "rate_limit"
  | "server"
  | "network"
  | "timeout"
  | "unknown";

export class ApiError extends Error {
  constructor(
    public readonly kind: ApiErrorKind,
    message: string,
    public readonly statusCode?: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

function classifyStatus(status: number): ApiErrorKind {
  if (status === 401 || status === 403) return "auth";
  if (status === 404) return "not_found";
  if (status === 429) return "rate_limit";
  if (status >= 500) return "server";
  return "unknown";
}

async function extractErrorMessage(res: Response): Promise<string> {
  try {
    const body = await res.text();
    const parsed = JSON.parse(body) as { error?: string; message?: string };
    return parsed.error ?? parsed.message ?? res.statusText;
  } catch {
    return res.statusText;
  }
}

// ---------------------------------------------------------------------------
// Sleep utility
// ---------------------------------------------------------------------------

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

export interface BinShieldClientOptions {
  baseUrl: string;
  apiKey?: string;
}

export class BinShieldClient {
  readonly baseUrl: string;
  readonly apiKey: string | undefined;

  constructor(options: BinShieldClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.apiKey = options.apiKey;
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = { "Content-Type": "application/json" };
    if (this.apiKey) h["Authorization"] = `Bearer ${this.apiKey}`;
    return h;
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    let res: Response;
    try {
      res = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers: this.headers(),
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
    } catch (err) {
      throw new ApiError(
        "network",
        `Network error: ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    if (!res.ok) {
      const msg = await extractErrorMessage(res);
      throw new ApiError(classifyStatus(res.status), msg, res.status);
    }

    return res.json() as Promise<T>;
  }

  // -- Package scan ---------------------------------------------------------

  async scan(ecosystem: string, name: string, version: string): Promise<ScanJob> {
    return this.request<ScanJob>("POST", "/scans/packages", {
      ecosystem,
      packageName: name,
      version,
      source: "api",
    });
  }

  async scanPublic(ecosystem: string, name: string, version: string): Promise<ScanJob> {
    return this.request<ScanJob>("POST", "/public/scan", {
      ecosystem,
      packageName: name,
      version,
    });
  }

  async getScanJob(id: string): Promise<ScanJob> {
    return this.request<ScanJob>("GET", `/scans/${encodeURIComponent(id)}`);
  }

  async waitForResult(
    job: ScanJob,
    opts: {
      timeoutMs?: number;
      onPoll?: (job: ScanJob) => void;
    } = {},
  ): Promise<PackageAnalysis> {
    if (job.result) return job.result;

    const timeout = opts.timeoutMs ?? 180_000;
    const start = Date.now();
    let delay = 1500;
    let current = job;

    while (Date.now() - start < timeout) {
      await sleep(delay);
      current = await this.getScanJob(current.id);
      opts.onPoll?.(current);

      if (current.status === "failed") {
        throw new ApiError("unknown", current.error ?? `Scan ${current.id} failed`);
      }

      if (current.result) return current.result;

      delay = Math.min(Math.round(delay * 1.4), 6000);
    }

    throw new ApiError(
      "timeout",
      `Timed out waiting for scan ${job.id} (${timeout / 1000}s). Check https://binshield.dev for results.`,
    );
  }

  // -- Lockfile scan --------------------------------------------------------

  async scanLockfile(filename: string, content: string): Promise<LockfileScanJob> {
    return this.request<LockfileScanJob>("POST", "/scans/lockfile", {
      filename,
      content,
    });
  }

  async getLockfileScan(id: string): Promise<LockfileScanResult> {
    return this.request<LockfileScanResult>(
      "GET",
      `/scans/lockfile/${encodeURIComponent(id)}`,
    );
  }

  async waitForLockfileResult(
    job: LockfileScanJob,
    opts: {
      timeoutMs?: number;
      onPoll?: (status: string) => void;
    } = {},
  ): Promise<LockfileScanResult> {
    const timeout = opts.timeoutMs ?? 180_000;
    const start = Date.now();
    let delay = 2000;

    while (Date.now() - start < timeout) {
      await sleep(delay);
      const result = await this.getLockfileScan(job.id);
      opts.onPoll?.(result.status);

      if (result.status === "failed") {
        throw new ApiError("unknown", `Lockfile scan ${job.id} failed`);
      }

      if (result.status === "complete" || result.status === "completed") {
        return result;
      }

      delay = Math.min(Math.round(delay * 1.4), 6000);
    }

    throw new ApiError(
      "timeout",
      `Timed out waiting for lockfile scan ${job.id} (${timeout / 1000}s).`,
    );
  }

  // -- Search ---------------------------------------------------------------

  async search(query: string): Promise<ApiListResponse<SearchResult>> {
    return this.request<ApiListResponse<SearchResult>>(
      "GET",
      `/packages?q=${encodeURIComponent(query)}`,
    );
  }

  // -- SBOM -----------------------------------------------------------------

  async getSbom(ecosystem: string, name: string, version: string): Promise<string> {
    let res: Response;
    try {
      res = await fetch(
        `${this.baseUrl}/packages/${encodeURIComponent(ecosystem)}/${encodeURIComponent(name)}/${encodeURIComponent(version)}/sbom`,
        { headers: this.headers() },
      );
    } catch (err) {
      throw new ApiError(
        "network",
        `Network error: ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    if (!res.ok) {
      const msg = await extractErrorMessage(res);
      throw new ApiError(classifyStatus(res.status), msg, res.status);
    }

    return res.text();
  }
}
