import type {
  AnalysisStatus,
  BehaviorSummary,
  BinaryFormat,
  Ecosystem,
  Finding,
  ManifestAnalysis,
  PackageAnalysis,
  RiskLevel,
  ScanRequest
} from "@binshield/analysis-types";

export type PackageSourceKind = "fixture" | "directory" | "registry" | "tarball" | "install";

export interface WorkerScanRequest extends ScanRequest {
  packageRoot?: string;
  packageTarball?: string;
  packageSource?: PackageSourceKind;
  forceReanalyze?: boolean;
  /**
   * Optional comma-separated analyzer names (or pre-split array) enabling
   * per-scan control over which MalwareAnalyzer plugins are active.
   * Corresponds to the `--analyzers=yara,heuristic,string-sig` CLI flag.
   * When absent or empty, all registered analyzers run.
   *
   * @example ["yara", "string-sig"]   // skip heuristic for this scan
   */
  analyzerFilter?: string[];
}

export interface PackageManifest {
  name: string;
  version: string;
  scripts: Record<string, string>;
  dependencies: Record<string, string>;
  optionalDependencies: Record<string, string>;
}

export interface AcquiredPackage {
  sourceKind: PackageSourceKind;
  packageRoot: string;
  packageJsonPath: string;
  manifest: PackageManifest;
}

export interface FingerprintedArtifact {
  filename: string;
  absolutePath: string;
  relativePath: string;
  fileSize: number;
  sha256: string;
  format: BinaryFormat;
  architecture: string;
  kind: "native-addon" | "shared-library" | "wasm" | "binary" | "unknown";
  bytes: Uint8Array;
  strings: string[];
  interestingStrings: string[];
}

export interface DecompiledArtifact {
  pseudoSource: string;
  imports: string[];
  strings: string[];
  functionCount: number;
  callTargets: string[];
  confidence: number;
}

export interface ClassifiedArtifact {
  summary: string;
  explanation: string;
  sourceMatchConfidence: "low" | "medium" | "high";
  behaviors: BehaviorSummary;
  findings: Finding[];
  riskNotes: string[];
}

export interface AnalysisCacheEntry {
  cacheKey: string;
  artifactHashes: string[];
  analysis: PackageAnalysis;
  createdAt: string;
}

export interface AnalysisJobRecord {
  id: string;
  request: WorkerScanRequest;
  status: AnalysisStatus;
  requestedAt: string;
  startedAt?: string;
  completedAt?: string;
  cacheKey: string;
  artifactHashes: string[];
  retries: number;
  fromCache: boolean;
  error?: string;
}

export interface AnalysisOutcome {
  job: AnalysisJobRecord;
  analysis: PackageAnalysis;
  artifacts: FingerprintedArtifact[];
}

export interface JobEvent {
  jobId: string;
  status: AnalysisStatus | "cached" | "retry";
  at: string;
  message?: string;
}

export interface AnalysisServiceBundle {
  acquisition: PackageAcquisitionService;
  extraction: BinaryExtractor;
  decompiler: DecompilerProvider;
  classifier: ClassifierProvider;
  scriptAnalyzer: ScriptAnalyzerProvider;
  cache: AnalysisCache;
  jobs: JobStore;
}

export interface PackageAcquisitionService {
  readonly name: string;
  acquire(request: WorkerScanRequest): Promise<AcquiredPackage>;
}

export interface BinaryExtractor {
  discover(packageRoot: string): Promise<FingerprintedArtifact[]>;
}

export interface DecompilerProvider {
  readonly name: string;
  decompile(input: {
    packageRequest: WorkerScanRequest;
    packageRoot: string;
    artifact: FingerprintedArtifact;
  }): Promise<DecompiledArtifact>;
}

export interface ClassifierProvider {
  readonly name: string;
  classify(input: {
    packageRequest: WorkerScanRequest;
    packageRoot: string;
    artifact: FingerprintedArtifact;
    decompiled: DecompiledArtifact;
  }): Promise<ClassifiedArtifact>;
}

export interface ScriptAnalysisInput {
  packageRequest: WorkerScanRequest;
  packageRoot: string;
  manifest: PackageManifest;
}

/**
 * Analyzes a package's manifest and install scripts for supply-chain worm
 * behavior. The second analysis path alongside `DecompilerProvider` +
 * `ClassifierProvider`, which only cover native binaries.
 */
export interface ScriptAnalyzerProvider {
  readonly name: string;
  analyze(input: ScriptAnalysisInput): Promise<ManifestAnalysis>;
}

export interface AnalysisCache {
  get(cacheKey: string): AnalysisCacheEntry | undefined;
  set(entry: AnalysisCacheEntry): void;
  clear(): void;
}

export interface JobStore {
  submit(request: WorkerScanRequest, cacheKey: string): AnalysisJobRecord;
  start(jobId: string): AnalysisJobRecord;
  cache(jobId: string, analysis: PackageAnalysis, artifactHashes: string[], cacheKey?: string): AnalysisJobRecord;
  complete(jobId: string, analysis: PackageAnalysis, artifactHashes: string[], cacheKey?: string): AnalysisJobRecord;
  fail(jobId: string, error: unknown): AnalysisJobRecord;
  retry(jobId: string): AnalysisJobRecord;
  get(jobId: string): AnalysisJobRecord | undefined;
  list(): AnalysisJobRecord[];
  events(jobId: string): JobEvent[];
}

export interface PackagePackageResult {
  packageAnalysis: PackageAnalysis;
  artifactHashes: string[];
  cacheKey: string;
}

export interface RuntimeOptions {
  services?: Partial<AnalysisServiceBundle>;
  demoPackageRoot?: string;
}

export interface AnalysisProviderResult {
  packageAnalysis: PackageAnalysis;
  fromCache: boolean;
  job: AnalysisJobRecord;
  artifacts: FingerprintedArtifact[];
}

export const isBinaryFormat = (value: BinaryFormat): boolean => value !== "unknown";

export const statusOrder: Array<AnalysisStatus | "cached" | "retry"> = [
  "queued",
  "analyzing",
  "complete",
  "failed"
];

export function confidenceRank(value: "low" | "medium" | "high"): number {
  return value === "high" ? 3 : value === "medium" ? 2 : 1;
}

export function collapseConfidence(values: Array<"low" | "medium" | "high">): "low" | "medium" | "high" {
  if (values.length === 0) {
    return "low";
  }

  const rank = Math.min(...values.map(confidenceRank));
  return rank === 3 ? "high" : rank === 2 ? "medium" : "low";
}
