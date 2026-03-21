export type Ecosystem = "npm" | "pypi";
export type AnalysisStatus = "queued" | "analyzing" | "complete" | "failed";
export type RiskLevel = "none" | "low" | "medium" | "high" | "critical";
export type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";
export type BinaryFormat = "ELF" | "PE" | "Mach-O" | "WASM" | "unknown";

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

export interface BinaryAnalysis {
  id: string;
  filename: string;
  architecture: string;
  format: BinaryFormat;
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
  ecosystem: Ecosystem;
  packageName: string;
  version: string;
  status: AnalysisStatus;
  riskScore: number;
  riskLevel: RiskLevel;
  summary: string;
  sourceMatchConfidence: "low" | "medium" | "high";
  binaryCount: number;
  totalBinarySize: number;
  aiModel: string;
  createdAt: string;
  binaries: BinaryAnalysis[];
}

export interface PackageDiff {
  packageName: string;
  ecosystem: Ecosystem;
  fromVersion: string;
  toVersion: string;
  riskDelta: number;
  summary: string;
  addedBehaviors: string[];
  removedBehaviors: string[];
}

export interface SearchResult {
  ecosystem: Ecosystem;
  packageName: string;
  latestVersion: string;
  riskLevel: RiskLevel;
  riskScore: number;
  summary: string;
  binaryCount: number;
}

export interface ScanRequest {
  ecosystem: Ecosystem;
  packageName: string;
  version: string;
  repo?: string;
}

export interface ScanJob {
  id: string;
  status: AnalysisStatus;
  requestedAt: string;
  completedAt?: string;
  request: ScanRequest;
  result?: PackageAnalysis;
  error?: string;
}

export interface RepoRecord {
  id: string;
  orgId: string;
  githubRepo: string;
  nativeDependencyCount: number;
  aggregateRiskScore: number;
  lastScanAt?: string;
}

export interface ApiListResponse<T> {
  items: T[];
  total: number;
}

export const emptyBehaviorSummary = (): BehaviorSummary => ({
  network: { detected: false, details: [] },
  filesystem: { detected: false, details: [] },
  process: { detected: false, details: [] },
  crypto: { detected: false, details: [] },
  obfuscation: { detected: false, details: [] },
  dataExfiltration: { detected: false, details: [] }
});

const sharedBehaviors = emptyBehaviorSummary();
sharedBehaviors.filesystem = {
  detected: true,
  details: ["Reads system entropy sources and temporary image buffers."]
};
sharedBehaviors.crypto = {
  detected: true,
  details: ["Calls common OpenSSL-style hashing and key derivation primitives."]
};

export const sampleAnalyses: PackageAnalysis[] = [
  {
    id: "pkg_bcrypt_5_1_1",
    ecosystem: "npm",
    packageName: "bcrypt",
    version: "5.1.1",
    status: "complete",
    riskScore: 12,
    riskLevel: "low",
    summary: "Standard bcrypt native addon with expected entropy access and no suspicious network activity.",
    sourceMatchConfidence: "high",
    binaryCount: 1,
    totalBinarySize: 198451,
    aiModel: "claude-sonnet",
    createdAt: "2026-03-21T12:00:00.000Z",
    binaries: [
      {
        id: "bin_bcrypt_lib",
        filename: "bcrypt_lib.node",
        architecture: "x86_64",
        format: "ELF",
        fileSize: 198451,
        functionCount: 43,
        importCount: 17,
        riskScore: 12,
        riskLevel: "low",
        decompiledPreview: "int bcrypt_hash(...) { /* native hashing flow */ }",
        aiExplanation: "The binary performs native password hashing and seed generation using expected runtime libraries.",
        imports: ["EVP_sha512", "uv_queue_work", "node_module_register"],
        strings: ["/dev/urandom", "Invalid salt version"],
        behaviors: {
          ...emptyBehaviorSummary(),
          filesystem: { detected: true, details: ["Reads /dev/urandom for entropy."] },
          crypto: { detected: true, details: ["Uses OpenSSL EVP routines for hashing."] }
        },
        findings: [
          {
            severity: "info",
            title: "Entropy source access",
            description: "Reads system entropy for password hashing.",
            location: "bcrypt_gensalt",
            recommendation: "No action needed."
          }
        ]
      }
    ]
  },
  {
    id: "pkg_sharp_0_33_2",
    ecosystem: "npm",
    packageName: "sharp",
    version: "0.33.2",
    status: "complete",
    riskScore: 8,
    riskLevel: "low",
    summary: "Image processing addon with expected filesystem and memory operations, no outbound network behavior.",
    sourceMatchConfidence: "high",
    binaryCount: 1,
    totalBinarySize: 612845,
    aiModel: "claude-sonnet",
    createdAt: "2026-03-21T12:00:00.000Z",
    binaries: [
      {
        id: "bin_sharp_linux_x64",
        filename: "sharp-linux-x64.node",
        architecture: "x86_64",
        format: "ELF",
        fileSize: 612845,
        functionCount: 87,
        importCount: 30,
        riskScore: 8,
        riskLevel: "low",
        decompiledPreview: "void process_image(...) { /* libvips wrapper */ }",
        aiExplanation: "The binary wraps libvips routines for image transforms and disk-backed image IO.",
        imports: ["vips_resize", "vips_jpegsave", "napi_create_function"],
        strings: ["/tmp", "Unsupported image format"],
        behaviors: {
          ...sharedBehaviors,
          crypto: { detected: false, details: [] }
        },
        findings: [
          {
            severity: "info",
            title: "Temporary file access",
            description: "Uses temp files during image processing operations.",
            location: "process_image",
            recommendation: "Validate temp directory policies in hardened environments."
          }
        ]
      }
    ]
  }
];

export const sampleDiff: PackageDiff = {
  packageName: "sqlite3",
  ecosystem: "npm",
  fromVersion: "5.1.6",
  toVersion: "5.1.7",
  riskDelta: 4,
  summary: "Version 5.1.7 adds optional extension loading checks but no new network behavior.",
  addedBehaviors: ["Additional filesystem path validation before extension loading."],
  removedBehaviors: []
};

export function getSampleAnalysis(packageName: string, version?: string): PackageAnalysis | undefined {
  return sampleAnalyses.find((analysis) => {
    if (analysis.packageName !== packageName) {
      return false;
    }

    return version ? analysis.version === version : true;
  });
}
