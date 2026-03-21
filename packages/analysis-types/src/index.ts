export type Ecosystem = "npm" | "pypi";
export type AnalysisStatus = "queued" | "analyzing" | "complete" | "failed";
export type RiskLevel = "none" | "low" | "medium" | "high" | "critical";
export type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";
export type BinaryFormat = "ELF" | "PE" | "Mach-O" | "WASM" | "unknown";
export type PlanName = "free" | "pro" | "team" | "enterprise";
export type SubscriptionStatus = "trialing" | "active" | "past_due" | "canceled" | "incomplete";
export type AuthRole = "anonymous" | "member" | "admin" | "owner" | "service";
export type AlertChannel = "email" | "slack" | "webhook";
export type AlertDeliveryStatus = "pending" | "sent" | "failed";
export type JobStage = "ingest" | "extract" | "decompile" | "classify" | "persist";
export type CommentMode = "always" | "failure-only" | "never";
export type SourceMatchConfidence = "low" | "medium" | "high";

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

export interface BinaryFingerprint {
  sha256: string;
  packageVersionKey: string;
  binaryKey: string;
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
  fingerprint?: BinaryFingerprint;
  behaviors: BehaviorSummary;
  findings: Finding[];
}

export interface PackageCoordinate {
  ecosystem: Ecosystem;
  packageName: string;
  version: string;
}

export interface PackageAnalysis extends PackageCoordinate {
  id: string;
  status: AnalysisStatus;
  riskScore: number;
  riskLevel: RiskLevel;
  summary: string;
  sourceMatchConfidence: SourceMatchConfidence;
  binaryCount: number;
  totalBinarySize: number;
  aiModel: string;
  createdAt: string;
  updatedAt?: string;
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

export interface DependencyReference extends PackageCoordinate {
  manifestPath?: string;
  lockfilePath?: string;
  reason?: string;
}

export interface ScanRequest extends PackageCoordinate {
  repo?: string;
  requestedByOrgId?: string;
  source?: "api" | "github-action" | "seed" | "dashboard";
  dependency?: DependencyReference;
}

export interface ScanJob {
  id: string;
  status: AnalysisStatus;
  stage?: JobStage;
  requestedAt: string;
  startedAt?: string;
  completedAt?: string;
  request: ScanRequest;
  result?: PackageAnalysis;
  cacheHit?: boolean;
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

export interface Organization {
  id: string;
  name: string;
  plan: PlanName;
  role: AuthRole;
  createdAt: string;
}

export interface ApiKeyRecord {
  id: string;
  orgId: string;
  label: string;
  preview: string;
  createdAt: string;
  lastUsedAt?: string;
}

export interface WatchlistRecord {
  id: string;
  orgId: string;
  packageName: string;
  ecosystem: Ecosystem;
  createdAt: string;
}

export interface AlertRecord {
  id: string;
  orgId: string;
  channel: AlertChannel;
  destination: string;
  deliveryStatus: AlertDeliveryStatus;
  packageName: string;
  createdAt: string;
}

export interface EntitlementRecord {
  canManageBilling: boolean;
  canCreateApiKeys: boolean;
  canUseWatchlists: boolean;
  maxRepos: number;
  maxMonthlyScans: number;
}

export interface SubscriptionRecord {
  id: string;
  orgId: string;
  plan: PlanName;
  status: SubscriptionStatus;
  stripeCustomerId?: string;
  stripeSubscriptionId?: string;
  currentPeriodEndsAt?: string;
  createdAt: string;
}

export interface DashboardSummary {
  organization: Organization;
  repos: RepoRecord[];
  watchlist: WatchlistRecord[];
  alerts: AlertRecord[];
  apiKeys: ApiKeyRecord[];
  subscription: SubscriptionRecord;
  entitlements: EntitlementRecord;
}

export interface ActionScanSummary {
  packageName: string;
  version: string;
  riskLevel: RiskLevel;
  riskScore: number;
  binaryFilenames: string[];
  summary: string;
}

export interface ActionConfig {
  failOn: RiskLevel | "never";
  commentMode: CommentMode;
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

export function entitlementForPlan(plan: PlanName): EntitlementRecord {
  switch (plan) {
    case "enterprise":
      return {
        canManageBilling: true,
        canCreateApiKeys: true,
        canUseWatchlists: true,
        maxRepos: 1000,
        maxMonthlyScans: 100000
      };
    case "team":
      return {
        canManageBilling: true,
        canCreateApiKeys: true,
        canUseWatchlists: true,
        maxRepos: 50,
        maxMonthlyScans: 10000
      };
    case "pro":
      return {
        canManageBilling: true,
        canCreateApiKeys: true,
        canUseWatchlists: true,
        maxRepos: 25,
        maxMonthlyScans: 2500
      };
    case "free":
    default:
      return {
        canManageBilling: false,
        canCreateApiKeys: true,
        canUseWatchlists: false,
        maxRepos: 3,
        maxMonthlyScans: 50
      };
  }
}

const bcryptBehaviors = emptyBehaviorSummary();
bcryptBehaviors.filesystem = {
  detected: true,
  details: ["Reads /dev/urandom for entropy."]
};
bcryptBehaviors.crypto = {
  detected: true,
  details: ["Uses OpenSSL EVP routines for hashing."]
};

const sharpBehaviors = emptyBehaviorSummary();
sharpBehaviors.filesystem = {
  detected: true,
  details: ["Reads system entropy sources and temporary image buffers."]
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
    updatedAt: "2026-03-21T12:00:00.000Z",
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
        fingerprint: {
          sha256: "sha256-bcrypt-511",
          packageVersionKey: "npm:bcrypt@5.1.1",
          binaryKey: "bcrypt_lib.node"
        },
        behaviors: bcryptBehaviors,
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
    updatedAt: "2026-03-21T12:00:00.000Z",
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
        fingerprint: {
          sha256: "sha256-sharp-0332",
          packageVersionKey: "npm:sharp@0.33.2",
          binaryKey: "sharp-linux-x64.node"
        },
        behaviors: {
          ...sharpBehaviors,
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

export const sampleOrganization: Organization = {
  id: "org_ashlrai",
  name: "Ashlr AI",
  plan: "pro",
  role: "owner",
  createdAt: "2026-03-21T12:00:00.000Z"
};

export const sampleRepos: RepoRecord[] = [
  {
    id: "repo_1",
    orgId: sampleOrganization.id,
    githubRepo: "ashlrai/platform-web",
    nativeDependencyCount: 4,
    aggregateRiskScore: 22,
    lastScanAt: "2026-03-21T13:30:00.000Z"
  },
  {
    id: "repo_2",
    orgId: sampleOrganization.id,
    githubRepo: "ashlrai/agent-runtime",
    nativeDependencyCount: 9,
    aggregateRiskScore: 43,
    lastScanAt: "2026-03-21T14:00:00.000Z"
  }
];

export const sampleApiKeys: ApiKeyRecord[] = [
  {
    id: "key_1",
    orgId: sampleOrganization.id,
    label: "GitHub Actions",
    preview: "bsh_live_****7A91",
    createdAt: "2026-03-21T12:30:00.000Z"
  }
];

export const sampleWatchlist: WatchlistRecord[] = [
  {
    id: "watch_1",
    orgId: sampleOrganization.id,
    packageName: "bcrypt",
    ecosystem: "npm",
    createdAt: "2026-03-21T13:00:00.000Z"
  }
];

export const sampleAlerts: AlertRecord[] = [
  {
    id: "alert_1",
    orgId: sampleOrganization.id,
    channel: "email",
    destination: "security@ashlr.ai",
    deliveryStatus: "sent",
    packageName: "bcrypt",
    createdAt: "2026-03-21T15:00:00.000Z"
  }
];

export const sampleSubscription: SubscriptionRecord = {
  id: "sub_1",
  orgId: sampleOrganization.id,
  plan: "pro",
  status: "active",
  stripeCustomerId: "cus_demo",
  stripeSubscriptionId: "sub_demo",
  currentPeriodEndsAt: "2026-04-21T00:00:00.000Z",
  createdAt: "2026-03-21T12:00:00.000Z"
};

export const sampleDashboard: DashboardSummary = {
  organization: sampleOrganization,
  repos: sampleRepos,
  watchlist: sampleWatchlist,
  alerts: sampleAlerts,
  apiKeys: sampleApiKeys,
  subscription: sampleSubscription,
  entitlements: entitlementForPlan(sampleSubscription.plan)
};

export const sampleActionSummaries: ActionScanSummary[] = sampleAnalyses.map((analysis) => ({
  packageName: analysis.packageName,
  version: analysis.version,
  riskLevel: analysis.riskLevel,
  riskScore: analysis.riskScore,
  binaryFilenames: analysis.binaries.map((binary) => binary.filename),
  summary: analysis.summary
}));

export function getSampleAnalysis(packageName: string, version?: string): PackageAnalysis | undefined {
  return sampleAnalyses.find((analysis) => {
    if (analysis.packageName !== packageName) {
      return false;
    }

    return version ? analysis.version === version : true;
  });
}
