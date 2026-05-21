import type {
  BehaviorSummary,
  ApiListResponse,
  AnalysisStatus,
  Ecosystem,
  Finding,
  ManifestAnalysis,
  PackageAnalysis,
  PackageDiff,
  RepoRecord,
  RiskLevel,
  ScanJob,
  ScanRequest,
  ScriptFinding,
  SearchResult
} from "@binshield/analysis-types";

export type {
  ApiListResponse,
  AnalysisStatus,
  BehaviorSummary,
  Ecosystem,
  Finding,
  ManifestAnalysis,
  PackageAnalysis,
  PackageDiff,
  RepoRecord,
  RiskLevel,
  ScanJob,
  ScanRequest,
  ScriptFinding,
  SearchResult
};

export interface AuthPrincipal {
  apiKeyId: string;
  orgId: string;
  userId?: string;
  label: string;
  scopes: string[];
}

export interface ApiKeySummary {
  id: string;
  label: string;
  prefix: string;
  createdAt: string;
  lastUsedAt?: string;
}

export interface OrganizationSummary {
  id: string;
  name: string;
  slug: string;
  plan: string;
  billingStatus: string;
  createdAt: string;
}

export interface WatchlistSummary {
  id: string;
  orgId: string;
  name: string;
  channel: "email" | "slack" | "webhook";
  destination: string;
  createdAt: string;
  packageCount: number;
}

export interface WatchlistPackageSummary {
  id: string;
  watchlistId: string;
  ecosystem: Ecosystem;
  packageName: string;
  version?: string;
  createdAt: string;
}

export interface SubscriptionSummary {
  id: string;
  orgId: string;
  provider: "stripe" | "manual";
  plan: string;
  status: string;
  currentPeriodEnd?: string;
  cancelAtPeriodEnd: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface CheckoutSession {
  checkoutUrl: string;
  customerId: string;
  subscriptionId: string;
  plan: string;
  status: "pending";
}

export interface RepositoryInfo {
  mode: "local" | "supabase";
  ready: boolean;
  description: string;
}

export interface Advisory {
  id: string;
  source: string;
  sourceId: string;
  /** 'vulnerability' = a CVE-style flaw; 'malware' = the package itself is malicious. */
  advisoryType?: "vulnerability" | "malware";
  title: string;
  description?: string;
  severity?: string;
  cvssScore?: number;
  cvssVector?: string;
  cweIds: string[];
  publishedAt?: string;
  updatedAt?: string;
  references: Array<{ type?: string; url: string }>;
  affectedPackages: Array<{
    ecosystem: string;
    packageName: string;
    vulnerableRange?: string;
    patchedVersion?: string;
  }>;
}

export interface AdvisorySyncResult {
  ecosystem: string;
  packageName: string;
  totalAdvisories: number;
  newAdvisories: number;
  sources: Record<string, number>;
}

export interface NotificationChannelSummary {
  id: string;
  orgId: string;
  channel: "email" | "slack" | "webhook";
  destination: string;
  enabled: boolean;
  minRiskLevel: string;
  createdAt: string;
  /** Webhook HMAC secret — returned only once, at creation time. */
  secret?: string;
}

export interface AlertSummary {
  id: string;
  orgId: string;
  ecosystem: string;
  packageName: string;
  version: string;
  riskLevel: string;
  riskScore: number;
  matchReason: string;
  channel: string;
  destination: string;
  status: string;
  createdAt: string;
  deliveredAt?: string;
}

export interface SuppressionSummary {
  id: string;
  orgId: string;
  ecosystem: string;
  packageName: string;
  /** Null = all versions */
  version?: string;
  /** Null = any category */
  findingCategory?: string;
  /** Null = any title */
  findingTitle?: string;
  reason: string;
  createdAt: string;
}
