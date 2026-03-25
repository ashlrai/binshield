import crypto from "node:crypto";

import { getSampleAnalysis, sampleAnalyses, sampleDiff } from "@binshield/analysis-types";

import { hashApiKey } from "./auth";
import type {
  Advisory,
  BehaviorSummary,
  ApiKeySummary,
  ApiListResponse,
  AuthPrincipal,
  CheckoutSession,
  Ecosystem,
  Finding,
  OrganizationSummary,
  PackageAnalysis,
  PackageDiff,
  RepoRecord,
  ScanJob,
  ScanRequest,
  SearchResult,
  SubscriptionSummary,
  WatchlistPackageSummary,
  WatchlistSummary
} from "./types";
import type { ApiEnv } from "./env";

interface OrganizationRow {
  id: string;
  name: string;
  slug: string;
  plan: string;
  billing_status: string;
  stripe_customer_id?: string | null;
  stripe_subscription_id?: string | null;
  created_at: string;
}

interface ApiKeyRow {
  id: string;
  org_id: string;
  label: string;
  prefix: string;
  hashed_key: string;
  scopes: string[];
  created_at: string;
  last_used_at?: string | null;
  revoked_at?: string | null;
}

interface PackageRow {
  id: string;
  ecosystem: Ecosystem;
  name: string;
  latest_analyzed_version?: string | null;
  total_versions_analyzed: number;
  created_at: string;
}

interface AnalysisRow {
  id: string;
  package_id: string;
  version: string;
  status: string;
  risk_score: number;
  risk_level: string;
  summary: string;
  source_match_confidence: "low" | "medium" | "high";
  behaviors: BehaviorSummary;
  findings: Finding[];
  binary_count: number;
  total_binary_size: number;
  ghidra_version?: string | null;
  ai_model?: string | null;
  analysis_duration_ms?: number | null;
  created_at: string;
}

interface BinaryRow {
  id: string;
  analysis_id: string;
  filename: string;
  architecture?: string | null;
  format?: string | null;
  file_size: number;
  function_count: number;
  import_count: number;
  risk_score: number;
  risk_level: string;
  decompiled_preview: string;
  ai_explanation: string;
  imports: string[];
  strings: string[];
  behaviors: BehaviorSummary;
  findings: Finding[];
  created_at: string;
}

interface RepoRow {
  id: string;
  org_id: string;
  github_repo: string;
  native_dep_count: number;
  aggregate_risk_score: number;
  last_scan_at?: string | null;
  created_at: string;
}

interface WatchlistRow {
  id: string;
  org_id: string;
  name: string;
  channel: "email" | "slack" | "webhook";
  destination: string;
  created_at: string;
}

interface WatchlistPackageRow {
  id: string;
  watchlist_id: string;
  ecosystem: Ecosystem;
  package_name: string;
  version?: string | null;
  created_at: string;
}

interface SubscriptionRow {
  id: string;
  org_id: string;
  provider: "stripe" | "manual";
  customer_id?: string | null;
  subscription_id?: string | null;
  plan: string;
  status: string;
  current_period_end?: string | null;
  cancel_at_period_end: boolean;
  created_at: string;
  updated_at: string;
}

interface AnalysisJobRow {
  id: string;
  org_id?: string | null;
  ecosystem: Ecosystem;
  package_name: string;
  version: string;
  status: string;
  error?: string | null;
  requested_at: string;
  completed_at?: string | null;
}

interface RepoContextRow {
  id: string;
  org_id: string;
  github_repo: string;
  native_dep_count: number;
  aggregate_risk_score: number;
  last_scan_at?: string | null;
  created_at: string;
}

interface BaseRepository {
  searchPackages(query?: string): Promise<ApiListResponse<SearchResult>>;
  listPackageVersions(ecosystem: Ecosystem, name: string): Promise<PackageAnalysis[]>;
  getPackage(ecosystem: Ecosystem, name: string, version?: string): Promise<PackageAnalysis | null>;
  getPackageDiff(ecosystem: Ecosystem, name: string, from: string, to: string): Promise<PackageDiff | null>;
  submitScan(request: ScanRequest, principal: AuthPrincipal): Promise<ScanJob>;
  getScanJob(id: string, orgId?: string): Promise<ScanJob | null>;
  listRepos(orgId: string): Promise<RepoRecord[]>;
  createRepo(orgId: string, githubRepo: string): Promise<RepoRecord>;
  listWatchlists(orgId: string): Promise<WatchlistSummary[]>;
  createWatchlist(orgId: string, input: { name: string; channel: WatchlistSummary["channel"]; destination: string }): Promise<WatchlistSummary>;
  addWatchlistPackage(
    orgId: string,
    watchlistId: string,
    input: { ecosystem: Ecosystem; packageName: string; version?: string }
  ): Promise<WatchlistPackageSummary>;
  listSubscriptions(orgId: string): Promise<SubscriptionSummary[]>;
  upsertSubscription(
    orgId: string,
    input: { plan: string; status: string; customerId?: string; subscriptionId?: string; currentPeriodEnd?: string; cancelAtPeriodEnd?: boolean }
  ): Promise<SubscriptionSummary>;
  listApiKeys(orgId: string): Promise<ApiKeySummary[]>;
  createApiKey(orgId: string, label: string, scopes?: string[]): Promise<{ summary: ApiKeySummary; plaintextKey: string }>;
  validateApiKey(rawKey: string): Promise<AuthPrincipal | null>;
  getOrganization(orgId: string): Promise<OrganizationSummary | null>;
  createBillingCheckout(orgId: string, plan: string): Promise<CheckoutSession>;
  getPackageAdvisories(ecosystem: Ecosystem, packageName: string): Promise<Advisory[]>;
  getRecentAdvisories(limit?: number): Promise<Advisory[]>;

  // Revocation & removal
  revokeApiKey(orgId: string, keyId: string): Promise<boolean>;
  removeWatchlistPackage(orgId: string, watchlistId: string, packageName: string): Promise<boolean>;

  // Usage tracking
  getUsageRecord(orgId: string): Promise<{ scanCount: number; repoCount: number; periodStart: string; periodEnd: string } | null>;
  incrementScanCount(orgId: string): Promise<void>;
  incrementRepoCount(orgId: string): Promise<void>;

  // Invitations
  createInvitation(orgId: string, email: string, role: string, invitedBy?: string): Promise<{ id: string; token: string; email: string; expiresAt: string }>;
  listInvitations(orgId: string): Promise<Array<{ id: string; email: string; role: string; createdAt: string; expiresAt: string; accepted: boolean }>>;
  acceptInvitation(token: string, userId: string): Promise<{ orgId: string; role: string } | null>;
}

function now() {
  return new Date().toISOString();
}

function randomId(prefix: string) {
  return `${prefix}_${crypto.randomUUID().replace(/-/g, "")}`;
}

function getCurrentPeriod(): { periodStart: string; periodEnd: string } {
  const now_ = new Date();
  const periodStart = new Date(Date.UTC(now_.getUTCFullYear(), now_.getUTCMonth(), 1)).toISOString();
  const periodEnd = new Date(Date.UTC(now_.getUTCFullYear(), now_.getUTCMonth() + 1, 1)).toISOString();
  return { periodStart, periodEnd };
}

interface UsageRecordRow {
  id: string;
  org_id: string;
  period_start: string;
  period_end: string;
  scan_count: number;
  repo_count: number;
  created_at: string;
  updated_at: string;
}

interface OrgInvitationRow {
  id: string;
  org_id: string;
  email: string;
  role: string;
  token: string;
  invited_by?: string | null;
  accepted_at?: string | null;
  expires_at: string;
  created_at: string;
}

function makeSearchResult(analysis: PackageAnalysis): SearchResult {
  return {
    ecosystem: analysis.ecosystem,
    packageName: analysis.packageName,
    latestVersion: analysis.version,
    riskLevel: analysis.riskLevel,
    riskScore: analysis.riskScore,
    summary: analysis.summary,
    binaryCount: analysis.binaryCount
  };
}

function cloneAnalysis(analysis: PackageAnalysis): PackageAnalysis {
  return {
    ...analysis,
    binaries: analysis.binaries.map((binary) => ({ ...binary, imports: [...binary.imports], strings: [...binary.strings], behaviors: { ...binary.behaviors }, findings: binary.findings.map((finding) => ({ ...finding })) }))
  };
}

class LocalRepository implements BaseRepository {
  private organizations = new Map<string, OrganizationRow>();
  private apiKeys = new Map<string, ApiKeyRow>();
  private packages = new Map<string, PackageRow>();
  private analyses = new Map<string, AnalysisRow>();
  private binaries = new Map<string, BinaryRow[]>();
  private repos = new Map<string, RepoRow>();
  private watchlists = new Map<string, WatchlistRow>();
  private watchlistPackages = new Map<string, WatchlistPackageRow[]>();
  private subscriptions = new Map<string, SubscriptionRow>();
  private jobs = new Map<string, AnalysisJobRow>();
  private usageRecords = new Map<string, UsageRecordRow>();
  private invitations = new Map<string, OrgInvitationRow>();

  constructor(private readonly env: ApiEnv) {
    const seededOrgId = "org_demo";
    const seededOrg: OrganizationRow = {
      id: seededOrgId,
      name: "BinShield Demo",
      slug: "binshield-demo",
      plan: "team",
      billing_status: "active",
      stripe_customer_id: "cus_demo",
      stripe_subscription_id: "sub_demo",
      created_at: now()
    };
    this.organizations.set(seededOrgId, seededOrg);

    const seedApiKey = this.createSeedApiKey(seededOrgId, "Demo API Key", [seededOrgId]);
    this.apiKeys.set(seedApiKey.id, seedApiKey.row);

    const seedWatchlistId = randomId("watchlist");
    this.watchlists.set(seedWatchlistId, {
      id: seedWatchlistId,
      org_id: seededOrgId,
      name: "Native packages",
      channel: "email",
      destination: "security@binshield.dev",
      created_at: now()
    });
    this.watchlistPackages.set(seedWatchlistId, [
      {
        id: randomId("watchpkg"),
        watchlist_id: seedWatchlistId,
        ecosystem: "npm",
        package_name: "bcrypt",
        version: "5.1.1",
        created_at: now()
      }
    ]);

    this.subscriptions.set(seededOrgId, {
      id: randomId("sub"),
      org_id: seededOrgId,
      provider: "stripe",
      customer_id: "cus_demo",
      subscription_id: "sub_demo",
      plan: "team",
      status: "active",
      current_period_end: new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString(),
      cancel_at_period_end: false,
      created_at: now(),
      updated_at: now()
    });

    this.repos.set("repo_demo", {
      id: "repo_demo",
      org_id: seededOrgId,
      github_repo: "ashlrai/binshield",
      native_dep_count: 3,
      aggregate_risk_score: 12,
      last_scan_at: now(),
      created_at: now()
    });

    for (const analysis of sampleAnalyses) {
      const packageId = randomId("pkg");
      this.packages.set(this.packageKey(analysis.ecosystem, analysis.packageName), {
        id: packageId,
        ecosystem: analysis.ecosystem,
        name: analysis.packageName,
        latest_analyzed_version: analysis.version,
        total_versions_analyzed: 1,
        created_at: analysis.createdAt
      });
      this.analyses.set(this.analysisKey(packageId, analysis.version), {
        id: analysis.id,
        package_id: packageId,
        version: analysis.version,
        status: analysis.status,
        risk_score: analysis.riskScore,
        risk_level: analysis.riskLevel,
        summary: analysis.summary,
        source_match_confidence: analysis.sourceMatchConfidence,
          behaviors: analysis.binaries[0]?.behaviors ?? {
            network: { detected: false, details: [] },
            filesystem: { detected: false, details: [] },
            process: { detected: false, details: [] },
            crypto: { detected: false, details: [] },
            obfuscation: { detected: false, details: [] },
            dataExfiltration: { detected: false, details: [] }
          },
          findings: analysis.binaries[0]?.findings ?? [],
        binary_count: analysis.binaryCount,
        total_binary_size: analysis.totalBinarySize,
        ghidra_version: "11.3.0",
        ai_model: analysis.aiModel,
        analysis_duration_ms: 1200,
        created_at: analysis.createdAt
      });
      this.binaries.set(
        analysis.id,
        analysis.binaries.map((binary) => ({
          id: binary.id,
          analysis_id: analysis.id,
          filename: binary.filename,
          architecture: binary.architecture,
          format: binary.format,
          file_size: binary.fileSize,
          function_count: binary.functionCount,
          import_count: binary.importCount,
          risk_score: binary.riskScore,
          risk_level: binary.riskLevel,
          decompiled_preview: binary.decompiledPreview,
          ai_explanation: binary.aiExplanation,
          imports: [...binary.imports],
          strings: [...binary.strings],
          behaviors: { ...binary.behaviors },
          findings: binary.findings.map((finding) => ({ ...finding })),
          created_at: analysis.createdAt
        }))
      );
    }
  }

  private packageKey(ecosystem: Ecosystem, name: string) {
    return `${ecosystem}:${name}`;
  }

  private analysisKey(packageId: string, version: string) {
    return `${packageId}:${version}`;
  }

  private createSeedApiKey(orgId: string, label: string, scopes: string[]) {
    const plaintextKey = this.env.demoApiKey;
    const row: ApiKeyRow = {
      id: randomId("key"),
      org_id: orgId,
      label,
      prefix: plaintextKey.slice(0, 8),
      hashed_key: hashApiKey(plaintextKey),
      scopes,
      created_at: now(),
      last_used_at: now(),
      revoked_at: null
    };

    return { id: row.id, row, plaintextKey };
  }

  private getPackageRow(ecosystem: Ecosystem, name: string) {
    return this.packages.get(this.packageKey(ecosystem, name));
  }

  private getAnalysisRows(packageRow: PackageRow) {
    return Array.from(this.analyses.values())
      .filter((analysis) => analysis.package_id === packageRow.id)
      .sort((left, right) => right.version.localeCompare(left.version, undefined, { numeric: true }));
  }

  private getBinaryRows(analysisId: string) {
    return this.binaries.get(analysisId) ?? [];
  }

  private toPackageAnalysis(packageRow: PackageRow, analysisRow: AnalysisRow): PackageAnalysis {
    const binaries = this.getBinaryRows(analysisRow.id).map((binary) => ({
      id: binary.id,
      filename: binary.filename,
      architecture: binary.architecture ?? "unknown",
      format: (binary.format ?? "unknown") as PackageAnalysis["binaries"][number]["format"],
      fileSize: binary.file_size,
      functionCount: binary.function_count,
      importCount: binary.import_count,
      riskScore: binary.risk_score,
      riskLevel: binary.risk_level as PackageAnalysis["riskLevel"],
      decompiledPreview: binary.decompiled_preview,
      aiExplanation: binary.ai_explanation,
      imports: [...binary.imports],
      strings: [...binary.strings],
      behaviors: binary.behaviors as PackageAnalysis["binaries"][number]["behaviors"],
      findings: binary.findings as PackageAnalysis["binaries"][number]["findings"]
    }));

    return {
      id: analysisRow.id,
      ecosystem: packageRow.ecosystem,
      packageName: packageRow.name,
      version: analysisRow.version,
      status: analysisRow.status as PackageAnalysis["status"],
      riskScore: analysisRow.risk_score,
      riskLevel: analysisRow.risk_level as PackageAnalysis["riskLevel"],
      summary: analysisRow.summary,
      sourceMatchConfidence: analysisRow.source_match_confidence,
      binaryCount: analysisRow.binary_count,
      totalBinarySize: analysisRow.total_binary_size,
      aiModel: analysisRow.ai_model ?? "claude-sonnet",
      createdAt: analysisRow.created_at,
      binaries
    };
  }

  async searchPackages(query?: string) {
    const packages = Array.from(this.packages.values())
      .filter((pkg) => !query || pkg.name.toLowerCase().includes(query.toLowerCase()))
      .map((pkg) => {
        const analysis = this.getAnalysisRows(pkg)[0];
        if (!analysis) {
          return undefined;
        }

        return makeSearchResult(this.toPackageAnalysis(pkg, analysis));
      })
      .filter(Boolean) as SearchResult[];

    return { items: packages, total: packages.length };
  }

  async listPackageVersions(ecosystem: Ecosystem, name: string) {
    const packageRow = this.getPackageRow(ecosystem, name);
    if (!packageRow) {
      return [];
    }

    return this.getAnalysisRows(packageRow).map((analysis) => this.toPackageAnalysis(packageRow, analysis));
  }

  async getPackage(ecosystem: Ecosystem, name: string, version?: string) {
    const packageRow = this.getPackageRow(ecosystem, name);
    if (!packageRow) {
      return null;
    }

    const analysisRow = version
      ? this.analyses.get(this.analysisKey(packageRow.id, version))
      : this.getAnalysisRows(packageRow)[0];

    if (!analysisRow) {
      return null;
    }

    return this.toPackageAnalysis(packageRow, analysisRow);
  }

  async getPackageDiff(ecosystem: Ecosystem, name: string, from: string, to: string) {
    const versions = await this.listPackageVersions(ecosystem, name);
    const fromAnalysis = versions.find((analysis) => analysis.version === from);
    const toAnalysis = versions.find((analysis) => analysis.version === to);
    if (!fromAnalysis || !toAnalysis) {
      return null;
    }

    return {
      packageName: name,
      ecosystem,
      fromVersion: from,
      toVersion: to,
      riskDelta: toAnalysis.riskScore - fromAnalysis.riskScore,
      summary: `${name}@${to} changed overall risk from ${fromAnalysis.riskLevel} to ${toAnalysis.riskLevel}.`,
      addedBehaviors: toAnalysis.binaries.flatMap((binary) =>
        Object.entries(binary.behaviors)
          .filter(([, signal]) => signal.detected)
          .map(([behavior]) => behavior)
          .filter((behavior) => !fromAnalysis.binaries.some((candidate) => candidate.behaviors[behavior as keyof typeof candidate.behaviors]?.detected))
      ),
      removedBehaviors: []
    };
  }

  async submitScan(request: ScanRequest, principal: AuthPrincipal): Promise<ScanJob> {
    const jobId = randomId("job");
    const analysis = await this.getPackage(request.ecosystem, request.packageName, request.version);
    const job: AnalysisJobRow = {
      id: jobId,
      org_id: principal.orgId,
      ecosystem: request.ecosystem,
      package_name: request.packageName,
      version: request.version,
      status: analysis ? "complete" : "queued",
      requested_at: now(),
      completed_at: analysis ? now() : null,
      error: null
    };
    this.jobs.set(jobId, job);

    if (analysis) {
      const jobWithResult: ScanJob = {
        id: job.id,
        status: "complete",
        requestedAt: job.requested_at,
        completedAt: job.completed_at ?? undefined,
        request,
        result: analysis
      };
      return jobWithResult;
    }

    return {
      id: job.id,
      status: "queued" as const,
      requestedAt: job.requested_at,
      request
    };
  }

  async getScanJob(id: string, orgId?: string) {
    const job = this.jobs.get(id);
    if (!job) {
      return null;
    }

    if (orgId && job.org_id !== orgId) {
      return null;
    }

    const request: ScanRequest = {
      ecosystem: job.ecosystem,
      packageName: job.package_name,
      version: job.version
    };
    const analysis = await this.getPackage(job.ecosystem, job.package_name, job.version);

    if (job.status === "queued" && analysis) {
      const completeJob: ScanJob = {
        id: job.id,
        status: "complete",
        requestedAt: job.requested_at,
        completedAt: now(),
        request,
        result: analysis
      };
      this.jobs.set(id, {
        ...job,
        status: "complete",
        completed_at: completeJob.completedAt
      });
      return completeJob;
    }

    return {
      id: job.id,
      status: job.status as ScanJob["status"],
      requestedAt: job.requested_at,
      completedAt: job.completed_at ?? undefined,
      request,
      error: job.error ?? undefined,
      result: analysis ?? undefined
    };
  }

  async listRepos(orgId: string) {
    return Array.from(this.repos.values())
      .filter((repo) => repo.org_id === orgId)
      .map((repo) => ({
        id: repo.id,
        orgId: repo.org_id,
        githubRepo: repo.github_repo,
        nativeDependencyCount: repo.native_dep_count,
        aggregateRiskScore: repo.aggregate_risk_score,
        lastScanAt: repo.last_scan_at ?? undefined
      }));
  }

  async createRepo(orgId: string, githubRepo: string) {
    const row: RepoRow = {
      id: randomId("repo"),
      org_id: orgId,
      github_repo: githubRepo,
      native_dep_count: 0,
      aggregate_risk_score: 0,
      last_scan_at: null,
      created_at: now()
    };
    this.repos.set(row.id, row);
    return {
      id: row.id,
      orgId: row.org_id,
      githubRepo: row.github_repo,
      nativeDependencyCount: row.native_dep_count,
      aggregateRiskScore: row.aggregate_risk_score,
      lastScanAt: undefined
    };
  }

  async listWatchlists(orgId: string) {
    return Array.from(this.watchlists.values())
      .filter((watchlist) => watchlist.org_id === orgId)
      .map((watchlist) => ({
        id: watchlist.id,
        orgId: watchlist.org_id,
        name: watchlist.name,
        channel: watchlist.channel,
        destination: watchlist.destination,
        createdAt: watchlist.created_at,
        packageCount: this.watchlistPackages.get(watchlist.id)?.length ?? 0
      }));
  }

  async createWatchlist(orgId: string, input: { name: string; channel: WatchlistSummary["channel"]; destination: string }) {
    const row: WatchlistRow = {
      id: randomId("watchlist"),
      org_id: orgId,
      name: input.name,
      channel: input.channel,
      destination: input.destination,
      created_at: now()
    };
    this.watchlists.set(row.id, row);
    this.watchlistPackages.set(row.id, []);

    return {
      id: row.id,
      orgId: row.org_id,
      name: row.name,
      channel: row.channel,
      destination: row.destination,
      createdAt: row.created_at,
      packageCount: 0
    };
  }

  async addWatchlistPackage(
    orgId: string,
    watchlistId: string,
    input: { ecosystem: Ecosystem; packageName: string; version?: string }
  ) {
    const watchlist = this.watchlists.get(watchlistId);
    if (!watchlist || watchlist.org_id !== orgId) {
      throw new Error("Watchlist not found");
    }

    const row: WatchlistPackageRow = {
      id: randomId("watchpkg"),
      watchlist_id: watchlistId,
      ecosystem: input.ecosystem,
      package_name: input.packageName,
      version: input.version ?? null,
      created_at: now()
    };
    this.watchlistPackages.set(watchlistId, [...(this.watchlistPackages.get(watchlistId) ?? []), row]);

    return {
      id: row.id,
      watchlistId: row.watchlist_id,
      ecosystem: row.ecosystem,
      packageName: row.package_name,
      version: row.version ?? undefined,
      createdAt: row.created_at
    };
  }

  async listSubscriptions(orgId: string) {
    const subscription = this.subscriptions.get(orgId);
    if (!subscription) {
      return [];
    }

    return [
      {
        id: subscription.id,
        orgId: subscription.org_id,
        provider: subscription.provider,
        plan: subscription.plan,
        status: subscription.status,
        currentPeriodEnd: subscription.current_period_end ?? undefined,
        cancelAtPeriodEnd: subscription.cancel_at_period_end,
        createdAt: subscription.created_at,
        updatedAt: subscription.updated_at
      }
    ];
  }

  async upsertSubscription(
    orgId: string,
    input: { plan: string; status: string; customerId?: string; subscriptionId?: string; currentPeriodEnd?: string; cancelAtPeriodEnd?: boolean }
  ) {
    const row: SubscriptionRow = {
      id: this.subscriptions.get(orgId)?.id ?? randomId("sub"),
      org_id: orgId,
      provider: input.customerId || input.subscriptionId ? "stripe" : "manual",
      customer_id: input.customerId ?? this.subscriptions.get(orgId)?.customer_id ?? null,
      subscription_id: input.subscriptionId ?? this.subscriptions.get(orgId)?.subscription_id ?? null,
      plan: input.plan,
      status: input.status,
      current_period_end: input.currentPeriodEnd ?? this.subscriptions.get(orgId)?.current_period_end ?? null,
      cancel_at_period_end: input.cancelAtPeriodEnd ?? false,
      created_at: this.subscriptions.get(orgId)?.created_at ?? now(),
      updated_at: now()
    };
    this.subscriptions.set(orgId, row);

    return {
      id: row.id,
      orgId: row.org_id,
      provider: row.provider,
      plan: row.plan,
      status: row.status,
      currentPeriodEnd: row.current_period_end ?? undefined,
      cancelAtPeriodEnd: row.cancel_at_period_end,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  async listApiKeys(orgId: string) {
    return Array.from(this.apiKeys.values())
      .filter((key) => key.org_id === orgId && !key.revoked_at)
      .map((key) => ({
        id: key.id,
        label: key.label,
        prefix: key.prefix,
        createdAt: key.created_at,
        lastUsedAt: key.last_used_at ?? undefined
      }));
  }

  async createApiKey(orgId: string, label: string, scopes: string[] = [orgId]) {
    const plaintextKey = `bsk_${crypto.randomBytes(24).toString("hex")}`;
    const row: ApiKeyRow = {
      id: randomId("key"),
      org_id: orgId,
      label,
      prefix: plaintextKey.slice(0, 8),
      hashed_key: hashApiKey(plaintextKey),
      scopes,
      created_at: now(),
      last_used_at: null,
      revoked_at: null
    };
    this.apiKeys.set(row.id, row);

    return {
      summary: {
        id: row.id,
        label: row.label,
        prefix: row.prefix,
        createdAt: row.created_at
      },
      plaintextKey
    };
  }

  async revokeApiKey(orgId: string, keyId: string): Promise<boolean> {
    const key = this.apiKeys.get(keyId);
    if (!key || key.org_id !== orgId || key.revoked_at) return false;
    key.revoked_at = now();
    return true;
  }

  async removeWatchlistPackage(orgId: string, watchlistId: string, packageName: string): Promise<boolean> {
    const watchlist = Array.from(this.watchlists.values()).find((w) => w.id === watchlistId && w.org_id === orgId);
    if (!watchlist) return false;
    const packages = this.watchlistPackages.get(watchlistId) ?? [];
    const idx = packages.findIndex((p) => p.package_name === packageName);
    if (idx === -1) return false;
    packages.splice(idx, 1);
    this.watchlistPackages.set(watchlistId, packages);
    return true;
  }

  async validateApiKey(rawKey: string) {
    const hashed = hashApiKey(rawKey);
    const key = Array.from(this.apiKeys.values()).find((row) => row.hashed_key === hashed && !row.revoked_at);
    if (!key) {
      return null;
    }

    key.last_used_at = now();

    return {
      apiKeyId: key.id,
      orgId: key.org_id,
      label: key.label,
      scopes: key.scopes
    };
  }

  async getOrganization(orgId: string) {
    const org = this.organizations.get(orgId);
    if (!org) {
      return null;
    }

    return {
      id: org.id,
      name: org.name,
      slug: org.slug,
      plan: org.plan,
      billingStatus: org.billing_status,
      createdAt: org.created_at
    };
  }

  async createBillingCheckout(orgId: string, plan: string): Promise<CheckoutSession> {
    const subscriptionId = randomId("sub");
    this.subscriptions.set(orgId, {
      id: subscriptionId,
      org_id: orgId,
      provider: "stripe",
      customer_id: `cus_${orgId}`,
      subscription_id: subscriptionId,
      plan,
      status: "pending",
      current_period_end: null,
      cancel_at_period_end: false,
      created_at: now(),
      updated_at: now()
    });

    return {
      checkoutUrl: `${this.env.publicAppUrl}/billing/checkout/${subscriptionId}`,
      customerId: `cus_${orgId}`,
      subscriptionId,
      plan,
      status: "pending" as const
    };
  }

  private readonly sampleAdvisories: Advisory[] = [
    {
      id: "adv_1", source: "osv", sourceId: "GHSA-3vjf-4m89-5hcr",
      title: "bcrypt timing attack in comparison function",
      description: "Versions of bcrypt prior to 5.1.1 are vulnerable to timing attacks when comparing hashes, potentially allowing attackers to determine password validity.",
      severity: "medium", cvssScore: 5.3, cweIds: ["CWE-208"],
      publishedAt: "2025-11-15T00:00:00Z", references: [{ type: "advisory", url: "https://github.com/advisories/GHSA-3vjf-4m89-5hcr" }],
      affectedPackages: [{ ecosystem: "npm", packageName: "bcrypt", vulnerableRange: "<5.1.1", patchedVersion: "5.1.1" }]
    },
    {
      id: "adv_2", source: "ghsa", sourceId: "GHSA-qhvf-7gv8-xr9m",
      title: "sharp libvips heap buffer overflow via crafted image",
      description: "The sharp image processing library uses libvips which has a heap buffer overflow vulnerability when processing specially crafted images.",
      severity: "high", cvssScore: 7.5, cweIds: ["CWE-122"],
      publishedAt: "2025-12-03T00:00:00Z", references: [{ type: "advisory", url: "https://github.com/advisories/GHSA-qhvf-7gv8-xr9m" }],
      affectedPackages: [{ ecosystem: "npm", packageName: "sharp", vulnerableRange: "<0.33.2", patchedVersion: "0.33.2" }]
    },
    {
      id: "adv_3", source: "nvd", sourceId: "CVE-2025-1234",
      title: "sqlite3 use-after-free in FTS5 extension",
      description: "SQLite versions before 3.45.1 contain a use-after-free vulnerability in the FTS5 full-text search extension that could be exploited for code execution.",
      severity: "critical", cvssScore: 9.8, cweIds: ["CWE-416"],
      publishedAt: "2026-01-20T00:00:00Z", references: [{ type: "advisory", url: "https://nvd.nist.gov/vuln/detail/CVE-2025-1234" }],
      affectedPackages: [{ ecosystem: "npm", packageName: "sqlite3", vulnerableRange: "<5.1.8", patchedVersion: "5.1.8" }]
    },
    {
      id: "adv_4", source: "osv", sourceId: "GHSA-wm63-7627-ch33",
      title: "node-canvas out-of-bounds write via SVG parsing",
      description: "node-canvas versions before 2.11.3 are vulnerable to an out-of-bounds write when parsing malicious SVG content via cairo.",
      severity: "high", cvssScore: 8.1, cweIds: ["CWE-787"],
      publishedAt: "2026-02-10T00:00:00Z", references: [{ type: "advisory", url: "https://github.com/advisories/GHSA-wm63-7627-ch33" }],
      affectedPackages: [{ ecosystem: "npm", packageName: "canvas", vulnerableRange: "<2.11.3", patchedVersion: "2.11.3" }]
    },
    {
      id: "adv_5", source: "ghsa", sourceId: "GHSA-5g9f-524r-2jhl",
      title: "argon2 integer overflow in memory allocation",
      description: "The argon2 npm package has an integer overflow in the memory parameter handling that could lead to denial of service or reduced security.",
      severity: "medium", cvssScore: 6.5, cweIds: ["CWE-190"],
      publishedAt: "2026-03-01T00:00:00Z", references: [{ type: "advisory", url: "https://github.com/advisories/GHSA-5g9f-524r-2jhl" }],
      affectedPackages: [{ ecosystem: "npm", packageName: "argon2", vulnerableRange: "<0.41.0", patchedVersion: "0.41.0" }]
    }
  ];

  async getPackageAdvisories(ecosystem: Ecosystem, packageName: string): Promise<Advisory[]> {
    return this.sampleAdvisories.filter((a) =>
      a.affectedPackages?.some((ap) => ap.ecosystem === ecosystem && ap.packageName === packageName)
    );
  }

  async getRecentAdvisories(limit = 50): Promise<Advisory[]> {
    return this.sampleAdvisories.slice(0, limit);
  }

  // Usage tracking

  private getOrCreateUsageRecord(orgId: string): UsageRecordRow {
    const { periodStart, periodEnd } = getCurrentPeriod();
    const key = `${orgId}:${periodStart}`;
    let record = this.usageRecords.get(key);
    if (!record) {
      record = {
        id: randomId("usage"),
        org_id: orgId,
        period_start: periodStart,
        period_end: periodEnd,
        scan_count: 0,
        repo_count: 0,
        created_at: now(),
        updated_at: now()
      };
      this.usageRecords.set(key, record);
    }
    return record;
  }

  async getUsageRecord(orgId: string) {
    const record = this.getOrCreateUsageRecord(orgId);
    return {
      scanCount: record.scan_count,
      repoCount: record.repo_count,
      periodStart: record.period_start,
      periodEnd: record.period_end
    };
  }

  async incrementScanCount(orgId: string) {
    const record = this.getOrCreateUsageRecord(orgId);
    record.scan_count += 1;
    record.updated_at = now();
  }

  async incrementRepoCount(orgId: string) {
    const record = this.getOrCreateUsageRecord(orgId);
    record.repo_count += 1;
    record.updated_at = now();
  }

  // Invitations

  async createInvitation(orgId: string, email: string, role: string, invitedBy?: string) {
    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    const row: OrgInvitationRow = {
      id: randomId("inv"),
      org_id: orgId,
      email,
      role,
      token,
      invited_by: invitedBy ?? null,
      accepted_at: null,
      expires_at: expiresAt,
      created_at: now()
    };
    this.invitations.set(token, row);

    return {
      id: row.id,
      token: row.token,
      email: row.email,
      expiresAt: row.expires_at
    };
  }

  async listInvitations(orgId: string) {
    return Array.from(this.invitations.values())
      .filter((inv) => inv.org_id === orgId)
      .map((inv) => ({
        id: inv.id,
        email: inv.email,
        role: inv.role,
        createdAt: inv.created_at,
        expiresAt: inv.expires_at,
        accepted: inv.accepted_at !== null
      }));
  }

  async acceptInvitation(token: string, userId: string) {
    const inv = this.invitations.get(token);
    if (!inv) {
      return null;
    }

    if (inv.accepted_at) {
      return null;
    }

    if (new Date(inv.expires_at) < new Date()) {
      return null;
    }

    inv.accepted_at = now();
    return { orgId: inv.org_id, role: inv.role };
  }
}

interface AdvisoryRow {
  id: string;
  source: string;
  source_id: string;
  title: string;
  description?: string | null;
  severity?: string | null;
  cvss_score?: number | null;
  cvss_vector?: string | null;
  cwe_ids: string[];
  published_at?: string | null;
  updated_at?: string | null;
  withdrawn_at?: string | null;
  references: Array<{ type?: string; url: string }>;
  raw_data?: unknown;
  created_at: string;
}

interface PackageAdvisoryRow {
  id: string;
  advisory_id: string;
  ecosystem: string;
  package_name: string;
  vulnerable_range?: string | null;
  patched_version?: string | null;
  created_at: string;
}

class SupabaseRepository implements BaseRepository {
  constructor(private readonly env: ApiEnv) {}

  private get baseUrl() {
    if (!this.env.supabaseUrl || !this.env.supabaseServiceRoleKey) {
      throw new Error("Supabase is not configured");
    }
    return this.env.supabaseUrl.replace(/\/$/, "");
  }

  private headers(extra: Record<string, string> = {}) {
    return {
      apikey: this.env.supabaseServiceRoleKey ?? "",
      authorization: `Bearer ${this.env.supabaseServiceRoleKey ?? ""}`,
      "content-type": "application/json",
      ...extra
    };
  }

  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const headers = new Headers(this.headers());
    if (init.headers) {
      new Headers(init.headers).forEach((value, key) => headers.set(key, value));
    }
    const response = await fetch(`${this.baseUrl}/rest/v1${path}`, {
      ...init,
      headers
    });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Supabase request failed (${response.status}): ${text}`);
    }
    if (response.status === 204) {
      return undefined as T;
    }
    return (await response.json()) as T;
  }

  private async select<T>(table: string, query = "") {
    const path = `/${table}${query.startsWith("?") ? query : `?${query}`}`;
    return this.request<T[]>(path, { method: "GET" });
  }

  private async insert<T>(table: string, row: unknown) {
    return this.request<T[]>(`/${table}?select=*`, {
      method: "POST",
      headers: {
        Prefer: "return=representation"
      },
      body: JSON.stringify(row)
    });
  }

  async searchPackages(query?: string) {
    const rows = await this.select<PackageRow>("packages", query ? `select=*&name=ilike.*${encodeURIComponent(query)}*` : "select=*");
    const items: SearchResult[] = [];
    for (const pkg of rows) {
      const analysis = await this.getPackage(pkg.ecosystem, pkg.name, pkg.latest_analyzed_version ?? undefined);
      if (analysis) {
        items.push(makeSearchResult(analysis));
      }
    }
    return { items, total: items.length };
  }

  async listPackageVersions(ecosystem: Ecosystem, name: string) {
    const packageRows = await this.select<PackageRow>("packages", `select=*&ecosystem=eq.${ecosystem}&name=eq.${encodeURIComponent(name)}`);
    const packageRow = packageRows[0];
    if (!packageRow) {
      return [];
    }
    const analyses = await this.select<AnalysisRow>("analyses", `select=*&package_id=eq.${packageRow.id}&order=created_at.desc`);
    const binaryFilter = analyses.map((analysis) => analysis.id).join(",");
    const binaries = binaryFilter
      ? await this.select<BinaryRow>("binaries", `select=*&analysis_id=in.(${binaryFilter})`)
      : [];
    return analyses.map((analysis) => this.mapAnalysis(packageRow, analysis, binaries.filter((binary) => binary.analysis_id === analysis.id)));
  }

  private mapAnalysis(packageRow: PackageRow, analysisRow: AnalysisRow, binaryRows: BinaryRow[]) {
    return {
      id: analysisRow.id,
      ecosystem: packageRow.ecosystem,
      packageName: packageRow.name,
      version: analysisRow.version,
      status: analysisRow.status as PackageAnalysis["status"],
      riskScore: analysisRow.risk_score,
      riskLevel: analysisRow.risk_level as PackageAnalysis["riskLevel"],
      summary: analysisRow.summary,
      sourceMatchConfidence: analysisRow.source_match_confidence,
      binaryCount: analysisRow.binary_count,
      totalBinarySize: analysisRow.total_binary_size,
      aiModel: analysisRow.ai_model ?? "claude-sonnet",
      createdAt: analysisRow.created_at,
      binaries: binaryRows.map((binary) => ({
        id: binary.id,
        filename: binary.filename,
        architecture: binary.architecture ?? "unknown",
        format: (binary.format ?? "unknown") as PackageAnalysis["binaries"][number]["format"],
        fileSize: binary.file_size,
        functionCount: binary.function_count,
        importCount: binary.import_count,
        riskScore: binary.risk_score,
        riskLevel: binary.risk_level as PackageAnalysis["binaries"][number]["riskLevel"],
        decompiledPreview: binary.decompiled_preview,
        aiExplanation: binary.ai_explanation,
        imports: binary.imports,
        strings: binary.strings,
        behaviors: binary.behaviors as PackageAnalysis["binaries"][number]["behaviors"],
        findings: binary.findings as PackageAnalysis["binaries"][number]["findings"]
      }))
    } satisfies PackageAnalysis;
  }

  async getPackage(ecosystem: Ecosystem, name: string, version?: string) {
    const packageRows = await this.select<PackageRow>("packages", `select=*&ecosystem=eq.${ecosystem}&name=eq.${encodeURIComponent(name)}`);
    const packageRow = packageRows[0];
    if (!packageRow) {
      return null;
    }

    const analyses = await this.select<AnalysisRow>("analyses", `select=*&package_id=eq.${packageRow.id}&order=created_at.desc`);
    const analysisRow = version ? analyses.find((analysis) => analysis.version === version) : analyses[0];
    if (!analysisRow) {
      return null;
    }

    const binaryRows = await this.select<BinaryRow>("binaries", `select=*&analysis_id=eq.${analysisRow.id}`);
    return this.mapAnalysis(packageRow, analysisRow, binaryRows);
  }

  async getPackageDiff(ecosystem: Ecosystem, name: string, from: string, to: string) {
    const versions = await this.listPackageVersions(ecosystem, name);
    const fromAnalysis = versions.find((analysis) => analysis.version === from);
    const toAnalysis = versions.find((analysis) => analysis.version === to);
    if (!fromAnalysis || !toAnalysis) {
      return null;
    }
    return {
      packageName: name,
      ecosystem,
      fromVersion: from,
      toVersion: to,
      riskDelta: toAnalysis.riskScore - fromAnalysis.riskScore,
      summary: `${name}@${to} changed overall risk from ${fromAnalysis.riskLevel} to ${toAnalysis.riskLevel}.`,
      addedBehaviors: [],
      removedBehaviors: []
    };
  }

  async submitScan(request: ScanRequest, principal: AuthPrincipal): Promise<ScanJob> {
    const existing = await this.getPackage(request.ecosystem, request.packageName, request.version);
    const [created] = await this.insert<AnalysisJobRow>("analysis_jobs", {
      org_id: principal.orgId,
      ecosystem: request.ecosystem,
      package_name: request.packageName,
      version: request.version,
      status: existing ? "complete" : "queued",
      error: null,
      requested_at: now(),
      completed_at: existing ? now() : null
    });

    if (existing) {
      return {
        id: created.id,
        status: "complete" as const,
        requestedAt: created.requested_at,
        completedAt: created.completed_at ?? undefined,
        request,
        result: existing
      };
    }

    return {
      id: created.id,
      status: "queued" as const,
      requestedAt: created.requested_at,
      request
    };
  }

  async getScanJob(id: string, orgId?: string) {
    const rows = await this.select<AnalysisJobRow>("analysis_jobs", `select=*&id=eq.${id}${orgId ? `&org_id=eq.${orgId}` : ""}`);
    const job = rows[0];
    if (!job) {
      return null;
    }
    const analysis = await this.getPackage(job.ecosystem, job.package_name, job.version);
    return {
      id: job.id,
      status: job.status as ScanJob["status"],
      requestedAt: job.requested_at,
      completedAt: job.completed_at ?? undefined,
      request: {
        ecosystem: job.ecosystem,
        packageName: job.package_name,
        version: job.version
      },
      error: job.error ?? undefined,
      result: analysis ?? undefined
    };
  }

  async listRepos(orgId: string) {
    const rows = await this.select<RepoContextRow>("repos", `select=*&org_id=eq.${orgId}`);
    return rows.map((repo) => ({
      id: repo.id,
      orgId: repo.org_id,
      githubRepo: repo.github_repo,
      nativeDependencyCount: repo.native_dep_count,
      aggregateRiskScore: repo.aggregate_risk_score,
      lastScanAt: repo.last_scan_at ?? undefined
    }));
  }

  async createRepo(orgId: string, githubRepo: string) {
    const [row] = await this.insert<RepoContextRow>("repos", {
      org_id: orgId,
      github_repo: githubRepo,
      native_dep_count: 0,
      aggregate_risk_score: 0,
      last_scan_at: null
    });
    return {
      id: row.id,
      orgId: row.org_id,
      githubRepo: row.github_repo,
      nativeDependencyCount: row.native_dep_count,
      aggregateRiskScore: row.aggregate_risk_score,
      lastScanAt: row.last_scan_at ?? undefined
    };
  }

  async listWatchlists(orgId: string) {
    const rows = await this.select<WatchlistRow>("watchlists", `select=*&org_id=eq.${orgId}`);
    return rows.map((watchlist) => ({
      id: watchlist.id,
      orgId: watchlist.org_id,
      name: watchlist.name,
      channel: watchlist.channel,
      destination: watchlist.destination,
      createdAt: watchlist.created_at,
      packageCount: 0
    }));
  }

  async createWatchlist(orgId: string, input: { name: string; channel: WatchlistSummary["channel"]; destination: string }) {
    const [row] = await this.insert<WatchlistRow>("watchlists", {
      org_id: orgId,
      name: input.name,
      channel: input.channel,
      destination: input.destination
    });
    return {
      id: row.id,
      orgId: row.org_id,
      name: row.name,
      channel: row.channel,
      destination: row.destination,
      createdAt: row.created_at,
      packageCount: 0
    };
  }

  async addWatchlistPackage(
    orgId: string,
    watchlistId: string,
    input: { ecosystem: Ecosystem; packageName: string; version?: string }
  ) {
    const [row] = await this.insert<WatchlistPackageRow>("watchlist_packages", {
      watchlist_id: watchlistId,
      ecosystem: input.ecosystem,
      package_name: input.packageName,
      version: input.version ?? null
    });
    return {
      id: row.id,
      watchlistId: row.watchlist_id,
      ecosystem: row.ecosystem,
      packageName: row.package_name,
      version: row.version ?? undefined,
      createdAt: row.created_at
    };
  }

  async listSubscriptions(orgId: string) {
    const rows = await this.select<SubscriptionRow>("subscriptions", `select=*&org_id=eq.${orgId}`);
    return rows.map((row) => ({
      id: row.id,
      orgId: row.org_id,
      provider: row.provider,
      plan: row.plan,
      status: row.status,
      currentPeriodEnd: row.current_period_end ?? undefined,
      cancelAtPeriodEnd: row.cancel_at_period_end,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    }));
  }

  async upsertSubscription(
    orgId: string,
    input: { plan: string; status: string; customerId?: string; subscriptionId?: string; currentPeriodEnd?: string; cancelAtPeriodEnd?: boolean }
  ) {
    const [row] = await this.request<SubscriptionRow[]>(`/subscriptions?select=*&on_conflict=org_id`, {
      method: "POST",
      headers: { Prefer: "resolution=merge-duplicates,return=representation" },
      body: JSON.stringify({
        org_id: orgId,
        provider: input.customerId || input.subscriptionId ? "stripe" : "manual",
        customer_id: input.customerId ?? null,
        subscription_id: input.subscriptionId ?? null,
        plan: input.plan,
        status: input.status,
        current_period_end: input.currentPeriodEnd ?? null,
        cancel_at_period_end: input.cancelAtPeriodEnd ?? false,
        updated_at: now()
      })
    });
    return {
      id: row.id,
      orgId: row.org_id,
      provider: row.provider,
      plan: row.plan,
      status: row.status,
      currentPeriodEnd: row.current_period_end ?? undefined,
      cancelAtPeriodEnd: row.cancel_at_period_end,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  async listApiKeys(orgId: string) {
    const rows = await this.select<ApiKeyRow>("api_keys", `select=*&org_id=eq.${orgId}&revoked_at=is.null`);
    return rows.map((key) => ({
      id: key.id,
      label: key.label,
      prefix: key.prefix,
      createdAt: key.created_at,
      lastUsedAt: key.last_used_at ?? undefined
    }));
  }

  async createApiKey(orgId: string, label: string, scopes: string[] = [orgId]) {
    const plaintextKey = `bsk_${crypto.randomBytes(24).toString("hex")}`;
    const [row] = await this.insert<ApiKeyRow>("api_keys", {
      org_id: orgId,
      label,
      prefix: plaintextKey.slice(0, 8),
      hashed_key: hashApiKey(plaintextKey),
      scopes
    });
    return {
      summary: {
        id: row.id,
        label: row.label,
        prefix: row.prefix,
        createdAt: row.created_at
      },
      plaintextKey
    };
  }

  async revokeApiKey(orgId: string, keyId: string): Promise<boolean> {
    try {
      await this.request<unknown>(
        `/api_keys?id=eq.${keyId}&org_id=eq.${orgId}&revoked_at=is.null`,
        {
          method: "PATCH",
          headers: { Prefer: "return=minimal" },
          body: JSON.stringify({ revoked_at: now() })
        }
      );
      return true;
    } catch {
      return false;
    }
  }

  async removeWatchlistPackage(orgId: string, watchlistId: string, packageName: string): Promise<boolean> {
    // Verify the watchlist belongs to this org
    const watchlists = await this.select<WatchlistRow>("watchlists", `select=id&id=eq.${watchlistId}&org_id=eq.${orgId}`);
    if (!watchlists.length) return false;
    try {
      await this.request<unknown>(
        `/watchlist_packages?watchlist_id=eq.${watchlistId}&package_name=eq.${encodeURIComponent(packageName)}`,
        { method: "DELETE" }
      );
      return true;
    } catch {
      return false;
    }
  }

  async validateApiKey(rawKey: string) {
    const hashed = hashApiKey(rawKey);
    const rows = await this.select<ApiKeyRow>("api_keys", `select=*&hashed_key=eq.${hashed}&revoked_at=is.null`);
    const key = rows[0];
    if (!key) {
      return null;
    }
    return {
      apiKeyId: key.id,
      orgId: key.org_id,
      label: key.label,
      scopes: key.scopes
    };
  }

  async getOrganization(orgId: string) {
    const rows = await this.select<OrganizationRow>("organizations", `select=*&id=eq.${orgId}`);
    const org = rows[0];
    if (!org) {
      return null;
    }
    return {
      id: org.id,
      name: org.name,
      slug: org.slug,
      plan: org.plan,
      billingStatus: org.billing_status,
      createdAt: org.created_at
    };
  }

  async createBillingCheckout(orgId: string, plan: string): Promise<CheckoutSession> {
    const [organization] = await this.select<OrganizationRow>("organizations", `select=*&id=eq.${orgId}`);
    const subscriptionId = randomId("sub");
    await this.insert<SubscriptionRow>("subscriptions", {
      org_id: orgId,
      provider: "stripe",
      customer_id: organization?.stripe_customer_id ?? `cus_${orgId}`,
      subscription_id: subscriptionId,
      plan,
      status: "pending",
      current_period_end: null,
      cancel_at_period_end: false
    });
    return {
      checkoutUrl: `${this.env.publicAppUrl}/billing/checkout/${subscriptionId}`,
      customerId: organization?.stripe_customer_id ?? `cus_${orgId}`,
      subscriptionId,
      plan,
      status: "pending" as const
    };
  }

  async getPackageAdvisories(ecosystem: Ecosystem, packageName: string): Promise<Advisory[]> {
    const packageAdvisoryRows = await this.select<PackageAdvisoryRow>(
      "package_advisories",
      `select=*&ecosystem=eq.${encodeURIComponent(ecosystem)}&package_name=eq.${encodeURIComponent(packageName)}`
    );
    if (packageAdvisoryRows.length === 0) {
      return [];
    }
    const advisoryIds = [...new Set(packageAdvisoryRows.map((r) => r.advisory_id))];
    const advisoryRows = await this.select<AdvisoryRow>(
      "advisories",
      `select=*&id=in.(${advisoryIds.join(",")})&withdrawn_at=is.null&order=published_at.desc`
    );
    return advisoryRows.map((row) => this.mapAdvisory(row, packageAdvisoryRows.filter((pa) => pa.advisory_id === row.id)));
  }

  async getRecentAdvisories(limit = 50): Promise<Advisory[]> {
    const advisoryRows = await this.select<AdvisoryRow>(
      "advisories",
      `select=*&withdrawn_at=is.null&order=published_at.desc&limit=${limit}`
    );
    if (advisoryRows.length === 0) {
      return [];
    }
    const advisoryIds = advisoryRows.map((r) => r.id);
    const packageAdvisoryRows = await this.select<PackageAdvisoryRow>(
      "package_advisories",
      `select=*&advisory_id=in.(${advisoryIds.join(",")})`
    );
    return advisoryRows.map((row) => this.mapAdvisory(row, packageAdvisoryRows.filter((pa) => pa.advisory_id === row.id)));
  }

  private mapAdvisory(row: AdvisoryRow, packageAdvisoryRows: PackageAdvisoryRow[]): Advisory {
    return {
      id: row.id,
      source: row.source,
      sourceId: row.source_id,
      title: row.title,
      description: row.description ?? undefined,
      severity: row.severity ?? undefined,
      cvssScore: row.cvss_score ?? undefined,
      cvssVector: row.cvss_vector ?? undefined,
      cweIds: row.cwe_ids ?? [],
      publishedAt: row.published_at ?? undefined,
      updatedAt: row.updated_at ?? undefined,
      references: row.references ?? [],
      affectedPackages: packageAdvisoryRows.map((pa) => ({
        ecosystem: pa.ecosystem,
        packageName: pa.package_name,
        vulnerableRange: pa.vulnerable_range ?? undefined,
        patchedVersion: pa.patched_version ?? undefined
      }))
    };
  }

  // Usage tracking

  async getUsageRecord(orgId: string) {
    const { periodStart } = getCurrentPeriod();
    const rows = await this.select<UsageRecordRow>(
      "usage_records",
      `select=*&org_id=eq.${orgId}&period_start=eq.${encodeURIComponent(periodStart)}`
    );
    const row = rows[0];
    if (!row) {
      return null;
    }
    return {
      scanCount: row.scan_count,
      repoCount: row.repo_count,
      periodStart: row.period_start,
      periodEnd: row.period_end
    };
  }

  async incrementScanCount(orgId: string) {
    const { periodStart, periodEnd } = getCurrentPeriod();
    // Upsert the usage record, then read-and-increment the counter
    await this.request<unknown>(
      `/usage_records?on_conflict=org_id,period_start`,
      {
        method: "POST",
        headers: {
          Prefer: "resolution=merge-duplicates,return=minimal"
        },
        body: JSON.stringify({
          org_id: orgId,
          period_start: periodStart,
          period_end: periodEnd,
          scan_count: 1,
          updated_at: now()
        })
      }
    );
    const rows = await this.select<UsageRecordRow>(
      "usage_records",
      `select=*&org_id=eq.${orgId}&period_start=eq.${encodeURIComponent(periodStart)}`
    );
    const row = rows[0];
    if (row) {
      await this.request<unknown>(
        `/usage_records?org_id=eq.${orgId}&period_start=eq.${encodeURIComponent(periodStart)}`,
        {
          method: "PATCH",
          headers: { Prefer: "return=minimal" },
          body: JSON.stringify({
            scan_count: row.scan_count + 1,
            updated_at: now()
          })
        }
      );
    }
  }

  async incrementRepoCount(orgId: string) {
    const { periodStart, periodEnd } = getCurrentPeriod();
    await this.request<unknown>(
      `/usage_records?on_conflict=org_id,period_start`,
      {
        method: "POST",
        headers: {
          Prefer: "resolution=merge-duplicates,return=minimal"
        },
        body: JSON.stringify({
          org_id: orgId,
          period_start: periodStart,
          period_end: periodEnd,
          repo_count: 1,
          updated_at: now()
        })
      }
    );
    const rows = await this.select<UsageRecordRow>(
      "usage_records",
      `select=*&org_id=eq.${orgId}&period_start=eq.${encodeURIComponent(periodStart)}`
    );
    const row = rows[0];
    if (row) {
      await this.request<unknown>(
        `/usage_records?org_id=eq.${orgId}&period_start=eq.${encodeURIComponent(periodStart)}`,
        {
          method: "PATCH",
          headers: { Prefer: "return=minimal" },
          body: JSON.stringify({
            repo_count: row.repo_count + 1,
            updated_at: now()
          })
        }
      );
    }
  }

  // Invitations

  async createInvitation(orgId: string, email: string, role: string, invitedBy?: string) {
    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    const [row] = await this.insert<OrgInvitationRow>("org_invitations", {
      org_id: orgId,
      email,
      role,
      token,
      invited_by: invitedBy ?? null,
      expires_at: expiresAt
    });
    return {
      id: row.id,
      token: row.token,
      email: row.email,
      expiresAt: row.expires_at
    };
  }

  async listInvitations(orgId: string) {
    const rows = await this.select<OrgInvitationRow>(
      "org_invitations",
      `select=*&org_id=eq.${orgId}&order=created_at.desc`
    );
    return rows.map((inv) => ({
      id: inv.id,
      email: inv.email,
      role: inv.role,
      createdAt: inv.created_at,
      expiresAt: inv.expires_at,
      accepted: inv.accepted_at !== null
    }));
  }

  async acceptInvitation(token: string, _userId: string) {
    const rows = await this.select<OrgInvitationRow>(
      "org_invitations",
      `select=*&token=eq.${token}&accepted_at=is.null`
    );
    const inv = rows[0];
    if (!inv) {
      return null;
    }

    if (new Date(inv.expires_at) < new Date()) {
      return null;
    }

    await this.request<unknown>(
      `/org_invitations?token=eq.${token}`,
      {
        method: "PATCH",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify({ accepted_at: now() })
      }
    );

    return { orgId: inv.org_id, role: inv.role };
  }
}

export interface BinShieldRepository extends BaseRepository {}

export interface AppServices {
  env: ApiEnv;
  repository: BinShieldRepository;
  repositoryInfo: { mode: "local" | "supabase"; ready: boolean; description: string };
}

export function createRepository(env: ApiEnv): BinShieldRepository {
  return env.mode === "supabase" ? new SupabaseRepository(env) : new LocalRepository(env);
}

export function createServices(env: ApiEnv): AppServices {
  return {
    env,
    repository: createRepository(env),
    repositoryInfo: {
      mode: env.mode,
      ready: true,
      description:
        env.mode === "supabase"
          ? "Supabase repository is configured and ready."
          : "Local repository fallback is active; set Supabase env vars to switch to live storage."
    }
  };
}
