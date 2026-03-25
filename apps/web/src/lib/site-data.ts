import type {
  AnalysisStatus,
  ApiListResponse,
  BinaryAnalysis,
  Ecosystem,
  Finding,
  FindingSeverity,
  PackageAnalysis,
  PackageDiff,
  RepoRecord,
  SearchResult
} from "@binshield/analysis-types";
import { getSampleAnalysis, getSamplePackageDiff, getSamplePackageHistory, sampleAnalyses, sampleDiff } from "@binshield/analysis-types";

export type DataMode = "live" | "demo";
export type EvidenceTone = "benign" | "review" | "suspicious";

export interface MetricCardData {
  label: string;
  value: string;
  detail: string;
}

export interface PublicPackageCard extends SearchResult {
  versions: number;
  publishedAt: string;
  sourceMatchConfidence: "low" | "medium" | "high";
  highestFinding: FindingSeverity;
  topBehaviors: string[];
}

export interface BinaryEvidenceCard {
  id: string;
  filename: string;
  architecture: string;
  format: string;
  sizeLabel: string;
  riskScore: number;
  riskLevel: BinaryAnalysis["riskLevel"];
  tone: EvidenceTone;
  headline: string;
  explanation: string;
  behaviors: Array<{
    name: string;
    summary: string;
    tone: EvidenceTone;
  }>;
  imports: string[];
  strings: string[];
  findings: Finding[];
  evidenceChecklist: string[];
  decompiledPreview: string;
}

export interface VersionTimelineEntry {
  version: string;
  riskLevel: PackageAnalysis["riskLevel"];
  riskScore: number;
  binaryCount: number;
  changedLabel: string;
  active: boolean;
}

export interface DiffNarrative {
  headline: string;
  analystNote: string;
  addedBehaviors: string[];
  removedBehaviors: string[];
  reviewChecklist: string[];
  impactLabel: string;
}

export interface PackageWorkspace {
  mode: DataMode;
  packageName: string;
  ecosystem: Ecosystem;
  versions: PackageAnalysis[];
  selected: PackageAnalysis;
  diff: PackageDiff;
  related: PublicPackageCard[];
  found: boolean;
  evidenceCards: BinaryEvidenceCard[];
  findingsBySeverity: Array<{
    severity: FindingSeverity;
    findings: Finding[];
  }>;
  versionTimeline: VersionTimelineEntry[];
  diffNarrative: DiffNarrative;
  packageSignals: Array<{
    label: string;
    value: string;
    detail: string;
  }>;
  evidenceSummary: Array<{
    title: string;
    detail: string;
    tone: EvidenceTone;
  }>;
}

export interface BinaryWorkspace {
  mode: DataMode;
  packageName: string;
  selectedVersion: string;
  binary: BinaryEvidenceCard;
  rawBinary: BinaryAnalysis;
  packageSignals: PackageWorkspace["packageSignals"];
  diffNarrative: DiffNarrative;
  breadcrumbs: Array<{
    label: string;
    href: string;
  }>;
}

export interface RepoSummary {
  name: string;
  ecosystem: Ecosystem;
  nativeDependencyCount: number;
  aggregateRiskScore: number;
  status: "healthy" | "watch" | "review";
  lastScanLabel: string;
}

export interface WatchlistItem {
  packageName: string;
  ecosystem: Ecosystem;
  currentVersion: string;
  previousVersion: string;
  riskChange: number;
  channel: "email" | "slack" | "webhook";
  status: "active" | "pending" | "paused";
  note: string;
}

export interface BillingSnapshot {
  mode: DataMode;
  plan: string;
  billingInterval: string;
  seatCount: number;
  seatLimit: number;
  monthlyUsage: number;
  monthlyLimit: number;
  paymentMethod: string;
  invoices: Array<{
    id: string;
    dateLabel: string;
    amount: string;
    status: "paid" | "open" | "draft";
  }>;
}

export interface SettingsSnapshot {
  orgName: string;
  orgSlug: string;
  contactEmail: string;
  role: string;
  apiKeys: Array<{
    label: string;
    maskedKey: string;
    lastUsedLabel: string;
  }>;
  alertPreferences: string[];
  auditTrail: string[];
}

export interface DashboardSnapshot {
  mode: DataMode;
  metrics: MetricCardData[];
  repos: RepoSummary[];
  watchlist: WatchlistItem[];
  recentScans: Array<{
    packageName: string;
    version: string;
    riskLevel: string;
    status: AnalysisStatus;
    timestampLabel: string;
  }>;
}

const rawApiBaseUrl = process.env.BINSHIELD_API_BASE_URL?.trim() || process.env.NEXT_PUBLIC_BINSHIELD_API_BASE_URL?.trim() || "";
const dataMode: DataMode = rawApiBaseUrl ? "live" : "demo";
const severityOrder: FindingSeverity[] = ["critical", "high", "medium", "low", "info"];

function normalizeBaseUrl(url: string) {
  return url.replace(/\/+$/, "");
}

function formatRelative(timestamp: string) {
  const time = new Date(timestamp).getTime();
  const diff = Date.now() - time;
  const hours = Math.max(1, Math.round(diff / (1000 * 60 * 60)));
  if (hours < 24) {
    return `${hours}h ago`;
  }

  const days = Math.max(1, Math.round(hours / 24));
  return `${days}d ago`;
}

function formatKilobytes(value: number) {
  return `${Math.max(1, Math.round(value / 1024))} KB`;
}

function dedupe<T>(items: T[]) {
  return Array.from(new Set(items));
}

function compareSeverity(a: FindingSeverity, b: FindingSeverity) {
  return severityOrder.indexOf(a) - severityOrder.indexOf(b);
}

function highestFindingSeverity(analysis: PackageAnalysis): FindingSeverity {
  const severities = analysis.binaries.flatMap((binary) => binary.findings.map((finding) => finding.severity));
  if (severities.length === 0) {
    return "info";
  }

  return severities.sort(compareSeverity)[0];
}

function topBehaviors(analysis: PackageAnalysis) {
  const entries = analysis.binaries.flatMap((binary) =>
    Object.entries(binary.behaviors)
      .filter(([, signal]) => signal.detected)
      .map(([name]) => name)
  );

  return dedupe(entries).slice(0, 3);
}

function toneForBinary(binary: BinaryAnalysis): EvidenceTone {
  if (binary.riskLevel === "critical" || binary.riskLevel === "high") {
    return "suspicious";
  }
  if (binary.riskLevel === "medium") {
    return "review";
  }
  return "benign";
}

function behaviorTone(behaviorName: string): EvidenceTone {
  if (behaviorName === "obfuscation" || behaviorName === "dataExfiltration" || behaviorName === "network") {
    return "suspicious";
  }
  if (behaviorName === "process" || behaviorName === "filesystem") {
    return "review";
  }
  return "benign";
}

function summarizeBehavior(name: string, binary: BinaryAnalysis) {
  const signal = binary.behaviors[name as keyof BinaryAnalysis["behaviors"]];
  if (!signal?.detected) {
    return "";
  }

  return signal.details[0] ?? `${name} activity observed during analysis.`;
}

function buildEvidenceChecklist(binary: BinaryAnalysis) {
  return [
    `${binary.importCount} imports surfaced during decompilation`,
    `${binary.functionCount} functions were recovered`,
    binary.strings.length ? `${Math.min(binary.strings.length, 3)} notable strings surfaced` : "No notable strings surfaced",
    binary.findings.length ? `${binary.findings.length} findings require analyst review` : "No findings escalated beyond informational"
  ];
}

function toEvidenceCard(binary: BinaryAnalysis): BinaryEvidenceCard {
  const detectedBehaviors = Object.entries(binary.behaviors).filter(([, signal]) => signal.detected);
  const tone = toneForBinary(binary);

  return {
    id: binary.id,
    filename: binary.filename,
    architecture: binary.architecture,
    format: binary.format,
    sizeLabel: formatKilobytes(binary.fileSize),
    riskScore: binary.riskScore,
    riskLevel: binary.riskLevel,
    tone,
    headline:
      tone === "suspicious"
        ? "Review this binary closely before allowing the package upgrade."
        : tone === "review"
          ? "Behavior is likely expected, but the evidence still deserves human review."
          : "Evidence is consistent with an expected native package implementation.",
    explanation: binary.aiExplanation,
    behaviors: detectedBehaviors.map(([name]) => ({
      name,
      summary: summarizeBehavior(name, binary),
      tone: behaviorTone(name)
    })),
    imports: binary.imports.slice(0, 8),
    strings: binary.strings.slice(0, 8),
    findings: binary.findings,
    evidenceChecklist: buildEvidenceChecklist(binary),
    decompiledPreview: binary.decompiledPreview
  };
}

function groupFindings(analysis: PackageAnalysis) {
  const grouped = new Map<FindingSeverity, Finding[]>();

  for (const binary of analysis.binaries) {
    for (const finding of binary.findings) {
      const bucket = grouped.get(finding.severity) ?? [];
      bucket.push(finding);
      grouped.set(finding.severity, bucket);
    }
  }

  return severityOrder
    .map((severity) => ({
      severity,
      findings: grouped.get(severity) ?? []
    }))
    .filter((entry) => entry.findings.length > 0);
}

function toSearchResult(analysis: PackageAnalysis): PublicPackageCard {
  const history = getSamplePackageHistory(analysis.packageName, analysis.ecosystem);
  return {
    ecosystem: analysis.ecosystem,
    packageName: analysis.packageName,
    latestVersion: analysis.version,
    riskLevel: analysis.riskLevel,
    riskScore: analysis.riskScore,
    summary: analysis.summary,
    binaryCount: analysis.binaryCount,
    versions: history.length,
    publishedAt: analysis.createdAt,
    sourceMatchConfidence: analysis.sourceMatchConfidence,
    highestFinding: highestFindingSeverity(analysis),
    topBehaviors: topBehaviors(analysis)
  };
}

function toPackageCards(analyses: PackageAnalysis[]): PublicPackageCard[] {
  const byPackage = new Map<string, PackageAnalysis>();

  for (const analysis of analyses) {
    const existing = byPackage.get(analysis.packageName);
    if (!existing || analysis.version.localeCompare(existing.version, undefined, { numeric: true }) > 0) {
      byPackage.set(analysis.packageName, analysis);
    }
  }

  const cards = Array.from(byPackage.values()).map(toSearchResult);
  return cards.sort((a, b) => b.riskScore - a.riskScore);
}

function getSamplePackage(name: string, version?: string) {
  return getSampleAnalysis(name, version);
}

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T | null> {
  if (!rawApiBaseUrl) {
    return null;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8_000);
  const headers = new Headers(init?.headers);
  headers.set("accept", "application/json");

  try {
    const response = await fetch(`${normalizeBaseUrl(rawApiBaseUrl)}${path}`, {
      ...init,
      cache: "no-store",
      headers,
      signal: controller.signal
    });

    if (!response.ok) {
      return null;
    }

    return (await response.json()) as T;
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

function buildVersionTimeline(versions: PackageAnalysis[], selectedVersion: string): VersionTimelineEntry[] {
  const reference = versions.find((entry) => entry.version === selectedVersion) ?? versions[0];

  return versions.map((analysis) => ({
    version: analysis.version,
    riskLevel: analysis.riskLevel,
    riskScore: analysis.riskScore,
    binaryCount: analysis.binaryCount,
    changedLabel:
      analysis.version === reference.version
        ? "Current investigation target"
        : analysis.riskScore > reference.riskScore
          ? "Riskier than selected"
          : analysis.riskScore < reference.riskScore
            ? "Less risky than selected"
            : "Same overall package score",
    active: analysis.version === selectedVersion
  }));
}

function buildDiffNarrative(selected: PackageAnalysis, diff: PackageDiff, previous?: PackageAnalysis): DiffNarrative {
  const riskDelta = selected.riskScore - (previous?.riskScore ?? selected.riskScore - diff.riskDelta);
  const impactLabel =
    riskDelta > 0 ? `Risk increased by ${riskDelta} points` : riskDelta < 0 ? `Risk decreased by ${Math.abs(riskDelta)} points` : "Risk held steady";

  return {
    headline:
      riskDelta > 0
        ? "This version introduces additional behavior that deserves security review."
        : riskDelta < 0
          ? "This version removes or tightens behavior compared with the previous release."
          : "This version keeps a similar behavioral profile to the previous release.",
    analystNote: diff.summary,
    addedBehaviors: diff.addedBehaviors,
    removedBehaviors: diff.removedBehaviors,
    reviewChecklist: [
      "Validate whether any newly added filesystem or process behavior is expected.",
      "Compare binary inventory to ensure no unexpected native artifact was introduced.",
      "Review high-signal strings and imports before approving rollout."
    ],
    impactLabel
  };
}

function buildPackageSignals(selected: PackageAnalysis) {
  const behaviors = dedupe(topBehaviors(selected));
  return [
    { label: "Overall risk", value: `${selected.riskLevel.toUpperCase()} (${selected.riskScore})`, detail: "Package-level aggregate score" },
    { label: "Source match", value: selected.sourceMatchConfidence.toUpperCase(), detail: "Confidence in decompiled/source alignment" },
    { label: "Binary inventory", value: String(selected.binaryCount), detail: `${formatKilobytes(selected.totalBinarySize)} total analyzed size` },
    { label: "Behavior families", value: behaviors.length ? behaviors.join(", ") : "none detected", detail: "Observed across all binaries" }
  ];
}

function buildEvidenceSummary(selected: PackageAnalysis): PackageWorkspace["evidenceSummary"] {
  const highest = highestFindingSeverity(selected);
  const binariesWithFindings = selected.binaries.filter((binary) => binary.findings.length > 0).length;
  return [
    {
      title: highest === "info" ? "No escalated findings" : `${highest.toUpperCase()} findings surfaced`,
      detail:
        highest === "info"
          ? "The current evidence set is dominated by expected native behavior."
          : "At least one binary contains findings that should be reviewed before shipping.",
      tone: highest === "info" ? "benign" : highest === "critical" || highest === "high" ? "suspicious" : "review"
    },
    {
      title: `${binariesWithFindings}/${selected.binaryCount} binaries carry findings`,
      detail: "Not every native artifact in a package deserves equal attention. Focus review where findings cluster.",
      tone: binariesWithFindings > 0 ? "review" : "benign"
    },
    {
      title: `${selected.aiModel} analysis with ${selected.sourceMatchConfidence} confidence`,
      detail: "Use the model summary as triage guidance, then validate against imports, strings, and recovered functions.",
      tone: selected.sourceMatchConfidence === "low" ? "review" : "benign"
    }
  ];
}

let verifiedDataMode: DataMode | null = null;

export async function getDataMode(): Promise<DataMode> {
  if (verifiedDataMode !== null) return verifiedDataMode;
  if (!rawApiBaseUrl) {
    verifiedDataMode = "demo";
    return "demo";
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const res = await fetch(`${normalizeBaseUrl(rawApiBaseUrl)}/health`, {
      signal: controller.signal,
      cache: "no-store"
    });
    clearTimeout(timeout);
    verifiedDataMode = res.ok ? "live" : "demo";
  } catch {
    verifiedDataMode = "demo";
  }

  return verifiedDataMode;
}

export async function getFeaturedPackages(limit = 6): Promise<PublicPackageCard[]> {
  const response = await fetchJson<ApiListResponse<SearchResult>>("/packages/search");
  if (response?.items?.length) {
    // Sort by risk score descending to show most interesting packages first
    const sorted = [...response.items].sort((a, b) => b.riskScore - a.riskScore);
    return sorted.slice(0, limit).map((item) => {
      const behaviorLabels: string[] = [];
      if (item.riskScore >= 30) behaviorLabels.push("review-worthy");
      if (item.binaryCount > 5) behaviorLabels.push("multi-binary");
      if (item.riskScore >= 60) behaviorLabels.push("elevated risk");

      return {
        ...item,
        versions: 1,
        publishedAt: new Date().toISOString(),
        sourceMatchConfidence: item.riskScore >= 40 ? "high" as const : "medium" as const,
        highestFinding: item.riskLevel === "high" || item.riskLevel === "critical" ? "high" as const : item.riskLevel === "medium" ? "medium" as const : "info" as const,
        topBehaviors: behaviorLabels
      };
    });
  }

  return toPackageCards(sampleAnalyses).slice(0, limit);
}

export async function searchPackages(query: string): Promise<PublicPackageCard[]> {
  const response = await fetchJson<ApiListResponse<SearchResult>>(`/packages/search?q=${encodeURIComponent(query)}`);
  if (response?.items?.length) {
    return response.items.map((item) => ({
      ...item,
      versions: 1,
      publishedAt: new Date().toISOString(),
      sourceMatchConfidence: "medium",
      highestFinding: item.riskLevel === "medium" || item.riskLevel === "high" || item.riskLevel === "critical" ? "medium" : "info",
      topBehaviors: []
    }));
  }

  const lower = query.trim().toLowerCase();
  return toPackageCards(
    sampleAnalyses.filter((analysis) =>
      lower.length === 0 ? true : analysis.packageName.toLowerCase().includes(lower) || analysis.summary.toLowerCase().includes(lower)
    )
  );
}

export async function getPackageWorkspace(packageName: string, version?: string): Promise<PackageWorkspace> {
  const packageResponse = await fetchJson<{ packageName: string; ecosystem: Ecosystem; versions: PackageAnalysis[] }>(
    `/packages/npm/${encodeURIComponent(packageName)}`
  );

  const versions = packageResponse?.versions?.length
    ? packageResponse.versions
    : getSamplePackageHistory(packageName);
  const selectedVersion = version ?? versions[0]?.version ?? getSamplePackageHistory(packageName)[0]?.version;

  const liveAnalysis = selectedVersion
    ? await fetchJson<PackageAnalysis>(`/packages/npm/${encodeURIComponent(packageName)}/versions/${encodeURIComponent(selectedVersion)}`)
    : null;

  const selected = liveAnalysis ?? getSamplePackage(packageName, selectedVersion) ?? sampleAnalyses[0];
  const found = Boolean(packageResponse?.versions?.length || liveAnalysis || versions.length);
  const previous = versions.find((entry) => entry.version !== selected.version);
  const diff =
    (await fetchJson<PackageDiff>(
      `/packages/npm/${encodeURIComponent(packageName)}/diff?from=${encodeURIComponent(previous?.version ?? sampleDiff.fromVersion)}&to=${encodeURIComponent(selected.version)}`
    )) ??
    getSamplePackageDiff(packageName, previous?.version ?? sampleDiff.fromVersion, selected.version) ??
    sampleDiff;
  const related = await searchPackages(packageName).then((items) => items.filter((item) => item.packageName !== packageName).slice(0, 4));

  return {
    mode: dataMode,
    packageName: selected.packageName,
    ecosystem: selected.ecosystem,
    versions: versions.length ? versions : [selected],
    selected,
    diff,
    related,
    found,
    evidenceCards: selected.binaries.map(toEvidenceCard),
    findingsBySeverity: groupFindings(selected),
    versionTimeline: buildVersionTimeline(versions.length ? versions : [selected], selected.version),
    diffNarrative: buildDiffNarrative(selected, diff, previous),
    packageSignals: buildPackageSignals(selected),
    evidenceSummary: buildEvidenceSummary(selected)
  };
}

export async function getBinaryWorkspace(
  packageName: string,
  binaryId: string,
  version?: string
): Promise<BinaryWorkspace | null> {
  const workspace = await getPackageWorkspace(packageName, version);
  const binary = workspace.evidenceCards.find((entry) => entry.id === binaryId);

  if (!binary) {
    return null;
  }

  const rawBinary = workspace.selected.binaries.find((b) => b.id === binaryId) ?? workspace.selected.binaries[0];

  return {
    mode: workspace.mode,
    packageName: workspace.packageName,
    selectedVersion: workspace.selected.version,
    binary,
    rawBinary,
    packageSignals: workspace.packageSignals,
    diffNarrative: workspace.diffNarrative,
    breadcrumbs: [
      { label: "Packages", href: "/packages" },
      { label: workspace.packageName, href: `/packages/${workspace.packageName}?version=${encodeURIComponent(workspace.selected.version)}` },
      { label: binary.filename, href: `/packages/${workspace.packageName}/binaries/${binary.id}?version=${encodeURIComponent(workspace.selected.version)}` }
    ]
  };
}

export async function getDashboardSnapshot(orgId?: string): Promise<DashboardSnapshot> {
  // When orgId is provided, try to fetch real data from Supabase directly
  if (orgId) {
    try {
      const { createServiceRoleClient } = await import("./supabase");
      const admin = createServiceRoleClient();

      const { data: repos } = await admin
        .from("repos")
        .select("id, org_id, github_repo, native_dep_count, aggregate_risk_score, last_scan_at")
        .eq("org_id", orgId);

      const { data: scans } = await admin
        .from("repo_scans")
        .select("id, status, scanned_at, repos(github_repo)")
        .eq("org_id", orgId)
        .order("created_at", { ascending: false })
        .limit(5);

      const repoItems = repos ?? [];
      const totalBinaries = repoItems.reduce((sum, r) => sum + (r.native_dep_count ?? 0), 0);
      const reviewCount = repoItems.filter((r) => (r.aggregate_risk_score ?? 0) >= 40).length;

      return {
        mode: "live",
        metrics: [
          { label: "Repos monitored", value: String(repoItems.length), detail: "Connected repositories" },
          { label: "Native binaries", value: String(totalBinaries || 0), detail: "Across active manifests" },
          { label: "Open reviews", value: String(reviewCount), detail: "Requiring follow-up" },
          { label: "Alert coverage", value: "Email", detail: "Watchlist notifications enabled" }
        ],
        repos: repoItems.map((repo, index) => ({
          name: repo.github_repo,
          ecosystem: "npm" as Ecosystem,
          nativeDependencyCount: repo.native_dep_count ?? 0,
          aggregateRiskScore: repo.aggregate_risk_score ?? 0,
          status: (repo.aggregate_risk_score ?? 0) >= 40 ? "review" : index === 1 ? "watch" : "healthy",
          lastScanLabel: repo.last_scan_at ? formatRelative(repo.last_scan_at) : "never"
        })),
        watchlist: [],
        recentScans: (scans ?? []).map((scan) => ({
          packageName: (scan.repos as unknown as { github_repo: string })?.github_repo ?? "unknown",
          version: "latest",
          riskLevel: "low",
          status: scan.status === "complete" ? "complete" as AnalysisStatus : "analyzing" as AnalysisStatus,
          timestampLabel: scan.scanned_at ? formatRelative(scan.scanned_at) : "recently"
        }))
      };
    } catch {
      // Fall through to demo data on error
    }
  }

  // Fallback: try the public API, then demo data
  const reposResponse = await fetchJson<{ items: RepoRecord[] }>("/orgs/demo/repos");
  const repoItems = reposResponse?.items?.length
    ? reposResponse.items
    : [
        {
          id: "repo-payments",
          orgId: "demo",
          githubRepo: "ashlrai/payments-api",
          nativeDependencyCount: 6,
          aggregateRiskScore: 18,
          lastScanAt: new Date(Date.now() - 1000 * 60 * 60 * 9).toISOString()
        },
        {
          id: "repo-platform",
          orgId: "demo",
          githubRepo: "ashlrai/platform-web",
          nativeDependencyCount: 4,
          aggregateRiskScore: 22,
          lastScanAt: new Date(Date.now() - 1000 * 60 * 60 * 26).toISOString()
        },
        {
          id: "repo-agent",
          orgId: "demo",
          githubRepo: "ashlrai/agent-runtime",
          nativeDependencyCount: 9,
          aggregateRiskScore: 43,
          lastScanAt: new Date(Date.now() - 1000 * 60 * 60 * 50).toISOString()
        }
      ];

  return {
    mode: dataMode,
    metrics: [
      { label: "Repos monitored", value: String(repoItems.length), detail: "Connected repositories" },
      { label: "Native binaries", value: "19", detail: "Across active manifests" },
      { label: "Open reviews", value: "1", detail: "Requiring follow-up" },
      { label: "Alert coverage", value: "Email", detail: "Watchlist notifications enabled" }
    ],
    repos: repoItems.map((repo, index) => ({
      name: repo.githubRepo,
      ecosystem: "npm",
      nativeDependencyCount: repo.nativeDependencyCount,
      aggregateRiskScore: repo.aggregateRiskScore,
      status: repo.aggregateRiskScore >= 40 ? "review" : index === 1 ? "watch" : "healthy",
      lastScanLabel: repo.lastScanAt ? formatRelative(repo.lastScanAt) : "recently"
    })),
    watchlist: [
      {
        packageName: "bcrypt",
        ecosystem: "npm",
        currentVersion: "5.1.1",
        previousVersion: "5.1.0",
        riskChange: 0,
        channel: "email",
        status: "active",
        note: "Stable behavior with entropy-only filesystem access."
      },
      {
        packageName: "sharp",
        ecosystem: "npm",
        currentVersion: "0.33.2",
        previousVersion: "0.33.1",
        riskChange: -2,
        channel: "email",
        status: "active",
        note: "No suspicious process or network behavior detected."
      }
    ],
    recentScans: [
      {
        packageName: "bcrypt",
        version: "5.1.1",
        riskLevel: "low",
        status: "complete",
        timestampLabel: "15m ago"
      },
      {
        packageName: "sharp",
        version: "0.33.2",
        riskLevel: "low",
        status: "complete",
        timestampLabel: "2h ago"
      },
      {
        packageName: "sqlite3",
        version: "5.1.7",
        riskLevel: "medium",
        status: "analyzing",
        timestampLabel: "running now"
      }
    ]
  };
}

export async function getWatchlistSnapshot(orgId?: string) {
  // When orgId is provided, try to fetch real watchlist data from Supabase
  if (orgId) {
    try {
      const { createServiceRoleClient } = await import("./supabase");
      const admin = createServiceRoleClient();

      const { data: watchlists } = await admin
        .from("watchlists")
        .select("id, name, channel, destination, created_at")
        .eq("org_id", orgId)
        .order("created_at", { ascending: false });

      if (watchlists && watchlists.length > 0) {
        // Fetch packages for each watchlist
        const watchlistIds = watchlists.map((w) => w.id);
        const { data: watchlistPackages } = await admin
          .from("watchlist_packages")
          .select("id, watchlist_id, ecosystem, package_name, version")
          .in("watchlist_id", watchlistIds);

        const items: WatchlistItem[] = (watchlistPackages ?? []).map((wp) => ({
          packageName: wp.package_name,
          ecosystem: wp.ecosystem as Ecosystem,
          currentVersion: wp.version ?? "latest",
          previousVersion: "unknown",
          riskChange: 0,
          channel: (watchlists.find((w) => w.id === wp.watchlist_id)?.channel ?? "email") as "email" | "slack" | "webhook",
          status: "active" as const,
          note: `Tracked in ${watchlists.find((w) => w.id === wp.watchlist_id)?.name ?? "watchlist"}`
        }));

        // Derive channel availability from watchlist configurations
        const channels = new Set(watchlists.map((w) => w.channel));
        return {
          mode: "live" as DataMode,
          items,
          alertChannels: [
            { name: "Email", enabled: channels.has("email"), detail: channels.has("email") ? "Active watchlist channel" : "Not configured" },
            { name: "Slack", enabled: channels.has("slack"), detail: channels.has("slack") ? "Active watchlist channel" : "Not configured" },
            { name: "Webhook", enabled: channels.has("webhook"), detail: channels.has("webhook") ? "Active watchlist channel" : "Not configured" }
          ]
        };
      }

      // No watchlists found -- return empty state
      return {
        mode: "live" as DataMode,
        items: [] as WatchlistItem[],
        alertChannels: [
          { name: "Email", enabled: false, detail: "Not configured" },
          { name: "Slack", enabled: false, detail: "Not configured" },
          { name: "Webhook", enabled: false, detail: "Not configured" }
        ]
      };
    } catch {
      // Fall through to demo data
    }
  }

  const dashboard = await getDashboardSnapshot();

  return {
    mode: dashboard.mode,
    items: dashboard.watchlist,
    alertChannels: [
      { name: "Email", enabled: true, detail: "Primary launch channel" },
      { name: "Slack", enabled: false, detail: "Deferred until team rollout" },
      { name: "Webhook", enabled: false, detail: "Available in API design only" }
    ]
  };
}

export async function getBillingSnapshot(orgId?: string): Promise<BillingSnapshot> {
  // When orgId is provided, try to fetch real subscription data from Supabase
  if (orgId) {
    try {
      const { createServiceRoleClient } = await import("./supabase");
      const admin = createServiceRoleClient();

      const { data: subscription } = await admin
        .from("subscriptions")
        .select("id, plan, status, provider, current_period_end, cancel_at_period_end, created_at")
        .eq("org_id", orgId)
        .maybeSingle();

      const { data: members } = await admin
        .from("organization_members")
        .select("id")
        .eq("org_id", orgId);

      const seatCount = members?.length ?? 1;

      if (subscription) {
        // Determine plan limits based on subscription plan
        const planLimits: Record<string, { seats: number; scans: number }> = {
          free: { seats: 3, scans: 100 },
          pro: { seats: 5, scans: 500 },
          team: { seats: 15, scans: 2000 },
          enterprise: { seats: 100, scans: 10000 }
        };
        const limits = planLimits[subscription.plan] ?? planLimits.free;

        // Count monthly scan jobs for usage
        const monthStart = new Date();
        monthStart.setDate(1);
        monthStart.setHours(0, 0, 0, 0);

        const { count: scanCount } = await admin
          .from("analysis_jobs")
          .select("id", { count: "exact", head: true })
          .eq("org_id", orgId)
          .gte("requested_at", monthStart.toISOString());

        return {
          mode: "live",
          plan: subscription.plan.charAt(0).toUpperCase() + subscription.plan.slice(1),
          billingInterval: "Monthly",
          seatCount,
          seatLimit: limits.seats,
          monthlyUsage: scanCount ?? 0,
          monthlyLimit: limits.scans,
          paymentMethod: subscription.provider === "stripe" ? "Stripe" : "Manual",
          invoices: [
            // Keep invoices as demo for now (Stripe integration separate)
            { id: "INV-1024", dateLabel: "Mar 1", amount: "$499", status: "paid" as const },
            { id: "INV-1025", dateLabel: "Apr 1", amount: "$499", status: "open" as const },
            { id: "INV-1026", dateLabel: "May 1", amount: "$499", status: "draft" as const }
          ]
        };
      }

      // No subscription found -- show Free plan
      return {
        mode: "live",
        plan: "Free",
        billingInterval: "None",
        seatCount,
        seatLimit: 3,
        monthlyUsage: 0,
        monthlyLimit: 100,
        paymentMethod: "No payment method",
        invoices: []
      };
    } catch {
      // Fall through to demo data
    }
  }

  return {
    mode: dataMode,
    plan: rawApiBaseUrl ? "Team" : "Launch Preview",
    billingInterval: "Monthly",
    seatCount: 5,
    seatLimit: rawApiBaseUrl ? 10 : 5,
    monthlyUsage: rawApiBaseUrl ? 117 : 43,
    monthlyLimit: rawApiBaseUrl ? 500 : 100,
    paymentMethod: "Visa ending in 4242",
    invoices: [
      { id: "INV-1024", dateLabel: "Mar 1", amount: "$499", status: "paid" },
      { id: "INV-1025", dateLabel: "Apr 1", amount: "$499", status: "open" },
      { id: "INV-1026", dateLabel: "May 1", amount: "$499", status: "draft" }
    ]
  };
}

export async function getSettingsSnapshot(orgId?: string, userEmail?: string): Promise<SettingsSnapshot> {
  // When orgId is provided, try to fetch real data from Supabase
  if (orgId) {
    try {
      const { createServiceRoleClient } = await import("./supabase");
      const admin = createServiceRoleClient();

      // Fetch org details
      const { data: org } = await admin
        .from("organizations")
        .select("id, name, slug")
        .eq("id", orgId)
        .maybeSingle();

      // Fetch API keys (non-revoked)
      const { data: apiKeys } = await admin
        .from("api_keys")
        .select("id, label, prefix, created_at, last_used_at, revoked_at")
        .eq("org_id", orgId)
        .is("revoked_at", null)
        .order("created_at", { ascending: false });

      // Fetch the user's role in the org
      const { data: membership } = await admin
        .from("organization_members")
        .select("role")
        .eq("org_id", orgId)
        .limit(1)
        .maybeSingle();

      // Fetch recent billing events for audit trail
      const { data: events } = await admin
        .from("billing_events")
        .select("event_type, created_at")
        .eq("org_id", orgId)
        .order("created_at", { ascending: false })
        .limit(5);

      const keyList = (apiKeys ?? []).map((key) => ({
        label: key.label,
        maskedKey: `${key.prefix}${"•".repeat(12)}`,
        lastUsedLabel: key.last_used_at ? formatRelative(key.last_used_at) : "never used"
      }));

      const auditItems = (events ?? []).map((evt) => {
        const dateStr = new Date(evt.created_at).toLocaleDateString();
        return `${evt.event_type} — ${dateStr}`;
      });

      return {
        orgName: org?.name ?? "My Organization",
        orgSlug: org?.slug ?? "my-org",
        contactEmail: userEmail ?? "unknown",
        role: membership?.role === "owner" ? "Owner" : membership?.role === "admin" ? "Admin" : "Member",
        apiKeys: keyList.length > 0 ? keyList : [],
        alertPreferences: ["Email on new binary behavior", "Daily digest", "Critical findings only"],
        auditTrail: auditItems.length > 0
          ? auditItems
          : ["No recent account events"]
      };
    } catch {
      // Fall through to demo data
    }
  }

  return {
    orgName: "Ashlr AI",
    orgSlug: "ashlrai",
    contactEmail: "security@ashlrai.com",
    role: "Owner",
    apiKeys: [
      { label: "CI prod", maskedKey: "bs_live_••••••••••a8c1", lastUsedLabel: "12m ago" },
      { label: "Staging", maskedKey: "bs_test_••••••••••b1f4", lastUsedLabel: "2d ago" }
    ],
    alertPreferences: ["Email on new binary behavior", "Daily digest", "Critical findings only"],
    auditTrail: [
      "API key created for GitHub Actions",
      "Watchlist added for bcrypt and sharp",
      "Org member invited to dashboard"
    ]
  };
}

/* ------------------------------------------------------------------ */
/*  Advisory, Feed, Lockfile-scan, and Compliance-report interfaces    */
/* ------------------------------------------------------------------ */

export interface Advisory {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  source: "OSV" | "NVD" | "GitHub";
  sourceId: string;
  description: string;
  publishedAt: string;
  affectedPackages: string[];
  url: string;
}

export interface FeedEvent {
  id: string;
  eventType: "new_package" | "new_version" | "risk_change";
  packageName: string;
  version: string;
  riskLevel: "none" | "low" | "medium" | "high" | "critical";
  riskScore: number;
  timestamp: string;
}

export interface FeedStats {
  packagesProcessed: number;
  nativePackagesFound: number;
  latestEvents: number;
}

export interface LockfileScan {
  id: string;
  filename: string;
  format: "npm" | "yarn" | "pnpm";
  totalDeps: number;
  nativeDeps: number;
  riskScore: number;
  riskLevel: "none" | "low" | "medium" | "high" | "critical";
  status: "complete" | "analyzing" | "queued";
  scannedAt: string;
}

export interface ComplianceReport {
  id: string;
  reportType: "SOC 2" | "ISO 27001" | "EU CRA" | "Custom";
  title: string;
  status: "complete" | "generating" | "queued";
  generatedAt: string;
  downloadUrl: string;
}

export async function getRecentAdvisories(): Promise<Advisory[]> {
  const response = await fetchJson<{ items: Advisory[] }>("/advisories/recent?limit=50");
  if (response?.items?.length) {
    return response.items;
  }

  // Demo data
  return [
    {
      id: "adv-1",
      title: "Heap buffer overflow in libwebp",
      severity: "critical",
      source: "NVD",
      sourceId: "CVE-2023-4863",
      description: "A heap buffer overflow in libwebp allows remote attackers to perform an out-of-bounds memory write via a crafted HTML page, affecting any application that processes WebP images including sharp and other image-processing npm packages.",
      publishedAt: new Date(Date.now() - 1000 * 60 * 60 * 6).toISOString(),
      affectedPackages: ["sharp", "libwebp"],
      url: "https://nvd.nist.gov/vuln/detail/CVE-2023-4863"
    },
    {
      id: "adv-2",
      title: "Prototype pollution in node-forge",
      severity: "high",
      source: "GitHub",
      sourceId: "GHSA-5rrq-pxf6-6jx5",
      description: "A prototype pollution vulnerability in node-forge could allow an attacker to inject properties into object prototypes, potentially leading to denial of service or remote code execution in applications using affected versions.",
      publishedAt: new Date(Date.now() - 1000 * 60 * 60 * 18).toISOString(),
      affectedPackages: ["node-forge"],
      url: "https://github.com/advisories/GHSA-5rrq-pxf6-6jx5"
    },
    {
      id: "adv-3",
      title: "Use-after-free in OpenSSL",
      severity: "high",
      source: "OSV",
      sourceId: "CVE-2024-0727",
      description: "Processing a maliciously formatted PKCS12 file may lead to OpenSSL crashing, potentially enabling denial of service attacks on applications that use native crypto bindings.",
      publishedAt: new Date(Date.now() - 1000 * 60 * 60 * 30).toISOString(),
      affectedPackages: ["node-openssl", "crypto-native"],
      url: "https://osv.dev/vulnerability/CVE-2024-0727"
    },
    {
      id: "adv-4",
      title: "Integer overflow in SQLite via better-sqlite3",
      severity: "medium",
      source: "NVD",
      sourceId: "CVE-2023-7104",
      description: "An integer overflow in certain SQLite queries can cause unexpected behavior in better-sqlite3 and sqlite3 npm packages when processing untrusted input through the native database binding layer.",
      publishedAt: new Date(Date.now() - 1000 * 60 * 60 * 48).toISOString(),
      affectedPackages: ["better-sqlite3", "sqlite3"],
      url: "https://nvd.nist.gov/vuln/detail/CVE-2023-7104"
    },
    {
      id: "adv-5",
      title: "bcrypt timing side-channel in password comparison",
      severity: "low",
      source: "GitHub",
      sourceId: "GHSA-wm7h-9275-46v2",
      description: "A theoretical timing side-channel in the bcrypt native binding compare function could allow an attacker with precise timing measurement to distinguish password hash comparison outcomes under specific conditions.",
      publishedAt: new Date(Date.now() - 1000 * 60 * 60 * 72).toISOString(),
      affectedPackages: ["bcrypt"],
      url: "https://github.com/advisories/GHSA-wm7h-9275-46v2"
    }
  ];
}

export async function getFeedEvents(): Promise<FeedEvent[]> {
  const response = await fetchJson<{ items: FeedEvent[] }>("/feed/events?limit=50");
  if (response?.items?.length) {
    return response.items;
  }

  // Demo data
  return [
    {
      id: "evt-1",
      eventType: "new_version",
      packageName: "sharp",
      version: "0.33.3",
      riskLevel: "low",
      riskScore: 14,
      timestamp: new Date(Date.now() - 1000 * 60 * 2).toISOString()
    },
    {
      id: "evt-2",
      eventType: "risk_change",
      packageName: "bcrypt",
      version: "5.1.1",
      riskLevel: "low",
      riskScore: 8,
      timestamp: new Date(Date.now() - 1000 * 60 * 15).toISOString()
    },
    {
      id: "evt-3",
      eventType: "new_package",
      packageName: "argon2",
      version: "0.31.2",
      riskLevel: "medium",
      riskScore: 34,
      timestamp: new Date(Date.now() - 1000 * 60 * 45).toISOString()
    },
    {
      id: "evt-4",
      eventType: "new_version",
      packageName: "sqlite3",
      version: "5.1.7",
      riskLevel: "medium",
      riskScore: 41,
      timestamp: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString()
    },
    {
      id: "evt-5",
      eventType: "risk_change",
      packageName: "node-gyp",
      version: "10.0.1",
      riskLevel: "high",
      riskScore: 67,
      timestamp: new Date(Date.now() - 1000 * 60 * 60 * 4).toISOString()
    },
    {
      id: "evt-6",
      eventType: "new_package",
      packageName: "canvas",
      version: "2.11.2",
      riskLevel: "low",
      riskScore: 18,
      timestamp: new Date(Date.now() - 1000 * 60 * 60 * 8).toISOString()
    }
  ];
}

export async function getFeedStats(): Promise<FeedStats> {
  const response = await fetchJson<FeedStats>("/feed/stats");
  if (response) {
    return response;
  }

  return {
    packagesProcessed: 1247,
    nativePackagesFound: 83,
    latestEvents: 6
  };
}

export async function getLockfileScans(): Promise<LockfileScan[]> {
  const response = await fetchJson<{ items: LockfileScan[] }>("/lockfile-scans");
  if (response?.items?.length) {
    return response.items;
  }

  // Demo data
  return [
    {
      id: "scan-1",
      filename: "package-lock.json",
      format: "npm",
      totalDeps: 847,
      nativeDeps: 12,
      riskScore: 28,
      riskLevel: "low",
      status: "complete",
      scannedAt: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString()
    },
    {
      id: "scan-2",
      filename: "yarn.lock",
      format: "yarn",
      totalDeps: 1203,
      nativeDeps: 19,
      riskScore: 45,
      riskLevel: "medium",
      status: "complete",
      scannedAt: new Date(Date.now() - 1000 * 60 * 60 * 26).toISOString()
    },
    {
      id: "scan-3",
      filename: "pnpm-lock.yaml",
      format: "pnpm",
      totalDeps: 562,
      nativeDeps: 7,
      riskScore: 15,
      riskLevel: "low",
      status: "complete",
      scannedAt: new Date(Date.now() - 1000 * 60 * 60 * 72).toISOString()
    }
  ];
}

export async function getComplianceReports(): Promise<ComplianceReport[]> {
  const response = await fetchJson<{ items: ComplianceReport[] }>("/compliance/reports");
  if (response?.items?.length) {
    return response.items;
  }

  // Demo data
  return [
    {
      id: "rpt-1",
      reportType: "SOC 2",
      title: "SOC 2 Type II Binary Supply Chain Assessment",
      status: "complete",
      generatedAt: new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString(),
      downloadUrl: "#"
    },
    {
      id: "rpt-2",
      reportType: "EU CRA",
      title: "EU Cyber Resilience Act Compliance Summary",
      status: "complete",
      generatedAt: new Date(Date.now() - 1000 * 60 * 60 * 72).toISOString(),
      downloadUrl: "#"
    },
    {
      id: "rpt-3",
      reportType: "ISO 27001",
      title: "ISO 27001 Annex A Native Dependency Audit",
      status: "generating",
      generatedAt: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
      downloadUrl: "#"
    }
  ];
}

export async function getPublicBrowseCounts() {
  const response = await fetchJson<ApiListResponse<SearchResult>>("/packages/search");
  if (response?.items?.length) {
    return {
      packages: response.items.length,
      binaries: response.items.reduce((total, item) => total + item.binaryCount, 0),
      watchlists: 2
    };
  }

  return {
    packages: dedupe(sampleAnalyses.map((analysis) => analysis.packageName)).length,
    binaries: sampleAnalyses.reduce((total, analysis) => total + analysis.binaryCount, 0),
    watchlists: 2
  };
}

export function getPackageSummaryStats(analysis: PackageAnalysis) {
  return [
    { label: "Risk score", value: String(analysis.riskScore), detail: `${analysis.riskLevel} severity posture` },
    { label: "Binary count", value: String(analysis.binaryCount), detail: "Native artifacts recovered" },
    { label: "Confidence", value: analysis.sourceMatchConfidence.toUpperCase(), detail: "Source/decompile alignment" },
    { label: "Total size", value: formatKilobytes(analysis.totalBinarySize), detail: "Combined binary payload" }
  ];
}

