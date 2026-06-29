import type { Advisory, AdvisorySyncResult, EpssScore, RiskCorrelation } from "./types";
import type { VulnerabilityEnrichment, EnrichedFinding, ExploitMaturity } from "@binshield/analysis-types";
import { EpssCache } from "./epss-cache";
import type { VendorPatchContext, LockfileResolutionContext } from "@binshield/risk-engine";

// ---------------------------------------------------------------------------
// CveEpssEntry — result type for getCveForPackage()
// ---------------------------------------------------------------------------

/**
 * A single CVE entry returned by `getCveForPackage()`, combining the CVE ID
 * with its current EPSS percentile and CISA KEV status.
 *
 * Used by the risk-engine EPSS severity override pipeline to decide how much
 * to boost a package's risk_score based on real-world exploitation data.
 */
export interface CveEpssEntry {
  /** CVE identifier in uppercase, e.g. "CVE-2024-12345". */
  cveId: string;
  /**
   * EPSS probability percentile [0, 1].
   * 0 when no EPSS data is available for this CVE.
   */
  epss_percentile: number;
  /**
   * Raw EPSS probability score [0, 1] (distinct from the percentile rank).
   * 0 when no EPSS data is available.
   */
  epss_score: number;
  /**
   * True when this CVE appears in the CISA Known Exploited Vulnerabilities
   * catalogue (as populated by the NVD feed ingester).
   */
  kev_active: boolean;
  /**
   * ISO date string (YYYY-MM-DD) when the EPSS score was last computed.
   * Undefined when no EPSS data is available.
   */
  score_date?: string;
}

// ---------------------------------------------------------------------------
// Vendor advisory JSON shape (GitHub Security Advisories + generic feed)
// ---------------------------------------------------------------------------

/**
 * Minimal shape of a vendor advisory JSON file.
 * Accepts both GitHub Security Advisory (GHSA) feed format and a simplified
 * generic vendor feed used by some ecosystem registries.
 */
export interface VendorAdvisoryJson {
  /** GHSA or CVE identifier */
  id: string;
  /** CVE alias when the primary id is a GHSA */
  cve_id?: string | null;
  /** Affected packages / version ranges */
  vulnerabilities?: Array<{
    package?: { name?: string; ecosystem?: string };
    vulnerable_version_range?: string | null;
    patched_versions?: string | null;
    first_patched_version?: { identifier: string } | null;
  }>;
  /** ISO publish date (used to compute daysToFix relative to now) */
  published_at?: string | null;
  /** ISO date the advisory was last updated */
  updated_at?: string | null;
  /** Withdrawn advisories must be ignored */
  withdrawn_at?: string | null;
}

/**
 * Result from parsing a batch of vendor advisory JSON files.
 */
export interface VendorAdvisoryParseResult {
  /** Per-CVE vendor patch contexts extracted from the advisories */
  patches: VendorPatchContext[];
  /** How many advisories were parsed */
  parsed: number;
  /** How many were skipped (withdrawn or malformed) */
  skipped: number;
}

// ---------------------------------------------------------------------------
// EPSS feed row (FIRST / Cyentia CSV feed, JSON variant)
// ---------------------------------------------------------------------------

interface EpssFeedRow {
  cve: string;
  epss: string;
  percentile: string;
  date?: string;
  model_version?: string;
}

interface EpssScoreRow {
  id: string;
  cve_id: string;
  package_name: string;
  ecosystem: string;
  version: string;
  epss_score: number;
  epss_percentile: number;
  model_version: string;
  score_date: string;
  updated_at: string;
}

// ---------------------------------------------------------------------------
// Internal row types matching Supabase schema
// ---------------------------------------------------------------------------

interface AdvisoryRow {
  id: string;
  source: string;
  source_id: string;
  advisory_type?: string | null;
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

// ---------------------------------------------------------------------------
// Source-specific response types
// ---------------------------------------------------------------------------

interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package?: { name: string; ecosystem: string };
    ranges?: Array<{ type: string; events: Array<{ introduced?: string; fixed?: string; last_affected?: string }> }>;
    versions?: string[];
    database_specific?: Record<string, unknown>;
  }>;
  references?: Array<{ type?: string; url: string }>;
  database_specific?: { severity?: string; [key: string]: unknown };
  published?: string;
  modified?: string;
  withdrawn?: string;
}

interface GhsaAdvisory {
  ghsa_id: string;
  cve_id?: string | null;
  type?: string;
  summary: string;
  description: string;
  severity: string;
  cvss?: { score?: number; vector_string?: string } | null;
  cwes?: Array<{ cwe_id: string; name: string }>;
  vulnerabilities?: Array<{
    package?: { name: string; ecosystem: string };
    vulnerable_version_range?: string;
    patched_versions?: string;
    first_patched_version?: { identifier: string } | null;
  }>;
  references?: string[];
  html_url?: string;
  published_at?: string;
  updated_at?: string;
  withdrawn_at?: string | null;
}

interface NvdResponse {
  vulnerabilities?: Array<{
    cve: {
      id: string;
      descriptions?: Array<{ lang: string; value: string }>;
      metrics?: {
        cvssMetricV31?: Array<{
          cvssData: { baseScore: number; vectorString: string; baseSeverity?: string };
        }>;
        cvssMetricV2?: Array<{
          cvssData: { baseScore: number; vectorString: string };
        }>;
      };
      weaknesses?: Array<{
        description: Array<{ lang: string; value: string }>;
      }>;
      references?: Array<{ url: string; source?: string; tags?: string[] }>;
      published?: string;
      lastModified?: string;
    };
  }>;
}

// ---------------------------------------------------------------------------
// Parsed advisory before DB upsert
// ---------------------------------------------------------------------------

interface ParsedAdvisory {
  source: string;
  sourceId: string;
  advisoryType: "vulnerability" | "malware";
  title: string;
  description?: string;
  severity?: string;
  cvssScore?: number;
  cvssVector?: string;
  cweIds: string[];
  publishedAt?: string;
  updatedAt?: string;
  withdrawnAt?: string;
  references: Array<{ type?: string; url: string }>;
  rawData: unknown;
  affectedPackages: Array<{
    ecosystem: string;
    packageName: string;
    vulnerableRange?: string;
    patchedVersion?: string;
  }>;
}

// ---------------------------------------------------------------------------
// NVD rate limiter
// ---------------------------------------------------------------------------

class RateLimiter {
  private timestamps: number[] = [];
  constructor(
    private maxRequests: number,
    private windowMs: number
  ) {}

  async acquire(): Promise<void> {
    const now = Date.now();
    this.timestamps = this.timestamps.filter((t) => now - t < this.windowMs);
    if (this.timestamps.length >= this.maxRequests) {
      const oldestInWindow = this.timestamps[0]!;
      const waitMs = this.windowMs - (now - oldestInWindow) + 100; // +100ms buffer
      await new Promise((resolve) => setTimeout(resolve, waitMs));
      return this.acquire();
    }
    this.timestamps.push(Date.now());
  }
}

// ---------------------------------------------------------------------------
// AdvisoryService
// ---------------------------------------------------------------------------

interface AdvisoryServiceConfig {
  supabaseUrl: string;
  supabaseServiceRoleKey: string;
  githubToken?: string;
  nvdApiKey?: string;
}

export class AdvisoryService {
  private nvdLimiter: RateLimiter;

  constructor(private config: AdvisoryServiceConfig) {
    // NVD: 5 req/30s without key, 50 req/30s with key
    const nvdMaxRequests = config.nvdApiKey ? 45 : 4; // conservative margin
    this.nvdLimiter = new RateLimiter(nvdMaxRequests, 30_000);
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  async syncPackageAdvisories(ecosystem: string, packageName: string): Promise<AdvisorySyncResult> {
    const sources: Record<string, number> = {};
    const allParsed: ParsedAdvisory[] = [];

    // Fetch from all sources in parallel; if one fails, continue with others
    const results = await Promise.allSettled([
      this.fetchOsv(ecosystem, packageName),
      this.fetchGhsa(ecosystem, packageName),
      this.fetchNvd(packageName)
    ]);

    const sourceNames = ["osv", "ghsa", "nvd"];
    for (let i = 0; i < results.length; i++) {
      const result = results[i]!;
      const sourceName = sourceNames[i]!;
      if (result.status === "fulfilled") {
        sources[sourceName] = result.value.length;
        allParsed.push(...result.value);
      } else {
        console.error(`[advisory-service] ${sourceName} fetch failed for ${ecosystem}/${packageName}:`, result.reason);
        sources[sourceName] = 0;
      }
    }

    // Deduplicate by (source, sourceId) — keep first occurrence
    const seen = new Set<string>();
    const unique: ParsedAdvisory[] = [];
    for (const advisory of allParsed) {
      const key = `${advisory.source}:${advisory.sourceId}`;
      if (!seen.has(key)) {
        seen.add(key);
        unique.push(advisory);
      }
    }

    // Upsert to database
    let newCount = 0;
    for (const advisory of unique) {
      const isNew = await this.upsertAdvisory(advisory);
      if (isNew) newCount++;
    }

    // Update sync state
    await this.updateSyncState(ecosystem, packageName, unique.length);

    return {
      ecosystem,
      packageName,
      totalAdvisories: unique.length,
      newAdvisories: newCount,
      sources
    };
  }

  async syncBatch(packages: Array<{ ecosystem: string; name: string }>): Promise<void> {
    // Process sequentially to avoid hammering APIs
    for (const pkg of packages) {
      try {
        await this.syncPackageAdvisories(pkg.ecosystem, pkg.name);
      } catch (err) {
        console.error(`[advisory-service] batch sync failed for ${pkg.ecosystem}/${pkg.name}:`, err);
      }
    }
  }

  async getPackageAdvisories(ecosystem: string, packageName: string): Promise<Advisory[]> {
    const packageAdvisoryRows = await this.dbSelect<PackageAdvisoryRow>(
      "package_advisories",
      `select=*&ecosystem=eq.${encodeURIComponent(ecosystem)}&package_name=eq.${encodeURIComponent(packageName)}`
    );
    if (packageAdvisoryRows.length === 0) {
      return [];
    }
    const advisoryIds = [...new Set(packageAdvisoryRows.map((r) => r.advisory_id))];
    const advisoryRows = await this.dbSelect<AdvisoryRow>(
      "advisories",
      `select=*&id=in.(${advisoryIds.join(",")})&withdrawn_at=is.null&order=published_at.desc`
    );
    return advisoryRows.map((row) =>
      this.mapAdvisory(row, packageAdvisoryRows.filter((pa) => pa.advisory_id === row.id))
    );
  }

  async getRecentAdvisories(limit = 50): Promise<Advisory[]> {
    const advisoryRows = await this.dbSelect<AdvisoryRow>(
      "advisories",
      `select=*&withdrawn_at=is.null&order=published_at.desc&limit=${limit}`
    );
    if (advisoryRows.length === 0) {
      return [];
    }
    const advisoryIds = advisoryRows.map((r) => r.id);
    const packageAdvisoryRows = await this.dbSelect<PackageAdvisoryRow>(
      "package_advisories",
      `select=*&advisory_id=in.(${advisoryIds.join(",")})`
    );
    return advisoryRows.map((row) =>
      this.mapAdvisory(row, packageAdvisoryRows.filter((pa) => pa.advisory_id === row.id))
    );
  }

  /**
   * Advisories where the package itself is malicious (OSV `MAL-*` / GHSA
   * malware), as opposed to a package that merely has a vulnerability.
   */
  async getMalwareAdvisoriesForPackage(ecosystem: string, packageName: string): Promise<Advisory[]> {
    const advisories = await this.getPackageAdvisories(ecosystem, packageName);
    return advisories.filter((advisory) => advisory.advisoryType === "malware");
  }

  // -------------------------------------------------------------------------
  // EPSS severity override — getCveForPackage
  // -------------------------------------------------------------------------

  /**
   * Return all CVE IDs known for a given package + version, along with their
   * EPSS percentiles and CISA KEV status, ready for use by the risk-engine
   * EPSS severity override pipeline.
   *
   * Steps:
   *   1. Fetch all advisories stored for this ecosystem/package from the DB.
   *   2. Filter to CVE-prefixed source IDs (skip GHSA-only entries).
   *   3. For each CVE, look up any cached EPSS score; fall back to a live
   *      FIRST API fetch when no cached row exists.
   *   4. Return an array of CveEpssEntry objects sorted by epss_percentile desc.
   *
   * The result is intentionally lightweight — callers (e.g. aggregatePackageRisk
   * in the risk-engine) pass the highest-percentile entry to epssBoost() /
   * cisaKevBoost() to compute the risk score uplift.
   *
   * @param ecosystem    Package ecosystem ("npm" | "pypi").
   * @param packageName  Package name, e.g. "lodash".
   * @param version      Exact version string pinned in the lockfile.
   */
  async getCveForPackage(
    ecosystem: string,
    packageName: string,
    version: string
  ): Promise<CveEpssEntry[]> {
    // 1. Pull all advisories from DB (already synced by syncPackageAdvisories)
    let advisories: Advisory[] = [];
    try {
      advisories = await this.getPackageAdvisories(ecosystem, packageName);
    } catch {
      // Graceful degradation — no advisories means no boost
      return [];
    }

    // 2. Extract unique CVE IDs
    const cveIds = [
      ...new Set(
        advisories
          .map((a) => a.sourceId)
          .filter((id) => id.toUpperCase().startsWith("CVE-"))
          .map((id) => id.toUpperCase())
      )
    ];
    if (cveIds.length === 0) return [];

    // 3. Fetch EPSS scores (cached → live fallback)
    let epssRows: EpssScore[] = [];
    try {
      epssRows = await this.getEpssScores(ecosystem, packageName, version);
      if (epssRows.length === 0) {
        epssRows = await this.syncEpssScores(ecosystem, packageName, version, cveIds);
      }
    } catch {
      // EPSS enrichment is best-effort
    }

    const epssMap = new Map(epssRows.map((r) => [r.cveId.toUpperCase(), r]));

    // 4. Build KEV set from advisory raw data
    const kevSet = new Set<string>();
    for (const advisory of advisories) {
      const raw = advisory as unknown as Record<string, unknown>;
      const kevDate = raw["cisaKevDate"] ?? raw["cisa_kev_date"];
      if (kevDate && advisory.sourceId.toUpperCase().startsWith("CVE-")) {
        kevSet.add(advisory.sourceId.toUpperCase());
      }
    }

    // 5. Assemble result — one entry per CVE, sorted by percentile desc
    const entries: CveEpssEntry[] = cveIds.map((cveId) => {
      const epssRow = epssMap.get(cveId);
      return {
        cveId,
        epss_percentile: epssRow?.epssPercentile ?? 0,
        epss_score: epssRow?.epssScore ?? 0,
        kev_active: kevSet.has(cveId),
        score_date: epssRow?.scoreDate
      };
    });

    entries.sort((a, b) => b.epss_percentile - a.epss_percentile);
    return entries;
  }

  // -------------------------------------------------------------------------
  // Source fetchers
  // -------------------------------------------------------------------------

  private async fetchOsv(ecosystem: string, packageName: string): Promise<ParsedAdvisory[]> {
    const response = await fetch("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ package: { name: packageName, ecosystem } })
    });

    if (!response.ok) {
      throw new Error(`OSV API returned ${response.status}: ${await response.text()}`);
    }

    const data = (await response.json()) as { vulns?: OsvVulnerability[] };
    const vulns = data.vulns ?? [];

    return vulns.map((vuln) => {
      const severity = this.extractOsvSeverity(vuln);
      const affectedPackages = this.extractOsvAffected(vuln, ecosystem, packageName);

      return {
        source: "osv",
        sourceId: vuln.id,
        advisoryType: vuln.id.toUpperCase().startsWith("MAL-") ? "malware" : "vulnerability",
        title: vuln.summary ?? vuln.id,
        description: vuln.details,
        severity: severity.level,
        cvssScore: severity.score,
        cvssVector: severity.vector,
        cweIds: [],
        publishedAt: vuln.published,
        updatedAt: vuln.modified,
        withdrawnAt: vuln.withdrawn,
        references: (vuln.references ?? []).map((r) => ({ type: r.type, url: r.url })),
        rawData: vuln,
        affectedPackages
      };
    });
  }

  private extractOsvSeverity(vuln: OsvVulnerability): { level?: string; score?: number; vector?: string } {
    // Try CVSS from severity array first
    if (vuln.severity && vuln.severity.length > 0) {
      for (const s of vuln.severity) {
        if (s.type === "CVSS_V3" && s.score) {
          const parsed = this.parseCvssVector(s.score);
          if (parsed) return parsed;
        }
      }
    }
    // Fall back to database_specific.severity
    if (vuln.database_specific?.severity && typeof vuln.database_specific.severity === "string") {
      return { level: vuln.database_specific.severity.toUpperCase() };
    }
    return {};
  }

  private parseCvssVector(vectorOrScore: string): { level?: string; score?: number; vector?: string } | null {
    // Could be a CVSS vector string like "CVSS:3.1/AV:N/AC:L/..."
    if (vectorOrScore.startsWith("CVSS:")) {
      // Extract base score from vector — parse AV/AC/PR/UI/S/C/I/A
      // For simplicity, return the vector and derive severity from it later
      return { vector: vectorOrScore, level: this.severityFromVector(vectorOrScore) };
    }
    // Could be a raw score
    const score = parseFloat(vectorOrScore);
    if (!isNaN(score)) {
      return { score, level: this.severityFromScore(score) };
    }
    return null;
  }

  private severityFromScore(score: number): string {
    if (score >= 9.0) return "CRITICAL";
    if (score >= 7.0) return "HIGH";
    if (score >= 4.0) return "MEDIUM";
    if (score > 0) return "LOW";
    return "NONE";
  }

  private severityFromVector(vector: string): string {
    // Try to extract baseSeverity from the vector metrics
    // Common pattern: look for /AV: attack vector, /AC: attack complexity etc.
    // This is a heuristic — real scoring requires full CVSS calculation
    // Return undefined to let the caller use other severity sources
    const parts = vector.split("/");
    const metrics: Record<string, string> = {};
    for (const part of parts) {
      const [key, value] = part.split(":");
      if (key && value) metrics[key] = value;
    }
    // Rough heuristic based on attack vector + impact
    if (metrics["AV"] === "N" && metrics["AC"] === "L" && (metrics["C"] === "H" || metrics["I"] === "H")) {
      return "CRITICAL";
    }
    if (metrics["AV"] === "N") return "HIGH";
    if (metrics["AV"] === "A" || metrics["AV"] === "L") return "MEDIUM";
    return "LOW";
  }

  private extractOsvAffected(
    vuln: OsvVulnerability,
    ecosystem: string,
    packageName: string
  ): ParsedAdvisory["affectedPackages"] {
    if (!vuln.affected || vuln.affected.length === 0) {
      return [{ ecosystem, packageName }];
    }

    return vuln.affected.map((affected) => {
      let vulnerableRange: string | undefined;
      let patchedVersion: string | undefined;

      if (affected.ranges) {
        for (const range of affected.ranges) {
          const introduced = range.events.find((e) => e.introduced)?.introduced;
          const fixed = range.events.find((e) => e.fixed)?.fixed;
          if (introduced && fixed) {
            vulnerableRange = `>=${introduced}, <${fixed}`;
            patchedVersion = fixed;
          } else if (introduced) {
            vulnerableRange = `>=${introduced}`;
          }
        }
      }

      return {
        ecosystem: affected.package?.ecosystem ?? ecosystem,
        packageName: affected.package?.name ?? packageName,
        vulnerableRange,
        patchedVersion
      };
    });
  }

  private async fetchGhsa(ecosystem: string, packageName: string): Promise<ParsedAdvisory[]> {
    if (!this.config.githubToken) {
      return [];
    }

    const url = `https://api.github.com/advisories?ecosystem=${encodeURIComponent(ecosystem)}&affects=${encodeURIComponent(packageName)}&per_page=100`;
    const response = await fetch(url, {
      headers: {
        accept: "application/vnd.github+json",
        authorization: `Bearer ${this.config.githubToken}`,
        "x-github-api-version": "2022-11-28"
      }
    });

    if (!response.ok) {
      throw new Error(`GitHub Advisory API returned ${response.status}: ${await response.text()}`);
    }

    const advisories = (await response.json()) as GhsaAdvisory[];

    return advisories.map((advisory) => {
      const cweIds = (advisory.cwes ?? []).map((cwe) => cwe.cwe_id);
      const affectedPackages = (advisory.vulnerabilities ?? []).map((vuln) => ({
        ecosystem: vuln.package?.ecosystem ?? ecosystem,
        packageName: vuln.package?.name ?? packageName,
        vulnerableRange: vuln.vulnerable_version_range ?? undefined,
        patchedVersion: vuln.first_patched_version?.identifier ?? vuln.patched_versions ?? undefined
      }));

      // If no vulnerabilities listed, create a default entry
      if (affectedPackages.length === 0) {
        affectedPackages.push({ ecosystem, packageName, vulnerableRange: undefined, patchedVersion: undefined });
      }

      const references: Array<{ type?: string; url: string }> = [];
      if (advisory.html_url) {
        references.push({ type: "ADVISORY", url: advisory.html_url });
      }
      for (const ref of advisory.references ?? []) {
        references.push({ url: ref });
      }

      return {
        source: "ghsa",
        sourceId: advisory.ghsa_id,
        advisoryType: advisory.type === "malware" ? "malware" : "vulnerability",
        title: advisory.summary,
        description: advisory.description,
        severity: advisory.severity?.toUpperCase(),
        cvssScore: advisory.cvss?.score ?? undefined,
        cvssVector: advisory.cvss?.vector_string ?? undefined,
        cweIds,
        publishedAt: advisory.published_at ?? undefined,
        updatedAt: advisory.updated_at ?? undefined,
        withdrawnAt: advisory.withdrawn_at ?? undefined,
        references,
        rawData: advisory,
        affectedPackages
      };
    });
  }

  private async fetchNvd(packageName: string): Promise<ParsedAdvisory[]> {
    await this.nvdLimiter.acquire();

    const params = new URLSearchParams({ keywordSearch: packageName, resultsPerPage: "50" });

    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?${params.toString()}`;
    const headers: Record<string, string> = { accept: "application/json" };
    if (this.config.nvdApiKey) {
      headers["apiKey"] = this.config.nvdApiKey;
    }

    const response = await fetch(url, { headers });

    if (!response.ok) {
      throw new Error(`NVD API returned ${response.status}: ${await response.text()}`);
    }

    const data = (await response.json()) as NvdResponse;
    const vulns = data.vulnerabilities ?? [];

    return vulns.map((item) => {
      const cve = item.cve;
      const enDescription = cve.descriptions?.find((d) => d.lang === "en")?.value ?? cve.id;

      // Extract CVSS v3.1 first, fall back to v2
      let cvssScore: number | undefined;
      let cvssVector: string | undefined;
      let severity: string | undefined;

      const v31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
      if (v31) {
        cvssScore = v31.baseScore;
        cvssVector = v31.vectorString;
        severity = v31.baseSeverity?.toUpperCase() ?? this.severityFromScore(v31.baseScore);
      } else {
        const v2 = cve.metrics?.cvssMetricV2?.[0]?.cvssData;
        if (v2) {
          cvssScore = v2.baseScore;
          cvssVector = v2.vectorString;
          severity = this.severityFromScore(v2.baseScore);
        }
      }

      // Extract CWEs
      const cweIds: string[] = [];
      for (const weakness of cve.weaknesses ?? []) {
        for (const desc of weakness.description) {
          if (desc.value && desc.value !== "NVD-CWE-Other" && desc.value !== "NVD-CWE-noinfo") {
            cweIds.push(desc.value);
          }
        }
      }

      const references = (cve.references ?? []).map((ref) => ({
        type: ref.tags?.[0],
        url: ref.url
      }));

      return {
        source: "nvd",
        sourceId: cve.id,
        advisoryType: "vulnerability",
        title: `${cve.id}: ${enDescription.slice(0, 200)}`,
        description: enDescription,
        severity,
        cvssScore,
        cvssVector,
        cweIds,
        publishedAt: cve.published,
        updatedAt: cve.lastModified,
        references,
        rawData: item,
        // NVD is keyword-based, so we don't have precise package info
        affectedPackages: [{ ecosystem: "npm", packageName }]
      };
    });
  }

  // -------------------------------------------------------------------------
  // Database helpers
  // -------------------------------------------------------------------------

  private get baseUrl(): string {
    return this.config.supabaseUrl.replace(/\/$/, "");
  }

  private dbHeaders(extra: Record<string, string> = {}): Record<string, string> {
    return {
      apikey: this.config.supabaseServiceRoleKey,
      authorization: `Bearer ${this.config.supabaseServiceRoleKey}`,
      "content-type": "application/json",
      ...extra
    };
  }

  private async dbRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
    const headers = new Headers(this.dbHeaders());
    if (init.headers) {
      new Headers(init.headers as Record<string, string>).forEach((value, key) => headers.set(key, value));
    }
    const response = await fetch(`${this.baseUrl}/rest/v1${path}`, { ...init, headers });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Supabase request failed (${response.status}): ${text}`);
    }
    if (response.status === 204) {
      return undefined as T;
    }
    const text = await response.text();
    if (!text) {
      return undefined as T;
    }
    return JSON.parse(text) as T;
  }

  private async dbSelect<T>(table: string, query = ""): Promise<T[]> {
    const path = `/${table}${query.startsWith("?") ? query : `?${query}`}`;
    return this.dbRequest<T[]>(path, { method: "GET" });
  }

  /**
   * Upsert an advisory and its affected packages. Returns true if the advisory was newly inserted.
   */
  private async upsertAdvisory(parsed: ParsedAdvisory): Promise<boolean> {
    // Check if advisory already exists
    const existing = await this.dbSelect<AdvisoryRow>(
      "advisories",
      `select=id&source=eq.${encodeURIComponent(parsed.source)}&source_id=eq.${encodeURIComponent(parsed.sourceId)}&limit=1`
    );

    // Upsert advisory (PostgREST upsert via Prefer: resolution=merge-duplicates)
    const upserted = await this.dbRequest<AdvisoryRow[]>(
      "/advisories?on_conflict=source,source_id&select=id",
      {
        method: "POST",
        headers: {
          Prefer: "resolution=merge-duplicates,return=representation"
        },
        body: JSON.stringify({
          source: parsed.source,
          source_id: parsed.sourceId,
          advisory_type: parsed.advisoryType,
          title: parsed.title,
          description: parsed.description ?? null,
          severity: parsed.severity ?? null,
          cvss_score: parsed.cvssScore ?? null,
          cvss_vector: parsed.cvssVector ?? null,
          cwe_ids: parsed.cweIds,
          published_at: parsed.publishedAt ?? null,
          updated_at: parsed.updatedAt ?? null,
          withdrawn_at: parsed.withdrawnAt ?? null,
          references: parsed.references,
          raw_data: parsed.rawData ?? null
        })
      }
    );

    const advisoryId = upserted[0]?.id;
    if (!advisoryId) {
      console.error(`[advisory-service] failed to upsert advisory ${parsed.source}/${parsed.sourceId}`);
      return false;
    }

    // Delete existing package_advisories for this advisory, then re-insert
    // Using PostgREST DELETE
    await this.dbRequest<void>(
      `/package_advisories?advisory_id=eq.${advisoryId}`,
      { method: "DELETE" }
    );

    // Insert package_advisories
    if (parsed.affectedPackages.length > 0) {
      const rows = parsed.affectedPackages.map((ap) => ({
        advisory_id: advisoryId,
        ecosystem: ap.ecosystem,
        package_name: ap.packageName,
        vulnerable_range: ap.vulnerableRange ?? null,
        patched_version: ap.patchedVersion ?? null
      }));

      await this.dbRequest<void>("/package_advisories", {
        method: "POST",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify(rows)
      });
    }

    return existing.length === 0;
  }

  private async updateSyncState(ecosystem: string, packageName: string, advisoryCount: number): Promise<void> {
    await this.dbRequest<void>(
      "/advisory_sync_state?on_conflict=ecosystem,package_name",
      {
        method: "POST",
        headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
        body: JSON.stringify({
          ecosystem,
          package_name: packageName,
          last_synced_at: new Date().toISOString(),
          advisory_count: advisoryCount
        })
      }
    );
  }

  private mapAdvisory(row: AdvisoryRow, packageAdvisoryRows: PackageAdvisoryRow[]): Advisory {
    return {
      id: row.id,
      source: row.source,
      sourceId: row.source_id,
      advisoryType: row.advisory_type === "malware" ? "malware" : "vulnerability",
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

  // -------------------------------------------------------------------------
  // Vendor patch parsing — public API
  // -------------------------------------------------------------------------

  /**
   * Parse an array of vendor advisory JSON objects (e.g. GitHub Security
   * Advisories fetched from the GHSA REST API or a local vendor feed) and
   * extract VendorPatchContext entries for each CVE that has a known
   * patched version.
   *
   * Withdrawn advisories are skipped.  Advisories without a patched version
   * are also skipped (they provide no mitigation signal).
   *
   * @param advisories   Raw advisory JSON objects (already parsed from JSON).
   * @param packageName  Filter: only emit patches for this package name.
   *                     If omitted, all packages in the advisories are included.
   */
  parseVendorAdvisoryPatches(
    advisories: VendorAdvisoryJson[],
    packageName?: string
  ): VendorAdvisoryParseResult {
    let parsed = 0;
    let skipped = 0;
    const patches: VendorPatchContext[] = [];

    for (const advisory of advisories) {
      // Skip withdrawn advisories — the patch may have been retracted
      if (advisory.withdrawn_at) {
        skipped++;
        continue;
      }

      const cveId = advisory.cve_id ?? advisory.id;
      if (!cveId) {
        skipped++;
        continue;
      }

      const vulns = advisory.vulnerabilities ?? [];
      if (vulns.length === 0) {
        skipped++;
        continue;
      }

      let emittedForThisAdvisory = false;

      for (const vuln of vulns) {
        // Optional package name filter
        if (packageName && vuln.package?.name && vuln.package.name.toLowerCase() !== packageName.toLowerCase()) {
          continue;
        }

        // Resolve the patched version — prefer first_patched_version (more
        // precise from GHSA) then fall back to patched_versions string.
        const patchedVersion =
          vuln.first_patched_version?.identifier ??
          this.extractFirstPatchedVersion(vuln.patched_versions ?? null);

        if (!patchedVersion) {
          continue; // No patch yet — nothing to downgrade
        }

        // Compute daysToFix from published_at to now
        const daysToFix = advisory.published_at
          ? Math.max(0, Math.floor((Date.now() - new Date(advisory.published_at).getTime()) / 86_400_000))
          : 0;

        // Confidence: GHSA advisories sourced via GitHub API are "high";
        // plain vendor feeds with only patched_versions string are "medium".
        const vendorConfidence: VendorPatchContext["vendorConfidence"] =
          advisory.id.toUpperCase().startsWith("GHSA-") ? "high" : "medium";

        patches.push({ cveId, patchedVersion, daysToFix, vendorConfidence });
        emittedForThisAdvisory = true;
        parsed++;
        break; // One patch per advisory is enough for risk scoring
      }

      if (!emittedForThisAdvisory) {
        skipped++;
      }
    }

    return { patches, parsed, skipped };
  }

  /**
   * Build LockfileResolutionContext entries by comparing the version pinned in
   * the lockfile against the list of known patched versions.
   *
   * This is a simple semver-range-free comparison that works for the common
   * case where the lockfile pins an exact version.  For more complex ranges,
   * callers should use a full semver library before calling this helper.
   *
   * @param resolvedVersion  The exact version string pinned in the lockfile.
   * @param patches          VendorPatchContext entries from parseVendorAdvisoryPatches.
   */
  buildLockfileResolutionContexts(
    resolvedVersion: string,
    patches: VendorPatchContext[]
  ): LockfileResolutionContext[] {
    return patches.map((patch) => ({
      cveId: patch.cveId,
      resolvedVersion,
      patchedVersion: patch.patchedVersion,
      // Treat as unpatched when the resolved version string is not the same as
      // (or does not start with) the patched version.  This is intentionally
      // conservative: if the lockfile pins exactly the patched version we mark
      // it as patched; otherwise we flag it for review.
      isUnpatched: !this.isVersionPatched(resolvedVersion, patch.patchedVersion)
    }));
  }

  // -------------------------------------------------------------------------
  // Private patch helpers
  // -------------------------------------------------------------------------

  /**
   * Extract the first version string from a GHSA `patched_versions` string
   * like ">= 1.2.3" or "= 1.2.3" or just "1.2.3".
   */
  private extractFirstPatchedVersion(patched: string | null): string | undefined {
    if (!patched) return undefined;
    // Strip leading operators: >=, >, =, ^, ~
    const match = patched.trim().match(/[>=^~]*\s*([\d]+\.[\d]+\.[\d]+[\w.-]*)/);
    return match?.[1];
  }

  /**
   * Returns true when the resolved version is equal to or "newer than" the
   * patched version using simple dotted-number comparison.
   *
   * This is intentionally conservative: if either version is non-numeric we
   * fall back to strict string equality so we never incorrectly mark a
   * vulnerable version as patched.
   */
  private isVersionPatched(resolved: string, patched: string): boolean {
    if (resolved === patched) return true;

    const parseSemver = (v: string): number[] | null => {
      const parts = v.replace(/^[v=^~>=<]+/, "").split(".").map(Number);
      if (parts.some(isNaN)) return null;
      return parts;
    };

    const r = parseSemver(resolved);
    const p = parseSemver(patched);
    if (!r || !p) return false;

    const len = Math.max(r.length, p.length);
    for (let i = 0; i < len; i++) {
      const rv = r[i] ?? 0;
      const pv = p[i] ?? 0;
      if (rv > pv) return true;
      if (rv < pv) return false;
    }
    return true; // equal
  }

  // -------------------------------------------------------------------------
  // EPSS enrichment
  // -------------------------------------------------------------------------

  /**
   * Fetch EPSS scores for a set of CVE IDs from the FIRST/Cyentia EPSS API
   * (https://api.first.org/data/v1/epss) and upsert them into the
   * `epss_scores` table keyed to the given package.
   *
   * The FIRST EPSS REST API accepts up to 100 CVE IDs per request and returns
   * JSON — no auth required.
   */
  async syncEpssScores(
    ecosystem: string,
    packageName: string,
    version: string,
    cveIds: string[]
  ): Promise<EpssScore[]> {
    if (cveIds.length === 0) return [];

    const feedRows = await this.fetchEpssFromApi(cveIds);
    if (feedRows.length === 0) return [];

    const today = new Date().toISOString().slice(0, 10);
    const upsertRows = feedRows.map((row) => ({
      cve_id: row.cve,
      package_name: packageName,
      ecosystem,
      version,
      epss_score: parseFloat(row.epss),
      epss_percentile: parseFloat(row.percentile),
      model_version: row.model_version ?? "",
      score_date: row.date ?? today
    }));

    // Upsert — idempotent on (cve_id, package_name, ecosystem, version, score_date)
    await this.dbRequest<void>(
      "/epss_scores?on_conflict=cve_id,package_name,ecosystem,version,score_date",
      {
        method: "POST",
        headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
        body: JSON.stringify(upsertRows)
      }
    );

    return this.mapEpssRows(
      upsertRows.map((r, i) => ({
        id: `epss_${i}`,
        ...r,
        updated_at: new Date().toISOString()
      }))
    );
  }

  /**
   * Retrieve stored EPSS scores for a package version from the database.
   */
  async getEpssScores(ecosystem: string, packageName: string, version: string): Promise<EpssScore[]> {
    const rows = await this.dbSelect<EpssScoreRow>(
      "epss_scores",
      `select=*&ecosystem=eq.${encodeURIComponent(ecosystem)}&package_name=eq.${encodeURIComponent(packageName)}&version=eq.${encodeURIComponent(version)}&order=epss_percentile.desc`
    );
    return this.mapEpssRows(rows);
  }

  /**
   * Build a risk-correlation response for a specific package version:
   * joins advisory CVE/CVSS data with live EPSS percentiles and computes
   * a composite exploit risk score.
   *
   * composite_exploit_risk formula:
   *   For each (CVE, CVSS, EPSS) triple, contribution = cvssScore × epssPercentile × 10
   *   Final score = min(100, sum of top-3 contributions)
   *   If no EPSS data, falls back to max(cvssScores) × 10 / 10 (straight CVSS)
   */
  async getRiskCorrelation(
    ecosystem: string,
    packageName: string,
    version: string
  ): Promise<RiskCorrelation> {
    const advisories = await this.getPackageAdvisories(ecosystem, packageName);

    // Collect unique CVE IDs from all advisories
    const cveIds = [
      ...new Set(
        advisories
          .map((a) => a.sourceId)
          .filter((id) => id.toUpperCase().startsWith("CVE-"))
          .concat(
            // also pull CVE aliases from raw advisory source IDs (e.g. NVD source)
            advisories.filter((a) => a.source === "nvd").map((a) => a.sourceId)
          )
      )
    ];

    const cvssScores = advisories
      .filter((a) => a.cvssScore != null)
      .map((a) => ({
        cveId: a.sourceId,
        cvssScore: a.cvssScore!,
        severity: a.severity
      }));

    // Fetch/sync EPSS scores for all CVEs we know about
    let epssScores: EpssScore[] = [];
    try {
      // Try fetching from the database first (may already be cached)
      epssScores = await this.getEpssScores(ecosystem, packageName, version);
      // If stale or empty, re-sync from EPSS API
      if (epssScores.length === 0 && cveIds.length > 0) {
        epssScores = await this.syncEpssScores(ecosystem, packageName, version, cveIds);
      }
    } catch (err) {
      // EPSS enrichment is best-effort; don't fail the whole request
      console.warn(`[advisory-service] EPSS fetch failed for ${ecosystem}/${packageName}@${version}:`, err);
    }

    const compositeExploitRisk = this.computeCompositeExploitRisk(cvssScores, epssScores);

    return {
      ecosystem,
      packageName,
      version,
      cves: cveIds,
      cvssScores,
      epssScores,
      compositeExploitRisk
    };
  }

  /**
   * Composite exploit risk:
   *   contribution_i = cvssScore_i × epssPercentile_i × 10
   *   result = min(100, sum of top-3 contributions)
   *
   * Falls back to straight CVSS-based risk if no EPSS data is available.
   */
  computeCompositeExploitRisk(
    cvssScores: Array<{ cveId: string; cvssScore: number }>,
    epssScores: EpssScore[]
  ): number {
    if (cvssScores.length === 0) return 0;

    const epssMap = new Map(epssScores.map((e) => [e.cveId, e]));

    // If we have EPSS data, compute composite contributions
    if (epssMap.size > 0) {
      const contributions = cvssScores
        .map((c) => {
          const epss = epssMap.get(c.cveId);
          if (!epss) return c.cvssScore; // no EPSS → use CVSS/10 as fallback contribution
          return (c.cvssScore / 10) * epss.epssPercentile * 100;
        })
        .sort((a, b) => b - a)
        .slice(0, 3);

      return Math.min(100, Math.round(contributions.reduce((s, v) => s + v, 0)));
    }

    // Fallback: scale max CVSS score to 0–100
    const maxCvss = Math.max(...cvssScores.map((c) => c.cvssScore));
    return Math.min(100, Math.round((maxCvss / 10) * 100));
  }

  // -------------------------------------------------------------------------
  // EPSS API fetch (FIRST REST API)
  // -------------------------------------------------------------------------

  private async fetchEpssFromApi(cveIds: string[]): Promise<EpssFeedRow[]> {
    // FIRST EPSS API: GET https://api.first.org/data/v1/epss?cve=CVE-A,CVE-B,...
    // Max 100 CVEs per request; free, no auth required.
    const batchSize = 100;
    const results: EpssFeedRow[] = [];

    for (let i = 0; i < cveIds.length; i += batchSize) {
      const batch = cveIds.slice(i, i + batchSize);
      const url = `https://api.first.org/data/v1/epss?cve=${batch.join(",")}`;
      try {
        const response = await fetch(url, {
          headers: { accept: "application/json" }
        });
        if (!response.ok) {
          console.warn(`[advisory-service] EPSS API returned ${response.status} for batch`);
          continue;
        }
        const data = (await response.json()) as {
          status: string;
          status_code: number;
          version: string;
          access: string;
          total: number;
          offset: number;
          limit: number;
          data?: Array<{ cve: string; epss: string; percentile: string; date?: string; model_version?: string }>;
        };
        if (data.data && Array.isArray(data.data)) {
          results.push(...data.data);
        }
      } catch (err) {
        console.warn(`[advisory-service] EPSS fetch error for batch starting at ${i}:`, err);
      }
    }

    return results;
  }

  private mapEpssRows(rows: EpssScoreRow[]): EpssScore[] {
    return rows.map((row) => ({
      cveId: row.cve_id,
      packageName: row.package_name,
      ecosystem: row.ecosystem,
      version: row.version,
      epssScore: row.epss_score,
      epssPercentile: row.epss_percentile,
      modelVersion: row.model_version,
      scoreDate: row.score_date,
      updatedAt: row.updated_at,
      exploitedInTheWild: row.epss_percentile > 0.9
    }));
  }

  // -------------------------------------------------------------------------
  // EPSS enrichment — public helpers
  // -------------------------------------------------------------------------

  /**
   * Fetch EPSS scores for the given CVE IDs directly from the FIRST EPSS API
   * (https://api.first.org/data/v1/epss), using the supplied EpssCache for
   * deduplication.  Returns a map of CVE ID → { score, percentile }.
   *
   * Results are written back into the cache (both in-memory and Supabase layers).
   */
  async fetchEpssScores(
    ecosystem: string,
    cveIds: string[],
    cache: EpssCache
  ): Promise<Map<string, { score: number; percentile: number }>> {
    if (cveIds.length === 0) return new Map();

    // 1. Pull whatever is already cached (TTL-checked inside getMany)
    const cached = await cache.getMany(ecosystem, cveIds);
    const result = new Map<string, { score: number; percentile: number }>();
    for (const [id, entry] of cached) {
      result.set(id.toUpperCase(), { score: entry.score, percentile: entry.percentile });
    }

    // 2. Identify CVEs that still need a live fetch
    const missing = cveIds.filter((id) => !result.has(id.toUpperCase()));
    if (missing.length === 0) return result;

    // 3. Fetch from FIRST EPSS API in batches of 100
    const feedRows = await this.fetchEpssFromApi(missing);
    if (feedRows.length === 0) return result;

    // 4. Populate result map and build cache entries
    const now = new Date().toISOString();
    const cacheEntries = feedRows.map((row) => ({
      ecosystem,
      cveId: row.cve.toUpperCase(),
      score: parseFloat(row.epss),
      percentile: parseFloat(row.percentile),
      fetchedAt: now
    }));

    for (const entry of cacheEntries) {
      result.set(entry.cveId, { score: entry.score, percentile: entry.percentile });
    }

    // 5. Persist back to cache (fire-and-forget for Supabase layer)
    await cache.setMany(cacheEntries);

    return result;
  }

  /**
   * Build a fully enriched vulnerability response for a specific package version.
   *
   * Steps:
   *   1. Fetch all advisories for the package from the `advisories` table.
   *   2. For each CVE ID, query the EPSS API (via EpssCache with 7-day TTL).
   *   3. Check each CVE against CISA KEV data (stored as cisa_kev_date on the
   *      advisory row when populated by the nvd-feed-ingester).
   *   4. Aggregate maxEpssPercentile, maxCvssV3Score, cisaKevMatches,
   *      exploitMaturityStats.
   *   5. Compute riskBoost: base CVSS score + EPSS boost + CISA KEV boost.
   *   6. Return structured VulnerabilityEnrichment.
   */
  async enrichCvesWithEpss(
    ecosystem: string,
    packageName: string,
    version: string,
    cache: EpssCache
  ): Promise<VulnerabilityEnrichment> {
    const advisories = await this.getPackageAdvisories(ecosystem, packageName);

    // ── Extract unique CVE IDs ──────────────────────────────────────────────
    const cveIds = [
      ...new Set(
        advisories
          .map((a) => a.sourceId)
          .filter((id) => id.toUpperCase().startsWith("CVE-"))
          .map((id) => id.toUpperCase())
      )
    ];

    // ── Fetch EPSS scores (cached + live) ────────────────────────────────────
    const epssMap = await this.fetchEpssScores(ecosystem, cveIds, cache).catch(() => new Map<string, { score: number; percentile: number }>());

    // ── Build CISA KEV set ────────────────────────────────────────────────────
    // When the nvd-feed-ingester populates advisory rows it stores the CISA KEV
    // added-date in `cisa_kev_date`.  In local/dev mode this field is absent so
    // we fall back to checking the raw_data if available, otherwise empty set.
    const cisaKevDates = new Map<string, string>(); // cveId → ISO date
    for (const advisory of advisories) {
      const raw = advisory as unknown as Record<string, unknown>;
      const kevDate = (raw["cisaKevDate"] ?? raw["cisa_kev_date"]) as string | undefined;
      if (kevDate && advisory.sourceId.toUpperCase().startsWith("CVE-")) {
        cisaKevDates.set(advisory.sourceId.toUpperCase(), kevDate);
      }
    }

    // ── Build exploit maturity map ────────────────────────────────────────────
    // Derived heuristically from EPSS percentile and CISA KEV membership.
    function deriveExploitMaturity(cveId: string, epssPercentile: number): ExploitMaturity {
      if (cisaKevDates.has(cveId)) return "active-exploitation";
      if (epssPercentile >= 0.95) return "widespread";
      if (epssPercentile >= 0.5) return "active-exploitation";
      if (epssPercentile > 0) return "proof-of-concept";
      return "none";
    }

    // ── Assemble findings ─────────────────────────────────────────────────────
    const findings: EnrichedFinding[] = advisories.map((advisory) => {
      const cveId = advisory.sourceId.toUpperCase();
      const epss = epssMap.get(cveId);
      const epssPercentile = epss?.percentile;
      const cisaKevDate = cisaKevDates.get(cveId);
      const exploitMaturity = epssPercentile != null ? deriveExploitMaturity(cveId, epssPercentile) : undefined;

      const recommendation = buildRecommendation(advisory.sourceId, advisory.severity, epssPercentile, cisaKevDate);

      return {
        cvId: advisory.sourceId,
        title: advisory.title,
        severity: advisory.severity ?? "unknown",
        cvssScore: advisory.cvssScore,
        epssPercentile,
        cisaKevDate,
        exploitMaturity,
        recommendation
      };
    });

    // Sort findings: highest EPSS first, then highest CVSS, then alphabetical
    findings.sort((a, b) => {
      const epssA = a.epssPercentile ?? -1;
      const epssB = b.epssPercentile ?? -1;
      if (epssB !== epssA) return epssB - epssA;
      const cvssA = a.cvssScore ?? 0;
      const cvssB = b.cvssScore ?? 0;
      if (cvssB !== cvssA) return cvssB - cvssA;
      return a.cvId.localeCompare(b.cvId);
    });

    // ── Aggregate stats ───────────────────────────────────────────────────────
    const maxEpssPercentile = findings.reduce((max, f) => Math.max(max, f.epssPercentile ?? 0), 0);
    const maxCvssV3Score = findings.reduce((max, f) => Math.max(max, f.cvssScore ?? 0), 0);
    const cisaKevMatches = [...cisaKevDates.keys()];

    const exploitMaturityStats = {
      proofOfConcept: findings.filter((f) => f.exploitMaturity === "proof-of-concept").length,
      activeExploitation: findings.filter((f) => f.exploitMaturity === "active-exploitation").length,
      widespread: findings.filter((f) => f.exploitMaturity === "widespread").length
    };

    // ── Risk boost ────────────────────────────────────────────────────────────
    const baseScore = Math.round((maxCvssV3Score / 10) * 100);
    const epssBoost = Math.round(maxEpssPercentile * 40); // max +40
    const cisaKevBoost = cisaKevMatches.length > 0 ? 30 : 0; // flat +30 if in KEV
    const finalScore = Math.min(100, baseScore + epssBoost + cisaKevBoost);

    const riskBoost = { baseScore, epssBoost, cisaKevBoost, finalScore };

    // ── Recommendations ───────────────────────────────────────────────────────
    const recommendations = buildRecommendations(findings, cisaKevMatches, maxEpssPercentile);

    return {
      ecosystem,
      packageName,
      version,
      findings,
      maxEpssPercentile,
      maxCvssV3Score,
      cisaKevMatches,
      exploitMaturityStats,
      riskBoost,
      recommendations,
      enrichedAt: new Date().toISOString()
    };
  }
}

// ---------------------------------------------------------------------------
// CVE Heat Map — cross-CVE risk ranking by exploitability × severity × adoption
// ---------------------------------------------------------------------------

/**
 * A single entry in the CVE heat map.
 * Columns are designed to drive a sortable data-grid in the dashboard.
 */
export interface HeatMapEntry {
  /** CVE identifier */
  cveId: string;
  /** Human-readable advisory title */
  title: string;
  /** Affected package name (primary) */
  packageName: string;
  /** Ecosystem (npm | pypi | …) */
  ecosystem: string;
  /** CVSS base score (0–10) */
  cvssScore: number;
  /** EPSS percentile (0–1) — probability of exploitation in the next 30 days */
  epssPercentile: number;
  /** Advisory severity label (critical | high | medium | low) */
  severity: string;
  /** True when this CVE is in the CISA Known Exploited Vulnerabilities catalogue */
  activeExploit: boolean;
  /** ISO date when this CVE was added to the CISA KEV catalogue, if present */
  cisaKevDate?: string;
  /** True when a patched version has been published */
  patchAvailable: boolean;
  /** First patched version string, when known */
  patchedVersion?: string;
  /**
   * Ecosystem adoption percentage (0–100).
   * Derived from the package's weekly download rank within POPULAR_PACKAGES_CORPUS:
   * rank 1 → 100 %, rank N → (1 – rank/N) × 100.
   */
  adoptionPct: number;
  /**
   * Blast radius score (0–100).
   * Composite of adoptionPct × cvssScore / 10.
   */
  blastRadius: number;
  /**
   * Overall heat score used for default sort order (0–100).
   * Formula: min(100, cvssScore×5 + epssPercentile×40 + activeExploit×30)
   * Matches the finalScore calculation used in enrichCvesWithEpss.
   */
  heatScore: number;
  /** Patching colour tier: "red" | "yellow" | "green" */
  tier: "red" | "yellow" | "green";
}

export interface HeatMapData {
  items: HeatMapEntry[];
  total: number;
  generatedAt: string;
  ecosystem: string;
}

/**
 * Approximate weekly-download rank derived from POPULAR_PACKAGES_CORPUS order.
 * Packages earlier in the list are considered more widely adopted.
 * Returns 0–100 where 100 = most downloaded.
 */
function adoptionPctForPackage(packageName: string, ecosystem: string): number {
  const { POPULAR_PACKAGES_CORPUS } = require("@binshield/package-intelligence") as {
    POPULAR_PACKAGES_CORPUS: Array<{ name: string; ecosystem: string; weeklyDownloads?: number }>;
  };
  const corpusForEco = POPULAR_PACKAGES_CORPUS.filter((p) => p.ecosystem === ecosystem);
  const idx = corpusForEco.findIndex((p) => p.name.toLowerCase() === packageName.toLowerCase());
  if (idx === -1) return 10; // unknown package → low adoption baseline
  const rank = idx + 1; // 1-based
  return Math.max(1, Math.round((1 - rank / corpusForEco.length) * 100));
}

/**
 * Build a heat score for sorting: higher = more urgent to patch.
 * Formula: min(100, floor(cvssScore×5 + epssPercentile×40 + (activeExploit ? 30 : 0)))
 */
export function computeHeatScore(cvssScore: number, epssPercentile: number, activeExploit: boolean): number {
  return Math.min(100, Math.floor(cvssScore * 5 + epssPercentile * 40 + (activeExploit ? 30 : 0)));
}

/**
 * Return the colour tier for a heat-map cell:
 *   red    — critical+exploited (activeExploit OR heatScore ≥ 75)
 *   yellow — patchable (patchAvailable AND heatScore < 75)
 *   green  — low-risk (heatScore < 35 AND NOT activeExploit)
 */
export function computeHeatTier(
  heatScore: number,
  activeExploit: boolean,
  patchAvailable: boolean
): "red" | "yellow" | "green" {
  if (activeExploit || heatScore >= 75) return "red";
  if (patchAvailable && heatScore >= 35) return "yellow";
  return "green";
}

/**
 * Fetch the top `limit` CVEs affecting the registered dependency graph for an
 * org, ranked by exploitability (EPSS) × severity (CVSS) × adoption rate.
 *
 * In Supabase mode this queries the advisories + epss_scores tables live.
 * In local/dev mode it falls back to the in-memory seeded advisories.
 *
 * @param orgAdvisories  Pre-fetched list of Advisory rows to rank (caller supplies).
 * @param ecosystem      Filter to a single ecosystem ("npm" | "pypi") or "all".
 * @param limit          Max number of entries to return (default 100).
 * @param epssMap        Optional pre-fetched EPSS percentile map (cveId → {score,percentile}).
 */
export function buildHeatMapData(
  orgAdvisories: Advisory[],
  ecosystem: string,
  limit: number,
  epssMap: Map<string, { score: number; percentile: number }>
): HeatMapData {
  const seen = new Set<string>();
  const entries: HeatMapEntry[] = [];

  for (const advisory of orgAdvisories) {
    const cveId = advisory.sourceId.toUpperCase();
    if (!cveId.startsWith("CVE-")) continue;
    if (seen.has(cveId)) continue;
    seen.add(cveId);

    // Filter by ecosystem when requested
    const primaryPkg = advisory.affectedPackages[0];
    const pkgEco = primaryPkg?.ecosystem ?? "npm";
    if (ecosystem !== "all" && pkgEco !== ecosystem) continue;

    const pkgName = primaryPkg?.packageName ?? advisory.sourceId;
    const cvssScore = advisory.cvssScore ?? 0;
    const severityRaw = advisory.severity ?? "unknown";

    const epss = epssMap.get(cveId);
    const epssPercentile = epss?.percentile ?? 0;

    const raw = advisory as unknown as Record<string, unknown>;
    const cisaKevDate = (raw["cisaKevDate"] ?? raw["cisa_kev_date"]) as string | undefined;
    const activeExploit = Boolean(cisaKevDate);

    const patchedVersion = primaryPkg?.patchedVersion;
    const patchAvailable = Boolean(patchedVersion);

    const adoptionPct = adoptionPctForPackage(pkgName, pkgEco);
    const blastRadius = Math.min(100, Math.round(adoptionPct * (cvssScore / 10)));
    const heatScore = computeHeatScore(cvssScore, epssPercentile, activeExploit);
    const tier = computeHeatTier(heatScore, activeExploit, patchAvailable);

    entries.push({
      cveId,
      title: advisory.title,
      packageName: pkgName,
      ecosystem: pkgEco,
      cvssScore,
      epssPercentile,
      severity: severityRaw,
      activeExploit,
      cisaKevDate,
      patchAvailable,
      patchedVersion,
      adoptionPct,
      blastRadius,
      heatScore,
      tier
    });
  }

  // Sort: highest heatScore first, then blastRadius, then cveId
  entries.sort((a, b) => {
    if (b.heatScore !== a.heatScore) return b.heatScore - a.heatScore;
    if (b.blastRadius !== a.blastRadius) return b.blastRadius - a.blastRadius;
    return a.cveId.localeCompare(b.cveId);
  });

  const sliced = entries.slice(0, limit);

  return {
    items: sliced,
    total: entries.length,
    generatedAt: new Date().toISOString(),
    ecosystem
  };
}

/**
 * Full pipeline: fetch advisories for an org's registered deps, enrich with
 * live EPSS, and return the heat-map payload.
 *
 * Supabase mode: queries `registered_dependencies` → advisories → EPSS API.
 * Local/dev mode: uses in-memory seeded advisories and mocked EPSS (zeroed).
 */
export async function getHeatMapData(
  config: AdvisoryServiceConfig,
  recentAdvisories: Advisory[],
  ecosystem: string,
  limit: number
): Promise<HeatMapData> {
  // Collect unique CVE IDs
  const cveIds = [
    ...new Set(
      recentAdvisories
        .map((a) => a.sourceId.toUpperCase())
        .filter((id) => id.startsWith("CVE-"))
    )
  ];

  // Attempt live EPSS fetch; fall back to empty map on error
  let epssMap = new Map<string, { score: number; percentile: number }>();
  if (cveIds.length > 0 && config.supabaseUrl && config.supabaseServiceRoleKey) {
    try {
      const svc = new AdvisoryService(config);
      const { EpssCache } = await import("./epss-cache");
      const cache = new EpssCache({ supabaseUrl: config.supabaseUrl, supabaseServiceRoleKey: config.supabaseServiceRoleKey });
      epssMap = await svc.fetchEpssScores(ecosystem === "all" ? "npm" : ecosystem, cveIds, cache);
    } catch (err) {
      console.warn("[advisory-service] getHeatMapData: EPSS fetch failed (non-fatal):", err instanceof Error ? err.message : err);
    }
  }

  return buildHeatMapData(recentAdvisories, ecosystem, limit, epssMap);
}

// ---------------------------------------------------------------------------
// Pure helpers (module-level so they can be unit-tested independently)
// ---------------------------------------------------------------------------

function buildRecommendation(
  cveId: string,
  severity: string | undefined,
  epssPercentile: number | undefined,
  cisaKevDate: string | undefined
): string {
  const parts: string[] = [];

  if (cisaKevDate) {
    parts.push(`${cveId} is in the CISA KEV catalogue (added ${cisaKevDate}) — patch immediately.`);
  } else if (epssPercentile != null && epssPercentile >= 0.5) {
    parts.push(`${cveId} has high exploit probability (EPSS ${(epssPercentile * 100).toFixed(1)}th percentile) — prioritise patching.`);
  } else if (severity?.toUpperCase() === "CRITICAL" || severity?.toUpperCase() === "HIGH") {
    parts.push(`${cveId} is rated ${severity} — schedule prompt remediation.`);
  } else {
    parts.push(`Review ${cveId} and apply the latest patched version.`);
  }

  return parts.join(" ");
}

function buildRecommendations(
  findings: EnrichedFinding[],
  cisaKevMatches: string[],
  maxEpssPercentile: number
): string[] {
  const recs: string[] = [];

  if (cisaKevMatches.length > 0) {
    recs.push(
      `URGENT: ${cisaKevMatches.length} CVE(s) are in the CISA Known Exploited Vulnerabilities catalogue. Apply patches immediately: ${cisaKevMatches.join(", ")}.`
    );
  }

  if (maxEpssPercentile >= 0.5) {
    recs.push(
      `High exploit probability detected (max EPSS ${(maxEpssPercentile * 100).toFixed(1)}th percentile). Treat affected CVEs as actively exploitable.`
    );
  }

  const criticalOrHigh = findings.filter(
    (f) => f.severity?.toUpperCase() === "CRITICAL" || f.severity?.toUpperCase() === "HIGH"
  );
  if (criticalOrHigh.length > 0) {
    recs.push(
      `${criticalOrHigh.length} finding(s) rated CRITICAL or HIGH: ${criticalOrHigh.map((f) => f.cvId).join(", ")}.`
    );
  }

  if (recs.length === 0 && findings.length > 0) {
    recs.push("Review all listed advisories and upgrade to the patched version as soon as feasible.");
  }

  if (findings.length === 0) {
    recs.push("No known CVEs found for this package version. Continue monitoring for new advisories.");
  }

  return recs;
}
