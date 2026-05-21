/**
 * Lockfile Scanner — Parse lockfiles and identify native dependencies.
 *
 * Supports:
 *  - package-lock.json (npm v2/v3)
 *  - yarn.lock (classic v1)
 *  - pnpm-lock.yaml
 *
 * Uses native parsing — no external lockfile SDKs required.
 */

import type { SupabaseWorkerConfig } from "./supabase-store";
import { isNativePackage } from "./native-indicators";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type LockfileFormat = "npm" | "yarn-v1" | "pnpm";

export interface ParsedDependency {
  name: string;
  version: string;
  /** True if this package or any of its indicators suggest native binaries. */
  isNative: boolean;
}

export interface LockfileScanRequest {
  orgId: string;
  repoId?: string;
  filename: string;
  content: string;
}

export interface LockfileScanResult {
  id: string;
  filename: string;
  format: LockfileFormat;
  totalDependencies: number;
  nativeDependencies: number;
  aggregateRiskScore: number;
  aggregateRiskLevel: string;
  packages: LockfilePackageResult[];
}

export interface LockfilePackageResult {
  name: string;
  version: string;
  isNative: boolean;
  riskScore?: number;
  riskLevel?: string;
  status: "scanned" | "queued" | "unknown";
}

// ---------------------------------------------------------------------------
// Lockfile Parsers
// ---------------------------------------------------------------------------

function detectFormat(filename: string): LockfileFormat {
  if (filename === "pnpm-lock.yaml" || filename.endsWith("pnpm-lock.yaml")) {
    return "pnpm";
  }
  if (filename === "yarn.lock" || filename.endsWith("yarn.lock")) {
    return "yarn-v1";
  }
  return "npm";
}

/**
 * Parse package-lock.json (npm v2 and v3 format).
 * v2 uses `packages` with path-keyed entries, v3 is similar.
 * Both have a `dependencies` field for backward compat.
 */
function parseNpmLockfile(content: string): ParsedDependency[] {
  const lockfile = JSON.parse(content) as {
    lockfileVersion?: number;
    packages?: Record<string, { version?: string; dependencies?: Record<string, string>; devDependencies?: Record<string, string> }>;
    dependencies?: Record<string, { version?: string; requires?: Record<string, string> }>;
  };

  const deps: ParsedDependency[] = [];
  const seen = new Set<string>();

  // Prefer v2/v3 `packages` field
  if (lockfile.packages) {
    for (const [pkgPath, entry] of Object.entries(lockfile.packages)) {
      if (pkgPath === "") continue; // root package
      // Extract name from path: "node_modules/@scope/pkg" -> "@scope/pkg"
      const nameMatch = pkgPath.match(/node_modules\/(.+)$/);
      if (!nameMatch) continue;
      const name = nameMatch[1];
      if (seen.has(name)) continue;
      seen.add(name);
      deps.push({
        name,
        version: entry.version ?? "0.0.0",
        isNative: isNativePackage(name, entry.dependencies),
      });
    }
  }
  // Fallback to v1 `dependencies`
  else if (lockfile.dependencies) {
    for (const [name, entry] of Object.entries(lockfile.dependencies)) {
      if (seen.has(name)) continue;
      seen.add(name);
      deps.push({
        name,
        version: entry.version ?? "0.0.0",
        isNative: isNativePackage(name, entry.requires),
      });
    }
  }

  return deps;
}

/**
 * Parse yarn.lock (classic v1 format).
 * Format: `"pkg@version":\n  version "x.y.z"\n  ...`
 */
function parseYarnLockfile(content: string): ParsedDependency[] {
  const deps: ParsedDependency[] = [];
  const seen = new Set<string>();

  // Match blocks: "pkg@version": followed by indented lines
  const blockRegex = /^"?([^@\s"]+(?:@[^@\s"]+)?)@[^"]*"?:\s*$/gm;
  const versionRegex = /^\s+version\s+"([^"]+)"/;
  const lines = content.split("\n");

  let currentName: string | null = null;
  let currentVersion = "0.0.0";

  for (const line of lines) {
    // Check for block header
    const headerMatch = line.match(/^"?(@?[^@\s"]+(?:\/[^@\s"]+)?)@/);
    if (headerMatch && !line.startsWith(" ")) {
      // Save previous entry
      if (currentName && !seen.has(currentName)) {
        seen.add(currentName);
        deps.push({
          name: currentName,
          version: currentVersion,
          isNative: isNativePackage(currentName),
        });
      }
      currentName = headerMatch[1];
      currentVersion = "0.0.0";
      continue;
    }

    // Check for version line within a block
    const versionMatch = line.match(versionRegex);
    if (versionMatch) {
      currentVersion = versionMatch[1];
    }
  }

  // Don't forget the last entry
  if (currentName && !seen.has(currentName)) {
    seen.add(currentName);
    deps.push({
      name: currentName,
      version: currentVersion,
      isNative: isNativePackage(currentName),
    });
  }

  return deps;
}

/**
 * Parse pnpm-lock.yaml.
 * Uses simple regex parsing rather than a full YAML parser.
 */
function parsePnpmLockfile(content: string): ParsedDependency[] {
  const deps: ParsedDependency[] = [];
  const seen = new Set<string>();

  // pnpm-lock.yaml has packages section with entries like:
  // /@scope/pkg@version:
  //   or
  // /pkg@version:
  const pkgRegex = /^\s*\/?(@?[a-zA-Z0-9][\w./-]*)@(\d[^:(\s]*)/gm;

  let match: RegExpExecArray | null;
  while ((match = pkgRegex.exec(content)) !== null) {
    const name = match[1];
    const version = match[2];
    if (!seen.has(name)) {
      seen.add(name);
      deps.push({
        name,
        version,
        isNative: isNativePackage(name),
      });
    }
  }

  return deps;
}

export function parseLockfile(filename: string, content: string): {
  format: LockfileFormat;
  dependencies: ParsedDependency[];
} {
  const format = detectFormat(filename);
  let dependencies: ParsedDependency[];

  switch (format) {
    case "npm":
      dependencies = parseNpmLockfile(content);
      break;
    case "yarn-v1":
      dependencies = parseYarnLockfile(content);
      break;
    case "pnpm":
      dependencies = parsePnpmLockfile(content);
      break;
  }

  return { format, dependencies };
}

// ---------------------------------------------------------------------------
// Lockfile Scan Orchestrator
// ---------------------------------------------------------------------------

export class LockfileScanner {
  private readonly baseUrl: string;
  private readonly serviceRoleKey: string;

  constructor(private config: SupabaseWorkerConfig) {
    this.baseUrl = config.supabaseUrl.replace(/\/$/, "");
    this.serviceRoleKey = config.supabaseServiceRoleKey;
  }

  private headers(): Record<string, string> {
    return {
      apikey: this.serviceRoleKey,
      authorization: `Bearer ${this.serviceRoleKey}`,
      "content-type": "application/json",
    };
  }

  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const response = await fetch(`${this.baseUrl}/rest/v1${path}`, {
      ...init,
      headers: { ...this.headers(), ...(init.headers as Record<string, string> | undefined) },
    });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Supabase request failed (${response.status}): ${text}`);
    }
    if (response.status === 204) return undefined as T;
    return (await response.json()) as T;
  }

  /**
   * Scan a lockfile: parse it, identify native dependencies,
   * cross-reference with existing analyses, and queue missing scans.
   */
  async scan(req: LockfileScanRequest): Promise<LockfileScanResult> {
    const { format, dependencies } = parseLockfile(req.filename, req.content);
    const nativeDeps = dependencies.filter((d) => d.isNative);

    // Create the lockfile_scans record
    const [scanRow] = await this.request<Array<{ id: string }>>(
      "/lockfile_scans?select=id",
      {
        method: "POST",
        headers: { Prefer: "return=representation" },
        body: JSON.stringify({
          org_id: req.orgId,
          repo_id: req.repoId ?? null,
          filename: req.filename,
          format,
          total_dependencies: dependencies.length,
          native_dependencies: nativeDeps.length,
          status: "processing",
        }),
      },
    );

    // Index every dependency (native or not, including transitive) so the
    // proactive alert loop can match a flagged package back to this org.
    if (dependencies.length > 0) {
      const depRows = dependencies.map((dep) => ({
        lockfile_scan_id: scanRow.id,
        org_id: req.orgId,
        repo_id: req.repoId ?? null,
        ecosystem: "npm",
        package_name: dep.name,
        version: dep.version,
        is_native: dep.isNative,
        source: "lockfile-scan",
      }));
      for (let i = 0; i < depRows.length; i += 500) {
        await this.request<unknown>("/lockfile_dependencies", {
          method: "POST",
          headers: { Prefer: "return=minimal" },
          body: JSON.stringify(depRows.slice(i, i + 500)),
        }).catch(() => {
          /* dependency indexing is non-fatal — the scan result still returns */
        });
      }
    }

    // Cross-reference native deps with existing analyses
    const packageResults: LockfilePackageResult[] = [];
    let totalRisk = 0;
    let maxRisk = 0;
    let scannedCount = 0;

    for (const dep of nativeDeps) {
      let riskScore: number | undefined;
      let riskLevel: string | undefined;
      let status: "scanned" | "queued" | "unknown" = "unknown";

      // Two-step lookup: find package, then its latest analysis
      const pkgs = await this.request<Array<{ id: string }>>(
        `/packages?select=id&ecosystem=eq.npm&name=eq.${encodeURIComponent(dep.name)}`,
        { method: "GET" },
      ).catch(() => [] as Array<{ id: string }>);

      if (pkgs.length > 0) {
        const analysisRows = await this.request<Array<{ risk_score: number; risk_level: string }>>(
          `/analyses?select=risk_score,risk_level&package_id=eq.${pkgs[0].id}&order=created_at.desc&limit=1`,
          { method: "GET" },
        ).catch(() => [] as Array<{ risk_score: number; risk_level: string }>);

        if (analysisRows.length > 0) {
          riskScore = analysisRows[0].risk_score;
          riskLevel = analysisRows[0].risk_level;
          status = "scanned";
          totalRisk += riskScore;
          if (riskScore > maxRisk) maxRisk = riskScore;
          scannedCount++;
        }
      }

      if (status === "unknown") {
        // Queue for scanning
        await this.request<unknown>("/analysis_jobs", {
          method: "POST",
          headers: { Prefer: "return=minimal" },
          body: JSON.stringify({
            org_id: req.orgId,
            ecosystem: "npm",
            package_name: dep.name,
            version: dep.version,
            status: "queued",
          }),
        }).catch(() => { /* non-fatal */ });
        status = "queued";
      }

      packageResults.push({
        name: dep.name,
        version: dep.version,
        isNative: true,
        riskScore,
        riskLevel,
        status,
      });
    }

    // Compute aggregate risk
    const avgRisk = scannedCount > 0 ? totalRisk / scannedCount : 0;
    const aggregateRiskScore = scannedCount > 0
      ? Math.round(maxRisk * 0.65 + avgRisk * 0.35)
      : 0;
    const aggregateRiskLevel =
      aggregateRiskScore >= 80 ? "critical" :
      aggregateRiskScore >= 60 ? "high" :
      aggregateRiskScore >= 30 ? "medium" :
      aggregateRiskScore > 0 ? "low" : "none";

    // Update the scan record with results
    await this.request<unknown>(
      `/lockfile_scans?id=eq.${scanRow.id}`,
      {
        method: "PATCH",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify({
          aggregate_risk_score: aggregateRiskScore,
          aggregate_risk_level: aggregateRiskLevel,
          status: "complete",
          results: packageResults,
          completed_at: new Date().toISOString(),
        }),
      },
    );

    return {
      id: scanRow.id,
      filename: req.filename,
      format,
      totalDependencies: dependencies.length,
      nativeDependencies: nativeDeps.length,
      aggregateRiskScore,
      aggregateRiskLevel,
      packages: packageResults,
    };
  }
}
