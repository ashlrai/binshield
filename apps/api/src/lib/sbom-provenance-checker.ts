/**
 * SBOM Provenance Verification + Supply-Chain Resilience Checks
 *
 * Validates CycloneDX SBOMs and lockfiles against package registry metadata
 * to detect tampering, source mismatches, and unresolved dependencies.
 *
 * Checks performed per dependency:
 *   1. Fetch authoritative npm/PyPI registry metadata (name, version, dist hash, publish timestamp).
 *   2. Verify SBOM-recorded purl/digest matches registry data — detects substitution attacks.
 *   3. Flag resolution from non-canonical sources (private / unresolved registries).
 *   4. Detect yanked/retracted package versions still referenced in lockfiles.
 *
 * Finding severity map:
 *   registry-mismatch       → HIGH  (integrity hash or source differs from registry)
 *   unresolved-dependency   → MEDIUM (resolved from non-canonical URL)
 *   yanked-version          → HIGH  (package version retracted by maintainer)
 */

import type { ProvenanceCheck, ProvenanceCheckType, RiskLevel } from "@binshield/analysis-types";

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/** Normalised dependency extracted from an SBOM or lockfile. */
interface DependencyEntry {
  packageName: string;
  version: string;
  ecosystem: "npm" | "pypi";
  /** Hash recorded in the SBOM component (e.g. SHA-256 of tarball). */
  sbomHash?: string;
  /** purl recorded in the SBOM component. */
  purl?: string;
  /** resolved field from a lockfile (npm/pnpm/yarn). */
  resolvedUrl?: string;
}

/** Minimal shape of an npm registry dist-tags + versions response. */
interface NpmRegistryMetadata {
  name: string;
  /** versions keyed by semver string */
  versions: Record<string, {
    dist: {
      tarball: string;
      shasum: string;
      integrity?: string;
    };
    deprecated?: string;
  }>;
  time?: Record<string, string>;
}

/** Minimal shape of a PyPI JSON API release entry. */
interface PypiRegistryMetadata {
  info: { name: string; version: string };
  releases: Record<string, Array<{
    digests: { md5: string; sha256: string };
    url: string;
    yanked?: boolean;
    yanked_reason?: string | null;
  }>>;
  urls?: Array<{
    digests: { md5: string; sha256: string };
    url: string;
    yanked?: boolean;
  }>;
}

// ---------------------------------------------------------------------------
// Canonical registry URL constants
// ---------------------------------------------------------------------------

const NPM_REGISTRY_BASE = "https://registry.npmjs.org";
const PYPI_REGISTRY_BASE = "https://pypi.org/pypi";

/**
 * Canonical npm registry hostnames. Packages resolved from other hosts are
 * flagged as "unresolved-dependency".
 */
const CANONICAL_NPM_HOSTS = new Set([
  "registry.npmjs.org",
  "registry.yarnpkg.com",
  // GitHub Packages and local mirrors are NOT canonical for public packages
]);

// ---------------------------------------------------------------------------
// Registry fetch helpers
// ---------------------------------------------------------------------------

/**
 * Fetches npm registry metadata for a package.
 * Throws on non-200 responses so callers can distinguish network errors from
 * missing packages.
 */
export async function fetchNpmMetadata(
  packageName: string,
  fetchFn: typeof fetch = fetch
): Promise<NpmRegistryMetadata | null> {
  const encodedName = packageName.startsWith("@")
    ? `@${encodeURIComponent(packageName.slice(1))}`
    : encodeURIComponent(packageName);
  const url = `${NPM_REGISTRY_BASE}/${encodedName}`;

  let res: Response;
  try {
    res = await fetchFn(url, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    // Network error / timeout — treat as offline registry
    return null;
  }

  if (res.status === 404) return null;
  if (!res.ok) return null;

  return res.json() as Promise<NpmRegistryMetadata>;
}

/**
 * Fetches PyPI JSON API metadata for a package@version.
 * Returns null on 404 / network error.
 */
export async function fetchPypiMetadata(
  packageName: string,
  version: string,
  fetchFn: typeof fetch = fetch
): Promise<PypiRegistryMetadata | null> {
  const url = `${PYPI_REGISTRY_BASE}/${encodeURIComponent(packageName)}/${encodeURIComponent(version)}/json`;

  let res: Response;
  try {
    res = await fetchFn(url, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    return null;
  }

  if (res.status === 404) return null;
  if (!res.ok) return null;

  return res.json() as Promise<PypiRegistryMetadata>;
}

// ---------------------------------------------------------------------------
// SBOM / lockfile parsers
// ---------------------------------------------------------------------------

/**
 * Parses a CycloneDX JSON SBOM (spec 1.4 / 1.5) and extracts dependency entries.
 * Only "library" and "application" component types with a purl are extracted.
 */
export function parseCycloneDxSbom(
  sbomText: string,
  ecosystem: "npm" | "pypi"
): DependencyEntry[] {
  let doc: Record<string, unknown>;
  try {
    doc = JSON.parse(sbomText) as Record<string, unknown>;
  } catch {
    throw new Error("SBOM is not valid JSON");
  }

  if (doc.bomFormat !== "CycloneDX") {
    throw new Error("Unsupported SBOM format — expected CycloneDX");
  }

  const components = (doc.components ?? []) as Array<Record<string, unknown>>;
  const entries: DependencyEntry[] = [];

  for (const component of components) {
    const purl = component.purl as string | undefined;
    if (!purl) continue;

    // purl format: pkg:<type>/<namespace>/<name>@<version>?<qualifiers>#<subpath>
    const purlMatch = purl.match(/^pkg:([^/]+)\/(.+?)@([^?#]+)/);
    if (!purlMatch) continue;

    const [, purlType, rawName, version] = purlMatch as [string, string, string, string];

    // Filter to the requested ecosystem
    const isNpm = purlType === "npm" && ecosystem === "npm";
    const isPypi = (purlType === "pypi" || purlType === "python") && ecosystem === "pypi";
    if (!isNpm && !isPypi) continue;

    // Extract SHA-256 from hashes array if present
    let sbomHash: string | undefined;
    const hashes = (component.hashes ?? []) as Array<{ alg: string; content: string }>;
    const sha256Entry = hashes.find((h) => h.alg === "SHA-256" || h.alg === "sha-256");
    if (sha256Entry) sbomHash = sha256Entry.content;

    entries.push({
      packageName: rawName,
      version,
      ecosystem,
      sbomHash,
      purl,
    });
  }

  return entries;
}

/**
 * Parses an npm lockfile (package-lock.json v2/v3 or pnpm-lock.yaml subset)
 * and extracts dependency entries with resolved URLs.
 *
 * For pnpm-lock.yaml we perform a minimal line-level parse since the format
 * is well-structured; we only need name, version, and resolution url.
 */
export function parseLockfile(
  lockfileContent: string,
  ecosystem: "npm" | "pypi"
): DependencyEntry[] {
  if (ecosystem !== "npm") return [];

  // Try package-lock.json (npm / yarn --json)
  if (lockfileContent.trimStart().startsWith("{")) {
    try {
      const lock = JSON.parse(lockfileContent) as Record<string, unknown>;

      // npm/yarn v2+ lockfile: packages section
      if (lock.packages && typeof lock.packages === "object") {
        const entries: DependencyEntry[] = [];
        const packages = lock.packages as Record<string, Record<string, unknown>>;
        for (const [pkgPath, pkgData] of Object.entries(packages)) {
          if (!pkgData || pkgPath === "") continue;
          // pkgPath is like "node_modules/lodash" or "node_modules/@types/node"
          const namePart = pkgPath.replace(/^node_modules\//, "").replace(/\/node_modules\//g, "/");
          const version = pkgData.version as string | undefined;
          if (!namePart || !version) continue;
          entries.push({
            packageName: namePart,
            version,
            ecosystem,
            resolvedUrl: pkgData.resolved as string | undefined,
            sbomHash: pkgData.integrity as string | undefined,
          });
        }
        return entries;
      }

      // npm v1 lockfile: dependencies section
      if (lock.dependencies && typeof lock.dependencies === "object") {
        const entries: DependencyEntry[] = [];
        function extractDeps(deps: Record<string, Record<string, unknown>>, scope?: string): void {
          for (const [name, data] of Object.entries(deps)) {
            if (!data || typeof data !== "object") continue;
            const qualifiedName = scope ? `${scope}/${name}` : name;
            const version = data.version as string | undefined;
            if (!version) continue;
            entries.push({
              packageName: qualifiedName,
              version,
              ecosystem,
              resolvedUrl: data.resolved as string | undefined,
              sbomHash: data.integrity as string | undefined,
            });
            if (data.dependencies && typeof data.dependencies === "object") {
              extractDeps(data.dependencies as Record<string, Record<string, unknown>>);
            }
          }
        }
        extractDeps(lock.dependencies as Record<string, Record<string, unknown>>);
        return entries;
      }
    } catch {
      // Fall through to pnpm parse
    }
  }

  // Minimal pnpm-lock.yaml parser
  // Lines like: /lodash@4.17.21:\n  resolution: {integrity: sha512-...}\n  ...
  const entries: DependencyEntry[] = [];
  const lines = lockfileContent.split("\n");
  let currentName: string | undefined;
  let currentVersion: string | undefined;
  let currentResolved: string | undefined;
  let currentHash: string | undefined;

  for (const line of lines) {
    // Top-level entry: /packageName@version:
    const entryMatch = line.match(/^\/?(@?[^/@\s]+(?:\/[^/@\s]+)?)@([^/:]+):?\s*$/);
    if (entryMatch) {
      // Flush previous entry
      if (currentName && currentVersion) {
        entries.push({
          packageName: currentName,
          version: currentVersion,
          ecosystem,
          resolvedUrl: currentResolved,
          sbomHash: currentHash,
        });
      }
      currentName = entryMatch[1];
      currentVersion = entryMatch[2];
      currentResolved = undefined;
      currentHash = undefined;
      continue;
    }
    // resolution line
    const resolvedMatch = line.match(/^\s+resolution:\s*\{.*?tarball:\s*(\S+)/);
    if (resolvedMatch && currentName) {
      currentResolved = resolvedMatch[1].replace(/[,}].*$/, "").trim();
      continue;
    }
    // integrity line
    const integrityMatch = line.match(/^\s+resolution:\s*\{integrity:\s*([^,}]+)/);
    if (integrityMatch && currentName) {
      currentHash = integrityMatch[1].trim();
      continue;
    }
  }
  // Flush last
  if (currentName && currentVersion) {
    entries.push({
      packageName: currentName,
      version: currentVersion,
      ecosystem,
      resolvedUrl: currentResolved,
      sbomHash: currentHash,
    });
  }

  return entries;
}

// ---------------------------------------------------------------------------
// Per-dependency check logic
// ---------------------------------------------------------------------------

/**
 * Checks a single npm dependency against registry metadata.
 */
async function checkNpmDependency(
  dep: DependencyEntry,
  fetchFn: typeof fetch
): Promise<ProvenanceCheck> {
  const checkedAt = new Date().toISOString();
  const base: Omit<ProvenanceCheck, "passed" | "detail" | "checkType" | "severity"> = {
    packageName: dep.packageName,
    version: dep.version,
    ecosystem: "npm",
    sbomHash: dep.sbomHash,
    resolvedUrl: dep.resolvedUrl,
    checkedAt,
  };

  // 1. Check for non-canonical resolved URL (unresolved-dependency)
  if (dep.resolvedUrl) {
    try {
      const resolvedHost = new URL(dep.resolvedUrl).hostname;
      if (!CANONICAL_NPM_HOSTS.has(resolvedHost)) {
        return {
          ...base,
          passed: false,
          checkType: "unresolved-dependency",
          severity: "medium",
          detail: `Package resolved from non-canonical registry: ${resolvedHost}. Expected registry.npmjs.org.`,
        };
      }
    } catch {
      // Invalid URL — treat as unresolved
      return {
        ...base,
        passed: false,
        checkType: "unresolved-dependency",
        severity: "medium",
        detail: `Package has an invalid or private resolved URL: ${dep.resolvedUrl}`,
      };
    }
  }

  // 2. Fetch registry metadata
  const meta = await fetchNpmMetadata(dep.packageName, fetchFn);

  if (!meta) {
    // Registry unreachable or package not found — flag as unresolved
    return {
      ...base,
      passed: false,
      checkType: "unresolved-dependency",
      severity: "medium",
      detail: `Could not reach npm registry for ${dep.packageName}@${dep.version}. Package may be private or registry is offline.`,
    };
  }

  const versionData = meta.versions[dep.version];

  // 3. Version not found in registry → yanked or never published
  if (!versionData) {
    return {
      ...base,
      passed: false,
      checkType: "yanked-version",
      severity: "high",
      detail: `${dep.packageName}@${dep.version} is not present in the npm registry. The version may have been unpublished or was never published to the public registry.`,
    };
  }

  // 4. Version deprecated with a deprecation notice that matches yanked keywords
  if (versionData.deprecated) {
    const msg = versionData.deprecated.toLowerCase();
    if (
      msg.includes("yanked") ||
      msg.includes("retracted") ||
      msg.includes("security") ||
      msg.includes("malicious") ||
      msg.includes("compromised")
    ) {
      return {
        ...base,
        passed: false,
        checkType: "yanked-version",
        severity: "high",
        detail: `${dep.packageName}@${dep.version} is deprecated/yanked: "${versionData.deprecated}"`,
      };
    }
  }

  // 5. Verify SBOM/lockfile integrity hash against registry
  const registryHash = versionData.dist.integrity ?? versionData.dist.shasum;
  if (dep.sbomHash && registryHash) {
    // Normalise: strip algorithm prefix for comparison (sha512-<base64> vs raw)
    const normSbom = dep.sbomHash.replace(/^sha\d+-/i, "").toLowerCase();
    const normRegistry = registryHash.replace(/^sha\d+-/i, "").toLowerCase();

    if (normSbom !== normRegistry) {
      return {
        ...base,
        passed: false,
        checkType: "registry-mismatch",
        severity: "high",
        registryHash,
        detail: `Integrity hash mismatch for ${dep.packageName}@${dep.version}. SBOM/lockfile records "${dep.sbomHash}" but registry has "${registryHash}". This may indicate tampering or a substitution attack.`,
      };
    }
  }

  return {
    ...base,
    passed: true,
    registryHash,
    detail: `${dep.packageName}@${dep.version} verified against npm registry.`,
  };
}

/**
 * Checks a single PyPI dependency against registry metadata.
 */
async function checkPypiDependency(
  dep: DependencyEntry,
  fetchFn: typeof fetch
): Promise<ProvenanceCheck> {
  const checkedAt = new Date().toISOString();
  const base: Omit<ProvenanceCheck, "passed" | "detail" | "checkType" | "severity"> = {
    packageName: dep.packageName,
    version: dep.version,
    ecosystem: "pypi",
    sbomHash: dep.sbomHash,
    checkedAt,
  };

  const meta = await fetchPypiMetadata(dep.packageName, dep.version, fetchFn);

  if (!meta) {
    return {
      ...base,
      passed: false,
      checkType: "unresolved-dependency",
      severity: "medium",
      detail: `Could not reach PyPI registry for ${dep.packageName}@${dep.version}. Package may be private or registry is offline.`,
    };
  }

  const releases = meta.releases[dep.version] ?? [];

  // 1. Version not found
  if (releases.length === 0) {
    return {
      ...base,
      passed: false,
      checkType: "yanked-version",
      severity: "high",
      detail: `${dep.packageName}@${dep.version} has no release files on PyPI. The version may have been yanked.`,
    };
  }

  // 2. Yanked by PyPI
  const allYanked = releases.every((r) => r.yanked === true);
  if (allYanked) {
    const reason = releases[0]?.yanked_reason;
    return {
      ...base,
      passed: false,
      checkType: "yanked-version",
      severity: "high",
      detail: `${dep.packageName}@${dep.version} is yanked on PyPI.${reason ? ` Reason: ${reason}` : ""}`,
    };
  }

  // 3. Verify SHA-256 digest against SBOM hash
  const firstRelease = releases.find((r) => !r.yanked) ?? releases[0];
  const registryHash = firstRelease?.digests?.sha256;

  if (dep.sbomHash && registryHash) {
    const normSbom = dep.sbomHash.replace(/^sha256:/i, "").toLowerCase();
    const normRegistry = registryHash.toLowerCase();
    if (normSbom !== normRegistry) {
      return {
        ...base,
        passed: false,
        checkType: "registry-mismatch",
        severity: "high",
        registryHash,
        detail: `SHA-256 mismatch for ${dep.packageName}@${dep.version}. SBOM records "${dep.sbomHash}" but PyPI has "${registryHash}". Possible tampering or substitution attack.`,
      };
    }
  }

  return {
    ...base,
    passed: true,
    registryHash,
    detail: `${dep.packageName}@${dep.version} verified against PyPI registry.`,
  };
}

// ---------------------------------------------------------------------------
// Risk aggregation
// ---------------------------------------------------------------------------

function computeRiskLevel(checks: ProvenanceCheck[]): RiskLevel {
  const failed = checks.filter((c) => !c.passed);
  if (failed.some((c) => c.severity === "high")) return "high";
  if (failed.some((c) => c.severity === "medium")) return "medium";
  if (failed.length > 0) return "low";
  return "none";
}

function buildRecommendations(checks: ProvenanceCheck[]): string[] {
  const recs: string[] = [];
  const byType: Record<ProvenanceCheckType, ProvenanceCheck[]> = {
    "registry-mismatch": [],
    "unresolved-dependency": [],
    "yanked-version": [],
  };

  for (const check of checks) {
    if (!check.passed && check.checkType) {
      byType[check.checkType].push(check);
    }
  }

  if (byType["registry-mismatch"].length > 0) {
    recs.push(
      `Investigate ${byType["registry-mismatch"].length} integrity hash mismatch(es) — these packages may have been tampered with. Re-download from the official registry and re-lock.`
    );
  }
  if (byType["yanked-version"].length > 0) {
    recs.push(
      `${byType["yanked-version"].length} package version(s) have been unpublished or yanked. Update to the latest published version immediately.`
    );
  }
  if (byType["unresolved-dependency"].length > 0) {
    recs.push(
      `${byType["unresolved-dependency"].length} dependency/dependencies resolved from non-canonical or private registries. Audit registry configuration and ensure only trusted sources are used.`
    );
  }
  if (recs.length === 0) {
    recs.push("All dependencies verified against registry — no action required.");
  }

  return recs;
}

// ---------------------------------------------------------------------------
// Main exported function
// ---------------------------------------------------------------------------

export interface ProvenanceVerifyRequest {
  sbomText: string;
  packageFormat: "npm" | "pypi";
  lockfileContent?: string;
}

export interface ProvenanceVerifyResult {
  isValid: boolean;
  checks: ProvenanceCheck[];
  riskLevel: RiskLevel;
  recommendations: string[];
  checkedAt: string;
}

/**
 * Verifies provenance for all dependencies in an SBOM and optional lockfile.
 *
 * @param request  - SBOM text, package format, and optional lockfile content.
 * @param fetchFn  - Injectable fetch implementation (for testing).
 * @returns        - Aggregated provenance verification result.
 */
export async function verifySbomProvenance(
  request: ProvenanceVerifyRequest,
  fetchFn: typeof fetch = fetch
): Promise<ProvenanceVerifyResult> {
  const { sbomText, packageFormat, lockfileContent } = request;
  const checkedAt = new Date().toISOString();

  // Parse dependencies from SBOM
  const sbomDeps = parseCycloneDxSbom(sbomText, packageFormat);

  // Merge with lockfile deps (deduplicate by name@version)
  const lockfileDeps = lockfileContent
    ? parseLockfile(lockfileContent, packageFormat)
    : [];

  // Build a unified deduped map: key = "name@version"
  const depMap = new Map<string, DependencyEntry>();

  for (const dep of sbomDeps) {
    depMap.set(`${dep.packageName}@${dep.version}`, dep);
  }

  for (const dep of lockfileDeps) {
    const key = `${dep.packageName}@${dep.version}`;
    const existing = depMap.get(key);
    if (existing) {
      // Merge: prefer SBOM hash, take lockfile resolved URL
      depMap.set(key, {
        ...existing,
        resolvedUrl: dep.resolvedUrl ?? existing.resolvedUrl,
        sbomHash: existing.sbomHash ?? dep.sbomHash,
      });
    } else {
      depMap.set(key, dep);
    }
  }

  const deps = Array.from(depMap.values());

  if (deps.length === 0) {
    return {
      isValid: true,
      checks: [],
      riskLevel: "none",
      recommendations: ["No dependencies found in SBOM/lockfile to verify."],
      checkedAt,
    };
  }

  // Run checks in parallel (bounded concurrency at 10 to avoid hammering registries)
  const CONCURRENCY = 10;
  const checks: ProvenanceCheck[] = [];

  for (let i = 0; i < deps.length; i += CONCURRENCY) {
    const batch = deps.slice(i, i + CONCURRENCY);
    const batchResults = await Promise.all(
      batch.map((dep) =>
        packageFormat === "npm"
          ? checkNpmDependency(dep, fetchFn)
          : checkPypiDependency(dep, fetchFn)
      )
    );
    checks.push(...batchResults);
  }

  const riskLevel = computeRiskLevel(checks);
  const recommendations = buildRecommendations(checks);
  const isValid = checks.every((c) => c.passed);

  return { isValid, checks, riskLevel, recommendations, checkedAt };
}
