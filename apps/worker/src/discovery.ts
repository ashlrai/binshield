/**
 * Native Package Discovery Engine
 *
 * Finds npm packages containing native binaries (.node, .so, .dylib, .wasm)
 * by checking the npm registry for native indicators and persisting results
 * to the discovered_packages table in Supabase.
 */

import { NATIVE_PACKAGE_SEED_LIST, type SeedPackage } from "./seed-list";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface DiscoveryConfig {
  supabaseUrl: string;
  supabaseServiceRoleKey: string;
}

export interface DiscoveredPackage {
  ecosystem: string;
  name: string;
  latestVersion: string;
  discoverySource: string;
  nativeIndicators: NativeIndicators;
  weeklyDownloads: number;
  priorityScore: number;
  category?: string;
  description?: string;
}

export interface NativeIndicators {
  hasBindingGyp?: boolean;
  hasNativeAddonDep?: boolean;
  hasNapiRs?: boolean;
  hasBinaryDistribution?: boolean;
  hasInstallScript?: boolean;
  nativeDependencies?: string[];
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Dependencies that indicate a package has native code. */
const NATIVE_DEPENDENCY_NAMES = new Set([
  "node-gyp",
  "node-pre-gyp",
  "@mapbox/node-pre-gyp",
  "prebuild-install",
  "prebuild",
  "node-gyp-build",
  "cmake-js",
  "napi-rs",
  "node-addon-api",
]);

/**
 * Platform suffixes used by binary distribution packages.
 * Packages whose names end with these are platform-specific native binaries.
 */
const PLATFORM_SUFFIXES = [
  "-linux-x64-gnu",
  "-linux-x64-musl",
  "-linux-arm64-gnu",
  "-linux-arm64-musl",
  "-linux-arm-gnueabihf",
  "-linux-arm-musleabihf",
  "-linux-ia32",
  "-linux-loong64",
  "-linux-mips64el",
  "-linux-ppc64",
  "-linux-riscv64",
  "-linux-s390x",
  "-linux-powerpc64le-gnu",
  "-linux-loong64-gnu",
  "-linux-riscv64-gnu",
  "-linux-s390x-gnu",
  "-darwin-arm64",
  "-darwin-x64",
  "-win32-arm64",
  "-win32-arm64-msvc",
  "-win32-x64",
  "-win32-x64-msvc",
  "-win32-ia32",
  "-win32-ia32-msvc",
  "-freebsd-arm64",
  "-freebsd-x64",
  "-openbsd-arm64",
  "-openbsd-x64",
  "-netbsd-x64",
  "-sunos-x64",
  "-android-arm",
  "-android-arm64",
  "-android-arm-eabi",
  "-android-x64",
  "-aix-ppc64",
];

/** npm registry allows ~100 requests/minute. We use a conservative limit. */
const NPM_RATE_LIMIT_DELAY_MS = 650; // ~92 req/min

/** GitHub unauthenticated: 60 req/hour. */
const GITHUB_RATE_LIMIT_DELAY_MS = 61_000; // ~59 req/hr

/** Search terms for discovering native packages on npm. */
const DEFAULT_SEARCH_TERMS = [
  "native addon",
  "node-gyp",
  "napi-rs",
  "node-addon-api",
  "prebuild-install",
  "binding.gyp",
  "native binding",
  "ffi napi",
  "wasm binding",
  "c++ addon",
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function log(message: string) {
  console.log(`[Discovery] ${message}`);
}

function logError(message: string, error?: unknown) {
  const detail =
    error instanceof Error
      ? error.message
      : error !== undefined
        ? String(error)
        : "";
  console.error(`[Discovery] ${message}${detail ? `: ${detail}` : ""}`);
}

/** Wait for a given number of milliseconds. */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Calculate a priority score for a discovered package (0-100).
 *
 * Higher scores mean the package should be scanned sooner.
 */
function calculatePriorityScore(
  weeklyDownloads: number,
  indicators: NativeIndicators,
  hasKnownCategory: boolean,
): number {
  const downloadScore = Math.log10(weeklyDownloads + 1) * 15;

  const indicatorCount = [
    indicators.hasBindingGyp,
    indicators.hasNativeAddonDep,
    indicators.hasNapiRs,
    indicators.hasBinaryDistribution,
    indicators.hasInstallScript,
  ].filter(Boolean).length;

  const indicatorScore = indicatorCount * 10;
  const categoryBonus = hasKnownCategory ? 10 : 0;

  return Math.min(100, Math.floor(downloadScore + indicatorScore + categoryBonus));
}

/**
 * Check if a package name looks like a platform-specific binary distribution.
 */
function isPlatformPackage(name: string): boolean {
  if (name.startsWith("@napi-rs/")) return true;

  for (const suffix of PLATFORM_SUFFIXES) {
    if (name.endsWith(suffix)) return true;
  }

  return false;
}

// ---------------------------------------------------------------------------
// npm registry response types
// ---------------------------------------------------------------------------

interface NpmPackageMetadata {
  name: string;
  "dist-tags"?: Record<string, string>;
  versions?: Record<string, NpmVersionMetadata>;
  time?: Record<string, string>;
  repository?: { type?: string; url?: string } | string;
  maintainers?: Array<{ name: string; email?: string }>;
  description?: string;
}

interface NpmVersionMetadata {
  name: string;
  version: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  scripts?: Record<string, string>;
  gypfile?: boolean;
  files?: string[];
  binary?: Record<string, unknown>;
  description?: string;
}

interface NpmSearchResult {
  objects: Array<{
    package: {
      name: string;
      version: string;
      description?: string;
    };
  }>;
}

interface NpmDownloadResult {
  downloads: number;
  package: string;
}

// ---------------------------------------------------------------------------
// PackageDiscoveryEngine
// ---------------------------------------------------------------------------

export class PackageDiscoveryEngine {
  private readonly baseUrl: string;
  private readonly serviceRoleKey: string;

  constructor(private config: DiscoveryConfig) {
    this.baseUrl = config.supabaseUrl.replace(/\/$/, "");
    this.serviceRoleKey = config.supabaseServiceRoleKey;
  }

  // -------------------------------------------------------------------------
  // Supabase helpers (same pattern as supabase-store.ts)
  // -------------------------------------------------------------------------

  private headers(extra: Record<string, string> = {}): Record<string, string> {
    return {
      apikey: this.serviceRoleKey,
      authorization: `Bearer ${this.serviceRoleKey}`,
      "content-type": "application/json",
      ...extra,
    };
  }

  private async supabaseRequest<T>(
    path: string,
    init: RequestInit = {},
  ): Promise<T> {
    const response = await fetch(`${this.baseUrl}/rest/v1${path}`, {
      ...init,
      headers: {
        ...this.headers(),
        ...(init.headers as Record<string, string> | undefined),
      },
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(
        `Supabase request failed (${response.status}): ${text}`,
      );
    }

    if (response.status === 204) {
      return undefined as T;
    }

    return (await response.json()) as T;
  }

  // -------------------------------------------------------------------------
  // Discovery: seed list
  // -------------------------------------------------------------------------

  /**
   * Run discovery from the curated seed list. For each seed package, fetch
   * basic metadata from npm and compute native indicators + priority score.
   */
  async discoverFromSeedList(): Promise<DiscoveredPackage[]> {
    log(`Starting seed list discovery (${NATIVE_PACKAGE_SEED_LIST.length} packages)`);

    const discovered: DiscoveredPackage[] = [];
    let checked = 0;
    let errors = 0;

    for (const seed of NATIVE_PACKAGE_SEED_LIST) {
      try {
        const pkg = await this.checkPackageWithSeed(seed);
        if (pkg) {
          discovered.push(pkg);
        }
        checked++;

        if (checked % 25 === 0) {
          log(`Progress: ${checked}/${NATIVE_PACKAGE_SEED_LIST.length} checked, ${discovered.length} discovered`);
        }
      } catch (error) {
        errors++;
        logError(`Failed to check seed package ${seed.name}`, error);
      }

      // Rate limit: npm allows ~100 req/min
      await sleep(NPM_RATE_LIMIT_DELAY_MS);
    }

    log(
      `Seed list discovery complete: ${discovered.length} discovered, ${errors} errors`,
    );

    return discovered;
  }

  /**
   * Check a seed package: fetch metadata from npm, analyze for native
   * indicators, and enrich with the seed's category/description.
   */
  private async checkPackageWithSeed(
    seed: SeedPackage,
  ): Promise<DiscoveredPackage | null> {
    const result = await this.checkPackage(seed.name);
    if (!result) return null;

    result.category = seed.category;
    result.description = result.description || seed.description;
    result.discoverySource = "seed-list";

    // Recalculate priority with category bonus
    result.priorityScore = calculatePriorityScore(
      result.weeklyDownloads,
      result.nativeIndicators,
      true, // seed packages always have a category
    );

    return result;
  }

  // -------------------------------------------------------------------------
  // Discovery: npm registry search
  // -------------------------------------------------------------------------

  /**
   * Query npm registry search API for packages matching terms associated
   * with native addons. Returns deduplicated discovered packages.
   */
  async discoverFromRegistry(
    searchTerms: string[] = DEFAULT_SEARCH_TERMS,
  ): Promise<DiscoveredPackage[]> {
    log(`Starting registry discovery with ${searchTerms.length} search terms`);

    const seen = new Set<string>();
    const discovered: DiscoveredPackage[] = [];

    for (const term of searchTerms) {
      try {
        const results = await this.searchNpm(term);

        for (const result of results) {
          if (seen.has(result.package.name)) continue;
          seen.add(result.package.name);

          try {
            const pkg = await this.checkPackage(result.package.name);
            if (pkg) {
              pkg.discoverySource = `registry-search:${term}`;
              discovered.push(pkg);
            }
          } catch (error) {
            logError(`Failed to check ${result.package.name}`, error);
          }

          await sleep(NPM_RATE_LIMIT_DELAY_MS);
        }
      } catch (error) {
        logError(`Search failed for term "${term}"`, error);
      }

      // Small delay between search queries
      await sleep(NPM_RATE_LIMIT_DELAY_MS);
    }

    log(`Registry discovery complete: ${discovered.length} packages found`);
    return discovered;
  }

  /**
   * Search npm for packages matching a query string.
   * Returns up to 250 results per query (npm limit).
   */
  private async searchNpm(
    query: string,
    size = 50,
  ): Promise<NpmSearchResult["objects"]> {
    const url = `https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(query)}&size=${size}`;
    const response = await fetch(url, {
      headers: { Accept: "application/json" },
    });

    if (!response.ok) {
      throw new Error(`npm search failed (${response.status}): ${await response.text()}`);
    }

    const data = (await response.json()) as NpmSearchResult;
    return data.objects;
  }

  // -------------------------------------------------------------------------
  // Package inspection
  // -------------------------------------------------------------------------

  /**
   * Check a specific package for native indicators by fetching its
   * metadata from the npm registry.
   *
   * Returns null if the package does not exist or has no native signals.
   */
  async checkPackage(packageName: string): Promise<DiscoveredPackage | null> {
    const metadata = await this.fetchNpmMetadata(packageName);
    if (!metadata) return null;

    const latestTag = metadata["dist-tags"]?.latest;
    if (!latestTag) return null;

    const latestVersion = metadata.versions?.[latestTag];
    if (!latestVersion) return null;

    const indicators = this.detectNativeIndicators(
      packageName,
      latestVersion,
    );

    // Only return if at least one native signal is present
    const hasSignal =
      indicators.hasBindingGyp ||
      indicators.hasNativeAddonDep ||
      indicators.hasNapiRs ||
      indicators.hasBinaryDistribution ||
      indicators.hasInstallScript;

    if (!hasSignal) return null;

    // Fetch download count (lightweight call)
    const weeklyDownloads = await this.fetchWeeklyDownloads(packageName);

    const priorityScore = calculatePriorityScore(
      weeklyDownloads,
      indicators,
      false,
    );

    return {
      ecosystem: "npm",
      name: packageName,
      latestVersion: latestTag,
      discoverySource: "registry-check",
      nativeIndicators: indicators,
      weeklyDownloads,
      priorityScore,
      description: latestVersion.description ?? metadata.description,
    };
  }

  /**
   * Fetch full metadata for a package from the npm registry.
   * Returns null on 404 (package does not exist).
   */
  private async fetchNpmMetadata(
    packageName: string,
  ): Promise<NpmPackageMetadata | null> {
    const url = `https://registry.npmjs.org/${encodeURIComponent(packageName).replace("%40", "@")}`;
    const response = await fetch(url, {
      headers: { Accept: "application/json" },
    });

    if (response.status === 404) return null;

    if (!response.ok) {
      throw new Error(
        `npm metadata fetch failed for ${packageName} (${response.status})`,
      );
    }

    return (await response.json()) as NpmPackageMetadata;
  }

  /**
   * Detect native indicators from package metadata.
   *
   * Checks:
   * 1. binding.gyp in files or gypfile: true
   * 2. Known native dependencies
   * 3. @napi-rs scope or platform suffix naming
   * 4. install/postinstall scripts with compilation references
   * 5. binary field (used by node-pre-gyp)
   */
  private detectNativeIndicators(
    packageName: string,
    version: NpmVersionMetadata,
  ): NativeIndicators {
    const indicators: NativeIndicators = {};
    const nativeDeps: string[] = [];

    // 1. Check for binding.gyp
    const files = version.files ?? [];
    if (
      files.some((f) => f === "binding.gyp" || f.endsWith("/binding.gyp")) ||
      version.gypfile === true
    ) {
      indicators.hasBindingGyp = true;
    }

    // 2. Check dependencies for known native addon tools
    const allDeps: Record<string, string> = {
      ...(version.dependencies ?? {}),
      ...(version.devDependencies ?? {}),
      ...(version.optionalDependencies ?? {}),
    };

    for (const dep of Object.keys(allDeps)) {
      if (NATIVE_DEPENDENCY_NAMES.has(dep)) {
        nativeDeps.push(dep);
      }
    }

    if (nativeDeps.length > 0) {
      indicators.hasNativeAddonDep = true;
      indicators.nativeDependencies = nativeDeps;
    }

    // 3. Check if the package name indicates NAPI-RS or platform binary
    if (packageName.startsWith("@napi-rs/")) {
      indicators.hasNapiRs = true;
    }
    if (isPlatformPackage(packageName)) {
      indicators.hasBinaryDistribution = true;
    }

    // 4. Check install scripts for compilation references
    const installScript = version.scripts?.install ?? "";
    const postinstallScript = version.scripts?.postinstall ?? "";
    const preinstallScript = version.scripts?.preinstall ?? "";
    const combinedScripts = `${installScript} ${postinstallScript} ${preinstallScript}`;

    const compilationKeywords = [
      "node-gyp",
      "node-pre-gyp",
      "prebuild-install",
      "cmake-js",
      "napi",
      "node-gyp-build",
      "install.js",
      "binding.gyp",
    ];

    if (
      combinedScripts.length > 0 &&
      compilationKeywords.some((kw) =>
        combinedScripts.toLowerCase().includes(kw),
      )
    ) {
      indicators.hasInstallScript = true;
    }

    // 5. Check for binary field (node-pre-gyp)
    if (version.binary) {
      indicators.hasBinaryDistribution = true;
    }

    return indicators;
  }

  // -------------------------------------------------------------------------
  // Enrichment
  // -------------------------------------------------------------------------

  /**
   * Fetch weekly download count from the npm downloads API.
   * Returns 0 on failure to avoid blocking discovery.
   */
  private async fetchWeeklyDownloads(packageName: string): Promise<number> {
    try {
      const url = `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(packageName)}`;
      const response = await fetch(url, {
        headers: { Accept: "application/json" },
      });

      if (!response.ok) return 0;

      const data = (await response.json()) as NpmDownloadResult;
      return data.downloads ?? 0;
    } catch {
      return 0;
    }
  }

  /**
   * Enrich already-discovered packages with additional metadata:
   * download counts, GitHub stars, repo URL, maintainer count, etc.
   *
   * Writes enrichment data to the packages table (for scanned packages)
   * and updates discovered_packages with the latest download counts.
   */
  async enrichPackages(
    packages: Array<{ ecosystem: string; name: string }>,
  ): Promise<void> {
    log(`Enriching ${packages.length} packages`);

    let enriched = 0;
    let githubCalls = 0;

    for (const pkg of packages) {
      try {
        // Fetch npm metadata (includes repository, maintainers)
        const metadata = await this.fetchNpmMetadata(pkg.name);
        if (!metadata) continue;

        await sleep(NPM_RATE_LIMIT_DELAY_MS);

        const latestTag = metadata["dist-tags"]?.latest;
        const latestVersion = latestTag
          ? metadata.versions?.[latestTag]
          : undefined;

        // Download count
        const weeklyDownloads = await this.fetchWeeklyDownloads(pkg.name);
        await sleep(NPM_RATE_LIMIT_DELAY_MS);

        // Extract repository info
        const repoUrl = extractGithubUrl(metadata);
        const maintainerCount = metadata.maintainers?.length ?? 0;
        const lastPublished = latestTag
          ? metadata.time?.[latestTag]
          : undefined;

        // GitHub stars (rate-limited heavily)
        let githubStars: number | undefined;
        if (repoUrl && githubCalls < 55) {
          // Stay under 60/hr
          githubStars = await this.fetchGithubStars(repoUrl);
          githubCalls++;
          if (githubCalls < 55) {
            await sleep(GITHUB_RATE_LIMIT_DELAY_MS);
          }
        }

        // Update discovered_packages table
        await this.supabaseRequest<unknown>(
          `/discovered_packages?ecosystem=eq.${pkg.ecosystem}&name=eq.${encodeURIComponent(pkg.name)}`,
          {
            method: "PATCH",
            headers: { Prefer: "return=minimal" },
            body: JSON.stringify({
              weekly_downloads: weeklyDownloads,
              updated_at: new Date().toISOString(),
            }),
          },
        );

        // Update packages table (if the package has been scanned)
        const enrichmentData: Record<string, unknown> = {
          weekly_downloads: weeklyDownloads,
          maintainer_count: maintainerCount,
          description: latestVersion?.description ?? metadata.description,
        };
        if (repoUrl) enrichmentData.github_repo_url = repoUrl;
        if (githubStars !== undefined)
          enrichmentData.github_stars = githubStars;
        if (lastPublished) enrichmentData.last_published_at = lastPublished;

        await this.supabaseRequest<unknown>(
          `/packages?ecosystem=eq.${pkg.ecosystem}&name=eq.${encodeURIComponent(pkg.name)}`,
          {
            method: "PATCH",
            headers: { Prefer: "return=minimal" },
            body: JSON.stringify(enrichmentData),
          },
        );

        enriched++;
        if (enriched % 10 === 0) {
          log(`Enrichment progress: ${enriched}/${packages.length}`);
        }
      } catch (error) {
        logError(`Failed to enrich ${pkg.name}`, error);
      }
    }

    log(`Enrichment complete: ${enriched}/${packages.length} updated`);
  }

  /**
   * Fetch GitHub star count from the GitHub API.
   * Returns undefined on failure.
   */
  private async fetchGithubStars(repoUrl: string): Promise<number | undefined> {
    try {
      const match = repoUrl.match(
        /github\.com[/:]([^/]+)\/([^/.#]+)/,
      );
      if (!match) return undefined;

      const [, owner, repo] = match;
      const url = `https://api.github.com/repos/${owner}/${repo}`;
      const response = await fetch(url, {
        headers: {
          Accept: "application/vnd.github.v3+json",
          "User-Agent": "BinShield-Crawler/1.0",
        },
      });

      if (!response.ok) return undefined;

      const data = (await response.json()) as { stargazers_count?: number };
      return data.stargazers_count;
    } catch {
      return undefined;
    }
  }

  // -------------------------------------------------------------------------
  // Persistence
  // -------------------------------------------------------------------------

  /**
   * Persist discovered packages to the discovered_packages table.
   * Uses upsert (ON CONFLICT on ecosystem+name) so re-runs update
   * rather than duplicate.
   *
   * Returns the number of packages persisted.
   */
  async persistDiscovered(packages: DiscoveredPackage[]): Promise<number> {
    if (packages.length === 0) return 0;

    log(`Persisting ${packages.length} discovered packages`);

    let persisted = 0;

    // Insert in batches of 50 to avoid oversized payloads
    const batchSize = 50;
    for (let i = 0; i < packages.length; i += batchSize) {
      const batch = packages.slice(i, i + batchSize);
      const rows = batch.map((pkg) => ({
        ecosystem: pkg.ecosystem,
        name: pkg.name,
        latest_version: pkg.latestVersion,
        discovery_source: pkg.discoverySource,
        native_indicators: pkg.nativeIndicators,
        weekly_downloads: pkg.weeklyDownloads,
        priority_score: pkg.priorityScore,
        scan_status: "pending" as const,
      }));

      try {
        // PostgREST upsert: POST with Prefer: resolution=merge-duplicates
        // Requires a unique constraint on (ecosystem, name)
        await this.supabaseRequest<unknown>(`/discovered_packages`, {
          method: "POST",
          headers: {
            Prefer: "resolution=merge-duplicates,return=minimal",
          },
          body: JSON.stringify(rows),
        });

        persisted += batch.length;
      } catch (error) {
        logError(
          `Failed to persist batch ${i}-${i + batch.length}`,
          error,
        );
      }
    }

    log(`Persisted ${persisted}/${packages.length} discovered packages`);
    return persisted;
  }
}

// ---------------------------------------------------------------------------
// Standalone helpers
// ---------------------------------------------------------------------------

/**
 * Extract a GitHub URL from npm package metadata.
 * Handles both string and object forms of the repository field.
 */
function extractGithubUrl(metadata: NpmPackageMetadata): string | undefined {
  if (!metadata.repository) return undefined;

  let url: string;
  if (typeof metadata.repository === "string") {
    url = metadata.repository;
  } else {
    url = metadata.repository.url ?? "";
  }

  // Normalize git+https, git+ssh, git:// prefixes
  url = url
    .replace(/^git\+/, "")
    .replace(/^git:\/\//, "https://")
    .replace(/^ssh:\/\/git@/, "https://")
    .replace(/\.git$/, "");

  if (url.includes("github.com")) {
    // Normalize to https://github.com/owner/repo
    const match = url.match(/github\.com[/:]([^/]+)\/([^/.#]+)/);
    if (match) {
      return `https://github.com/${match[1]}/${match[2]}`;
    }
  }

  return undefined;
}
