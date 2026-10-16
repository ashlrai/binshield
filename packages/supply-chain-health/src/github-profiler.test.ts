/**
 * Tests for GitHubRepositoryProfiler
 *
 * Covers:
 *  - Constructor / options
 *  - Signal computation (commit velocity, release cadence, contributor turnover,
 *    dependency age, license analysis)
 *  - Edge cases: private repos, no releases, orphaned packages, deprecated licenses
 *  - Cache behaviour (TTL, invalidation, clear)
 *  - Error handling (404, 403, 409, network errors, bad slugs)
 *  - Integration: profile() → SupplyChainHealthAnalyzer pipeline
 *  - Weekly contributor data (precise turnover)
 *  - buildSyntheticNpmMetadata round-trip
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

import {
  GitHubRepositoryProfiler,
  GitHubProfilerError,
  type GitHubFetchResponse,
  type GitHubMaintenanceSignals,
} from "./github-profiler";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function daysAgo(n: number): string {
  return new Date(Date.now() - n * 24 * 60 * 60 * 1000).toISOString();
}

function yearsAgo(n: number): string {
  return daysAgo(n * 365);
}

/** Build a mock GitHubFetchResponse */
function mockResponse(
  status: number,
  body: unknown
): GitHubFetchResponse {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  };
}

/** Standard healthy repo API response */
function healthyRepo() {
  return {
    full_name: "test-owner/test-repo",
    private: false,
    license: { spdx_id: "MIT", key: "mit" },
    pushed_at: daysAgo(5),
    created_at: yearsAgo(2),
    default_branch: "main",
  };
}

function buildCommits(count: number, daysBackStart = 5): unknown[] {
  return Array.from({ length: count }, (_, i) => ({
    sha: `sha${i}`,
    commit: { author: { date: daysAgo(daysBackStart + i) } },
  }));
}

function buildReleases(
  count: number,
  spacingDays = 30,
  opts: { prerelease?: boolean; draft?: boolean } = {}
): unknown[] {
  return Array.from({ length: count }, (_, i) => ({
    tag_name: `v${count - i}.0.0`,
    published_at: daysAgo(spacingDays * (i + 1)),
    prerelease: opts.prerelease ?? false,
    draft: opts.draft ?? false,
  }));
}

function buildContributors(count: number): unknown[] {
  return Array.from({ length: count }, (_, i) => ({
    login: `contributor${i}`,
    contributions: 10 + i,
  }));
}

/** Creates a profiler with a mocked fetch that returns configurable responses */
function makeMockedProfiler(
  repoResp: unknown = healthyRepo(),
  commitsResp: unknown = buildCommits(15),
  releasesResp: unknown = buildReleases(5),
  contributorsResp: unknown = buildContributors(4),
  overrides: {
    repoStatus?: number;
    commitsStatus?: number;
    releasesStatus?: number;
    contributorsStatus?: number;
  } = {}
) {
  const fetchFn = vi.fn(async (url: string) => {
    if (url.includes("/commits")) {
      return mockResponse(overrides.commitsStatus ?? 200, commitsResp);
    }
    if (url.includes("/releases")) {
      return mockResponse(overrides.releasesStatus ?? 200, releasesResp);
    }
    if (url.includes("/contributors")) {
      return mockResponse(overrides.contributorsStatus ?? 200, contributorsResp);
    }
    // Default: repo endpoint
    return mockResponse(overrides.repoStatus ?? 200, repoResp);
  });

  const profiler = new GitHubRepositoryProfiler({
    token: "test-token",
    fetch: fetchFn,
    cacheTtlMs: 0, // disable cache for most tests
  });

  return { profiler, fetchFn };
}

// ---------------------------------------------------------------------------
// Constructor / options
// ---------------------------------------------------------------------------

describe("GitHubRepositoryProfiler — constructor", () => {
  it("constructs with default options", () => {
    const profiler = new GitHubRepositoryProfiler();
    expect(profiler).toBeInstanceOf(GitHubRepositoryProfiler);
  });

  it("constructs with a token", () => {
    const profiler = new GitHubRepositoryProfiler({ token: "ghp_test" });
    expect(profiler).toBeInstanceOf(GitHubRepositoryProfiler);
  });

  it("constructs with custom cacheTtlMs", () => {
    const profiler = new GitHubRepositoryProfiler({ cacheTtlMs: 3600_000 });
    expect(profiler.cacheSize()).toBe(0);
  });

  it("constructs with custom baseUrl", () => {
    const profiler = new GitHubRepositoryProfiler({
      baseUrl: "https://github.example.com/api/v3",
      fetch: vi.fn(),
    });
    expect(profiler).toBeInstanceOf(GitHubRepositoryProfiler);
  });

  it("constructs with injected fetch function", () => {
    const fetchFn = vi.fn();
    const profiler = new GitHubRepositoryProfiler({ fetch: fetchFn });
    expect(profiler).toBeInstanceOf(GitHubRepositoryProfiler);
  });
});

// ---------------------------------------------------------------------------
// Slug validation
// ---------------------------------------------------------------------------

describe("GitHubRepositoryProfiler — slug validation", () => {
  const { profiler } = makeMockedProfiler();

  it("throws for empty slug", async () => {
    await expect(profiler.profile("")).rejects.toThrow(GitHubProfilerError);
  });

  it("throws for slug without slash", async () => {
    await expect(profiler.profile("nodash")).rejects.toThrow(GitHubProfilerError);
  });

  it("throws for slug with too many slashes", async () => {
    await expect(profiler.profile("a/b/c")).rejects.toThrow(GitHubProfilerError);
  });

  it("throws for slug with empty owner", async () => {
    await expect(profiler.profile("/repo")).rejects.toThrow(GitHubProfilerError);
  });

  it("throws for slug with empty repo name", async () => {
    await expect(profiler.profile("owner/")).rejects.toThrow(GitHubProfilerError);
  });

  it("throws for slug with special characters in owner", async () => {
    await expect(profiler.profile("owner!invalid/repo")).rejects.toThrow(
      GitHubProfilerError
    );
  });

  it("accepts valid slug with hyphens and dots", async () => {
    const { profiler: p } = makeMockedProfiler();
    // Should not throw during validation (may throw on fetch if unconfigured)
    const result = await p.profile("my-org/my.repo");
    expect(result.repoSlug).toBe("my-org/my.repo");
  });
});

// ---------------------------------------------------------------------------
// Commit velocity signal
// ---------------------------------------------------------------------------

describe("GitHubRepositoryProfiler — commit velocity", () => {
  it("counts commits in the last 90 days", () => {
    const { profiler } = makeMockedProfiler();
    const signals = profiler.computeSignals(
      healthyRepo(),
      buildCommits(25) as never,
      [],
      []
    );
    expect(signals.commit_velocity_90d).toBe(25);
  });

  it("returns undefined when commit list is empty", () => {
    const { profiler } = makeMockedProfiler();
    const signals = profiler.computeSignals(healthyRepo(), [], [], []);
    expect(signals.commit_velocity_90d).toBeUndefined();
  });

  it("returns 1 for single commit", () => {
    const { profiler } = makeMockedProfiler();
    const commits = [{ sha: "abc123", commit: { author: { date: daysAgo(1) } } }];
    const signals = profiler.computeSignals(healthyRepo(), commits as never, [], []);
    expect(signals.commit_velocity_90d).toBe(1);
  });

  it("stores lastCommitAt from first commit", () => {
    const { profiler } = makeMockedProfiler();
    const date = daysAgo(3);
    const commits = [{ sha: "abc", commit: { author: { date } } }];
    const signals = profiler.computeSignals(healthyRepo(), commits as never, [], []);
    expect(signals.lastCommitAt).toBe(date);
  });

  it("falls back to pushed_at when no commits", () => {
    const { profiler } = makeMockedProfiler();
    const repo = { ...healthyRepo(), pushed_at: daysAgo(2) };
    const signals = profiler.computeSignals(repo, [], [], []);
    expect(signals.lastCommitAt).toBe(repo.pushed_at);
  });
});

// ---------------------------------------------------------------------------
// Release cadence signal
// ---------------------------------------------------------------------------

describe("GitHubRepositoryProfiler — release cadence", () => {
  it("computes average cadence for multiple releases", () => {
    const { profiler } = makeMockedProfiler();
    // 5 releases, 30 days apart → avg cadence ≈ 30 days
    const releases = buildReleases(5, 30);
    const signals = profiler.computeSignals(healthyRepo(), [], releases as never, []);
    expect(signals.release_cadence_days).toBeDefined();
    expect(signals.release_cadence_days!).toBeGreaterThan(0);
  });

  it("returns undefined for zero releases", () => {
    const { profiler } = makeMockedProfiler();
    const signals = profiler.computeSignals(healthyRepo(), [], [], []);
    expect(signals.release_cadence_days).toBeUndefined();
    expect(signals.totalReleases).toBe(0);
  });

  it("returns undefined for single release (no cadence possible)", () => {
    const { profiler } = makeMockedProfiler();
    const releases = buildReleases(1, 30);
    const signals = profiler.computeSignals(healthyRepo(), [], releases as never, []);
    expect(signals.release_cadence_days).toBeUndefined();
    expect(signals.totalReleases).toBe(1);
  });

  it("excludes pre-releases from cadence", () => {
    const { profiler } = makeMockedProfiler();
    const releases = [
      ...buildReleases(2, 30), // stable
      ...buildReleases(3, 5, { prerelease: true }), // pre-releases excluded
    ];
    const signals = profiler.computeSignals(healthyRepo(), [], releases as never, []);
    expect(signals.totalReleases).toBe(2); // only stable counted
  });

  it("excludes draft releases from cadence", () => {
    const { profiler } = makeMockedProfiler();
    const releases = [
      ...buildReleases(2, 30), // stable
      ...buildReleases(2, 10, { draft: true }), // drafts excluded
    ];
    const signals = profiler.computeSignals(healthyRepo(), [], releases as never, []);
    expect(signals.totalReleases).toBe(2);
  });

  it("stores lastReleaseAt correctly", () => {
    const { profiler } = makeMockedProfiler();
    const releases = buildReleases(3, 30);
    const signals = profiler.computeSignals(healthyRepo(), [], releases as never, []);
    expect(signals.lastReleaseAt).toBeDefined();
    // Most recent release should be ~30 days ago (first in list)
    const lastReleaseDate = new Date(signals.lastReleaseAt!).getTime();
    expect(lastReleaseDate).toBeGreaterThan(Date.now() - 40 * 24 * 60 * 60 * 1000);
  });

  it("handles very slow cadence (abandoned package)", () => {
    const { profiler } = makeMockedProfiler();
    const releases = [
      { tag_name: "v1.0.0", published_at: yearsAgo(3), prerelease: false, draft: false },
      { tag_name: "v2.0.0", published_at: yearsAgo(1), prerelease: false, draft: false },
    ];
    const signals = profiler.computeSignals(healthyRepo(), [], releases as never, []);
    expect(signals.release_cadence_days!).toBeGreaterThan(365);
  });
});

// ---------------------------------------------------------------------------
// Contributor turnover signal
// ---------------------------------------------------------------------------

describe("GitHubRepositoryProfiler — contributor turnover", () => {
  it("returns 0.9 for single contributor (bus-factor risk)", () => {
    const { profiler } = makeMockedProfiler();
    const signals = profiler.computeSignals(
      healthyRepo(), [], [], buildContributors(1) as never
    );
    expect(signals.contributor_turnover).toBe(0.9);
    expect(signals.activeContributorCount).toBe(1);
  });

  it("returns 0.6 for 2 contributors", () => {
    const { profiler } = makeMockedProfiler();
    const signals = profiler.computeSignals(
      healthyRepo(), [], [], buildContributors(2) as never
    );
    expect(signals.contributor_turnover).toBe(0.6);
  });

  it("returns 0.0 for 5+ contributors (healthy)", () => {
    const { profiler } = makeMockedProfiler();
    const signals = profiler.computeSignals(
      healthyRepo(), [], [], buildContributors(10) as never
    );
    expect(signals.contributor_turnover).toBe(0.0);
  });

  it("returns undefined when contributor list is empty", () => {
    const { profiler } = makeMockedProfiler();
    const signals = profiler.computeSignals(healthyRepo(), [], [], []);
    expect(signals.contributor_turnover).toBeUndefined();
    expect(signals.activeContributorCount).toBe(0);
  });

  it("computes precise turnover from weekly data — full churn", () => {
    const { profiler } = makeMockedProfiler();
    const nowSec = Math.floor(Date.now() / 1000);
    const prevWindow = nowSec - 500 * 24 * 3600; // 500 days ago (in prev window)
    const recentWindow = nowSec - 60 * 24 * 3600; // 60 days ago (in recent window)

    const contributors = [
      {
        login: "old-dev",
        weeks: [{ w: prevWindow, c: 5 }], // only in prev window
      },
      {
        login: "new-dev",
        weeks: [{ w: recentWindow, c: 10 }], // only in recent window
      },
    ];
    const result = profiler.computeContributorTurnoverFromWeeklyData(contributors);
    // old-dev left, new-dev joined. 1/1 prev contributors left → 100% turnover
    expect(result.contributor_turnover).toBe(1);
  });

  it("computes precise turnover from weekly data — no churn", () => {
    const { profiler } = makeMockedProfiler();
    const nowSec = Math.floor(Date.now() / 1000);
    const prevWindow = nowSec - 500 * 24 * 3600;
    const recentWindow = nowSec - 60 * 24 * 3600;

    const contributors = [
      {
        login: "dev-a",
        weeks: [
          { w: prevWindow, c: 3 },
          { w: recentWindow, c: 5 },
        ],
      },
      {
        login: "dev-b",
        weeks: [
          { w: prevWindow, c: 2 },
          { w: recentWindow, c: 4 },
        ],
      },
    ];
    const result = profiler.computeContributorTurnoverFromWeeklyData(contributors);
    expect(result.contributor_turnover).toBe(0);
    expect(result.activeContributorCount).toBe(2);
  });

  it("returns undefined turnover when previous window is empty", () => {
    const { profiler } = makeMockedProfiler();
    const nowSec = Math.floor(Date.now() / 1000);
    const recentWindow = nowSec - 60 * 24 * 3600;

    const contributors = [
      { login: "new-dev", weeks: [{ w: recentWindow, c: 5 }] },
    ];
    const result = profiler.computeContributorTurnoverFromWeeklyData(contributors);
    expect(result.contributor_turnover).toBeUndefined();
    expect(result.activeContributorCount).toBe(1);
  });

  it("returns undefined for empty weekly contributor list", () => {
    const { profiler } = makeMockedProfiler();
    const result = profiler.computeContributorTurnoverFromWeeklyData([]);
    expect(result.contributor_turnover).toBeUndefined();
    expect(result.activeContributorCount).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// License analysis
// ---------------------------------------------------------------------------

describe("GitHubRepositoryProfiler — license analysis", () => {
  it("marks MIT license as not deprecated", () => {
    const { profiler } = makeMockedProfiler();
    const signals = profiler.computeSignals(
      { ...healthyRepo(), license: { spdx_id: "MIT", key: "mit" } },
      [], [], []
    );
    expect(signals.license_deprecated).toBe(false);
    expect(signals.spdxKey).toBe("MIT");
  });

  it("marks Apache-2.0 as not deprecated", () => {
    const { profiler } = makeMockedProfiler();
    const signals = profiler.computeSignals(
      { ...healthyRepo(), license: { spdx_id: "Apache-2.0", key: "apache-2.0" } },
      [], [], []
    );
    expect(signals.license_deprecated).toBe(false);
  });

  it("marks GPL-2.0 (deprecated alias) as deprecated", () => {
    const { profiler } = makeMockedProfiler();
    const signals = profiler.computeSignals(
      { ...healthyRepo(), license: { spdx_id: "GPL-2.0", key: "gpl-2.0" } },
      [], [], []
    );
    expect(signals.license_deprecated).toBe(true);
  });

  it("marks GPL-3.0 (deprecated alias) as deprecated", () => {
    const { profiler } = makeMockedProfiler();
    const signals = profiler.computeSignals(
      { ...healthyRepo(), license: { spdx_id: "GPL-3.0", key: "gpl-3.0" } },
      [], [], []
    );
    expect(signals.license_deprecated).toBe(true);
  });

  it("marks NOASSERTION (GitHub placeholder) as deprecated", () => {
    const { profiler } = makeMockedProfiler();
    const signals = profiler.computeSignals(
      { ...healthyRepo(), license: { spdx_id: "NOASSERTION", key: "other" } },
      [], [], []
    );
    expect(signals.license_deprecated).toBe(true);
  });

  it("marks null license as deprecated", () => {
    const { profiler } = makeMockedProfiler();
    const signals = profiler.computeSignals(
      { ...healthyRepo(), license: null },
      [], [], []
    );
    expect(signals.license_deprecated).toBe(true);
    expect(signals.spdxKey).toBeUndefined();
  });

  it("marks missing license field as deprecated", () => {
    const { profiler } = makeMockedProfiler();
    const repo = { ...healthyRepo() };
    delete (repo as Record<string, unknown>)["license"];
    const signals = profiler.computeSignals(repo, [], [], []);
    expect(signals.license_deprecated).toBe(true);
  });

  it("marks AGPL-3.0 (deprecated alias) as deprecated", () => {
    const { profiler } = makeMockedProfiler();
    const signals = profiler.computeSignals(
      { ...healthyRepo(), license: { spdx_id: "AGPL-3.0", key: "agpl-3.0" } },
      [], [], []
    );
    expect(signals.license_deprecated).toBe(true);
  });

  it("marks BSD-2-Clause as not deprecated", () => {
    const { profiler } = makeMockedProfiler();
    const signals = profiler.computeSignals(
      { ...healthyRepo(), license: { spdx_id: "BSD-2-Clause", key: "bsd-2-clause" } },
      [], [], []
    );
    expect(signals.license_deprecated).toBe(false);
  });

  it("marks ISC as not deprecated", () => {
    const { profiler } = makeMockedProfiler();
    const signals = profiler.computeSignals(
      { ...healthyRepo(), license: { spdx_id: "ISC", key: "isc" } },
      [], [], []
    );
    expect(signals.license_deprecated).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Dependency age signal
// ---------------------------------------------------------------------------

describe("GitHubRepositoryProfiler — dependency age", () => {
  it("returns undefined when repo lacks created_at", () => {
    const { profiler } = makeMockedProfiler();
    const repo = { ...healthyRepo(), created_at: undefined };
    const signals = profiler.computeSignals(repo, [], [], []);
    expect(signals.dependency_age_percentile).toBeUndefined();
  });

  it("returns a number between 0 and 100 for a normal repo", () => {
    const { profiler } = makeMockedProfiler();
    const signals = profiler.computeSignals(healthyRepo(), [], [], []);
    expect(signals.dependency_age_percentile).toBeDefined();
    expect(signals.dependency_age_percentile!).toBeGreaterThanOrEqual(0);
    expect(signals.dependency_age_percentile!).toBeLessThanOrEqual(100);
  });

  it("gives higher age percentile for old repo with no recent pushes", () => {
    const { profiler } = makeMockedProfiler();
    const staleRepo = {
      ...healthyRepo(),
      created_at: yearsAgo(7),
      pushed_at: yearsAgo(3),
    };
    const activeRepo = {
      ...healthyRepo(),
      created_at: yearsAgo(1),
      pushed_at: daysAgo(2),
    };
    const staleSignals = profiler.computeSignals(staleRepo, [], [], []);
    const activeSignals = profiler.computeSignals(activeRepo, [], [], []);
    expect(staleSignals.dependency_age_percentile!).toBeGreaterThan(
      activeSignals.dependency_age_percentile!
    );
  });
});

// ---------------------------------------------------------------------------
// Profile integration — full pipeline
// ---------------------------------------------------------------------------

describe("GitHubRepositoryProfiler — profile() integration", () => {
  it("returns a valid GitHubRepositoryProfile for a healthy repo", async () => {
    const { profiler } = makeMockedProfiler(
      healthyRepo(),
      buildCommits(20),
      buildReleases(5, 30),
      buildContributors(5)
    );
    const profile = await profiler.profile("test-owner/test-repo", "1.0.0");

    expect(profile.repoSlug).toBe("test-owner/test-repo");
    expect(profile.fromCache).toBe(false);
    expect(profile.fetchedAt).toBeDefined();
    expect(new Date(profile.fetchedAt).getFullYear()).toBeGreaterThan(2020);
    expect(profile.signals.commit_velocity_90d).toBe(20);
    expect(profile.signals.license_deprecated).toBe(false);
    expect(profile.healthResult).toBeDefined();
    expect(profile.healthResult.packageName).toBe("test-repo");
    expect(["none", "low", "medium", "high", "critical"]).toContain(
      profile.healthResult.riskLevel
    );
  });

  it("computes high risk for abandoned package (no commits, old releases)", async () => {
    const abandonedRepo = {
      ...healthyRepo(),
      license: { spdx_id: "UNLICENSED", key: "unlicensed" },
      pushed_at: yearsAgo(3),
      created_at: yearsAgo(6),
    };
    const { profiler } = makeMockedProfiler(
      abandonedRepo,
      [], // no commits
      [
        { tag_name: "v1.0.0", published_at: yearsAgo(4), prerelease: false, draft: false },
        { tag_name: "v1.0.1", published_at: yearsAgo(3), prerelease: false, draft: false },
      ],
      buildContributors(1)
    );
    const profile = await profiler.profile("abandoned/pkg", "1.0.0");
    expect(["high", "critical", "medium"]).toContain(
      profile.healthResult.riskLevel
    );
    expect(profile.signals.license_deprecated).toBe(true);
  });

  it("sets ecosystem correctly for pypi", async () => {
    const { profiler } = makeMockedProfiler();
    const profile = await profiler.profile("test-owner/test-repo", "1.0.0", "pypi");
    expect(profile.healthResult.ecosystem).toBe("pypi");
  });

  it("uses version string from argument", async () => {
    const { profiler } = makeMockedProfiler();
    const profile = await profiler.profile("test-owner/test-repo", "3.2.1");
    expect(profile.healthResult.version).toBe("3.2.1");
  });

  it("defaults version to 'unknown'", async () => {
    const { profiler } = makeMockedProfiler();
    const profile = await profiler.profile("test-owner/test-repo");
    expect(profile.healthResult.version).toBe("unknown");
  });
});

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

describe("GitHubRepositoryProfiler — error handling", () => {
  it("throws GitHubProfilerError on 404 (repo not found)", async () => {
    const { profiler } = makeMockedProfiler(
      { message: "Not Found" },
      [],
      [],
      [],
      { repoStatus: 404 }
    );
    await expect(profiler.profile("nonexistent/repo")).rejects.toThrow(
      GitHubProfilerError
    );
  });

  it("throws GitHubProfilerError on 403 (rate limit / forbidden)", async () => {
    const { profiler } = makeMockedProfiler(
      { message: "Forbidden" },
      [],
      [],
      [],
      { repoStatus: 403 }
    );
    await expect(profiler.profile("test/repo")).rejects.toThrow(
      GitHubProfilerError
    );
  });

  it("GitHubProfilerError includes statusCode", async () => {
    const { profiler } = makeMockedProfiler(
      { message: "Not Found" },
      [],
      [],
      [],
      { repoStatus: 404 }
    );
    try {
      await profiler.profile("nonexistent/repo");
      expect.fail("Should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(GitHubProfilerError);
      expect((err as GitHubProfilerError).statusCode).toBe(404);
    }
  });

  it("GitHubProfilerError includes repoSlug", async () => {
    const { profiler } = makeMockedProfiler(
      { message: "Not Found" },
      [],
      [],
      [],
      { repoStatus: 404 }
    );
    try {
      await profiler.profile("my-org/my-repo");
      expect.fail("Should have thrown");
    } catch (err) {
      expect((err as GitHubProfilerError).repoSlug).toBe("my-org/my-repo");
    }
  });

  it("returns empty commits on 409 (empty repo)", async () => {
    // 409 on commits = uninitialized repo, should not crash
    const { profiler } = makeMockedProfiler(
      healthyRepo(),
      [],
      buildReleases(2),
      buildContributors(2),
      { commitsStatus: 409 }
    );
    const profile = await profiler.profile("test/empty-repo");
    expect(profile.signals.commit_velocity_90d).toBeUndefined();
  });

  it("gracefully handles 403 on contributors endpoint (private repo)", async () => {
    const { profiler } = makeMockedProfiler(
      healthyRepo(),
      buildCommits(10),
      buildReleases(3),
      [],
      { contributorsStatus: 403 }
    );
    const profile = await profiler.profile("test/private-repo");
    expect(profile.signals.contributor_turnover).toBeUndefined();
    expect(profile.signals.activeContributorCount).toBe(0);
  });

  it("gracefully handles 404 on releases endpoint", async () => {
    const { profiler } = makeMockedProfiler(
      healthyRepo(),
      buildCommits(10),
      [],
      buildContributors(3),
      { releasesStatus: 404 }
    );
    const profile = await profiler.profile("test/no-releases-repo");
    expect(profile.signals.release_cadence_days).toBeUndefined();
    expect(profile.signals.totalReleases).toBe(0);
  });

  it("GitHubProfilerError name is 'GitHubProfilerError'", () => {
    const err = new GitHubProfilerError("test message", 404, "owner/repo");
    expect(err.name).toBe("GitHubProfilerError");
    expect(err.message).toBe("test message");
    expect(err.statusCode).toBe(404);
    expect(err.repoSlug).toBe("owner/repo");
  });

  it("GitHubProfilerError is instanceof Error", () => {
    const err = new GitHubProfilerError("test");
    expect(err).toBeInstanceOf(Error);
  });
});

// ---------------------------------------------------------------------------
// Cache behaviour
// ---------------------------------------------------------------------------

describe("GitHubRepositoryProfiler — cache", () => {
  it("caches result on second call with same slug/version", async () => {
    const fetchFn = vi.fn(async (url: string) => {
      if (url.includes("/commits")) return mockResponse(200, buildCommits(5));
      if (url.includes("/releases")) return mockResponse(200, buildReleases(3));
      if (url.includes("/contributors")) return mockResponse(200, buildContributors(3));
      return mockResponse(200, healthyRepo());
    });
    const profiler = new GitHubRepositoryProfiler({
      token: "test-token",
      fetch: fetchFn,
      cacheTtlMs: DEFAULT_CACHE_TTL_MS,
    });

    const p1 = await profiler.profile("test-owner/test-repo", "1.0.0");
    const p2 = await profiler.profile("test-owner/test-repo", "1.0.0");

    expect(p1.fromCache).toBe(false);
    expect(p2.fromCache).toBe(true);
    // fetch called 4 times for first call (repo, commits, releases, contributors)
    // second call should use cache
    expect(fetchFn).toHaveBeenCalledTimes(4);
  });

  it("does not serve different versions from same slug cache", async () => {
    const fetchFn = vi.fn(async (url: string) => {
      if (url.includes("/commits")) return mockResponse(200, buildCommits(5));
      if (url.includes("/releases")) return mockResponse(200, buildReleases(3));
      if (url.includes("/contributors")) return mockResponse(200, buildContributors(3));
      return mockResponse(200, healthyRepo());
    });
    const profiler = new GitHubRepositoryProfiler({
      token: "test-token",
      fetch: fetchFn,
      cacheTtlMs: DEFAULT_CACHE_TTL_MS,
    });

    await profiler.profile("test-owner/test-repo", "1.0.0");
    const p2 = await profiler.profile("test-owner/test-repo", "2.0.0");
    expect(p2.fromCache).toBe(false);
    expect(fetchFn).toHaveBeenCalledTimes(8); // 4 + 4 calls
  });

  it("invalidate() removes matching slug from cache", async () => {
    const fetchFn = vi.fn(async (url: string) => {
      if (url.includes("/commits")) return mockResponse(200, buildCommits(5));
      if (url.includes("/releases")) return mockResponse(200, buildReleases(3));
      if (url.includes("/contributors")) return mockResponse(200, buildContributors(3));
      return mockResponse(200, healthyRepo());
    });
    const profiler = new GitHubRepositoryProfiler({
      token: "test-token",
      fetch: fetchFn,
      cacheTtlMs: DEFAULT_CACHE_TTL_MS,
    });

    await profiler.profile("test-owner/test-repo", "1.0.0");
    expect(profiler.cacheSize()).toBe(1);

    profiler.invalidate("test-owner/test-repo");
    expect(profiler.cacheSize()).toBe(0);

    const p3 = await profiler.profile("test-owner/test-repo", "1.0.0");
    expect(p3.fromCache).toBe(false);
  });

  it("clearCache() removes all entries", async () => {
    const fetchFn = vi.fn(async (url: string) => {
      if (url.includes("/commits")) return mockResponse(200, buildCommits(5));
      if (url.includes("/releases")) return mockResponse(200, buildReleases(3));
      if (url.includes("/contributors")) return mockResponse(200, buildContributors(3));
      return mockResponse(200, healthyRepo());
    });
    const profiler = new GitHubRepositoryProfiler({
      token: "test-token",
      fetch: fetchFn,
      cacheTtlMs: DEFAULT_CACHE_TTL_MS,
    });

    await profiler.profile("test-owner/test-repo", "1.0.0");
    await profiler.profile("test-owner/test-repo", "2.0.0");
    expect(profiler.cacheSize()).toBe(2);

    profiler.clearCache();
    expect(profiler.cacheSize()).toBe(0);
  });

  it("cacheTtlMs=0 disables caching", async () => {
    const fetchFn = vi.fn(async (url: string) => {
      if (url.includes("/commits")) return mockResponse(200, buildCommits(5));
      if (url.includes("/releases")) return mockResponse(200, buildReleases(3));
      if (url.includes("/contributors")) return mockResponse(200, buildContributors(3));
      return mockResponse(200, healthyRepo());
    });
    const profiler = new GitHubRepositoryProfiler({
      token: "test-token",
      fetch: fetchFn,
      cacheTtlMs: 0,
    });

    await profiler.profile("test-owner/test-repo", "1.0.0");
    const p2 = await profiler.profile("test-owner/test-repo", "1.0.0");
    expect(p2.fromCache).toBe(false);
    expect(profiler.cacheSize()).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// buildSyntheticNpmMetadata round-trip
// ---------------------------------------------------------------------------

describe("GitHubRepositoryProfiler — buildSyntheticNpmMetadata", () => {
  it("encodes license_deprecated=true as UNLICENSED", () => {
    const { profiler } = makeMockedProfiler();
    const signals: GitHubMaintenanceSignals = {
      commit_velocity_90d: 10,
      release_cadence_days: undefined,
      contributor_turnover: undefined,
      dependency_age_percentile: undefined,
      license_deprecated: true,
      spdxKey: "GPL-2.0",
      lastCommitAt: undefined,
      lastReleaseAt: undefined,
      activeContributorCount: 0,
      totalReleases: 0,
    };
    const meta = profiler.buildSyntheticNpmMetadata("test-pkg", signals, {});
    expect(meta.license).toBe("UNLICENSED");
  });

  it("encodes license_deprecated=false with real spdxKey", () => {
    const { profiler } = makeMockedProfiler();
    const signals: GitHubMaintenanceSignals = {
      commit_velocity_90d: 10,
      release_cadence_days: undefined,
      contributor_turnover: undefined,
      dependency_age_percentile: undefined,
      license_deprecated: false,
      spdxKey: "Apache-2.0",
      lastCommitAt: undefined,
      lastReleaseAt: undefined,
      activeContributorCount: 0,
      totalReleases: 0,
    };
    const meta = profiler.buildSyntheticNpmMetadata("test-pkg", signals, {});
    expect(meta.license).toBe("Apache-2.0");
  });

  it("encodes dependency_age_percentile=100 as all-pinned deps", () => {
    const { profiler } = makeMockedProfiler();
    const signals: GitHubMaintenanceSignals = {
      commit_velocity_90d: undefined,
      release_cadence_days: undefined,
      contributor_turnover: undefined,
      dependency_age_percentile: 100,
      license_deprecated: false,
      spdxKey: "MIT",
      lastCommitAt: undefined,
      lastReleaseAt: undefined,
      activeContributorCount: 0,
      totalReleases: 0,
    };
    const meta = profiler.buildSyntheticNpmMetadata("test-pkg", signals, {});
    const deps = meta.versions?.["1.0.0"]?.dependencies ?? {};
    const values = Object.values(deps);
    const pinned = values.filter((v) => /^\d+\.\d+\.\d+$/.test(v));
    // All 10 synthetic deps should be exact-pinned
    expect(pinned.length).toBe(10);
    expect(values.length).toBe(10);
  });

  it("encodes dependency_age_percentile=0 as all-ranged deps", () => {
    const { profiler } = makeMockedProfiler();
    const signals: GitHubMaintenanceSignals = {
      commit_velocity_90d: undefined,
      release_cadence_days: undefined,
      contributor_turnover: undefined,
      dependency_age_percentile: 0,
      license_deprecated: false,
      spdxKey: "MIT",
      lastCommitAt: undefined,
      lastReleaseAt: undefined,
      activeContributorCount: 0,
      totalReleases: 0,
    };
    const meta = profiler.buildSyntheticNpmMetadata("test-pkg", signals, {});
    const deps = meta.versions?.["1.0.0"]?.dependencies ?? {};
    const values = Object.values(deps);
    const pinned = values.filter((v) => /^\d+\.\d+\.\d+$/.test(v));
    expect(pinned.length).toBe(0);
  });

  it("encodes single-contributor turnover as 1 maintainer", () => {
    const { profiler } = makeMockedProfiler();
    const signals: GitHubMaintenanceSignals = {
      commit_velocity_90d: undefined,
      release_cadence_days: undefined,
      contributor_turnover: 0.9,
      dependency_age_percentile: undefined,
      license_deprecated: false,
      spdxKey: "MIT",
      lastCommitAt: undefined,
      lastReleaseAt: undefined,
      activeContributorCount: 1,
      totalReleases: 0,
    };
    const meta = profiler.buildSyntheticNpmMetadata("test-pkg", signals, {});
    expect(meta.maintainers).toHaveLength(1);
  });

  it("encodes healthy turnover (0.0) as 5 maintainers", () => {
    const { profiler } = makeMockedProfiler();
    const signals: GitHubMaintenanceSignals = {
      commit_velocity_90d: undefined,
      release_cadence_days: undefined,
      contributor_turnover: 0.0,
      dependency_age_percentile: undefined,
      license_deprecated: false,
      spdxKey: "MIT",
      lastCommitAt: undefined,
      lastReleaseAt: undefined,
      activeContributorCount: 10,
      totalReleases: 0,
    };
    const meta = profiler.buildSyntheticNpmMetadata("test-pkg", signals, {});
    expect(meta.maintainers!.length).toBeGreaterThanOrEqual(5);
  });

  it("sets correct package name on synthetic metadata", () => {
    const { profiler } = makeMockedProfiler();
    const signals: GitHubMaintenanceSignals = {
      commit_velocity_90d: undefined,
      release_cadence_days: undefined,
      contributor_turnover: undefined,
      dependency_age_percentile: undefined,
      license_deprecated: false,
      spdxKey: "MIT",
      lastCommitAt: undefined,
      lastReleaseAt: undefined,
      activeContributorCount: 0,
      totalReleases: 0,
    };
    const meta = profiler.buildSyntheticNpmMetadata("my-package", signals, {});
    expect(meta.name).toBe("my-package");
  });
});

// ---------------------------------------------------------------------------
// Private repo / orphaned package edge cases
// ---------------------------------------------------------------------------

describe("GitHubRepositoryProfiler — private repo / orphaned package", () => {
  it("handles private repo with no contributors gracefully", async () => {
    const { profiler } = makeMockedProfiler(
      { ...healthyRepo(), private: true },
      buildCommits(5),
      [],
      [],
      { contributorsStatus: 403 }
    );
    const profile = await profiler.profile("company/private-repo");
    expect(profile.signals.contributor_turnover).toBeUndefined();
    expect(profile.healthResult).toBeDefined();
  });

  it("handles repo with zero commits and zero releases (orphaned package)", async () => {
    const { profiler } = makeMockedProfiler(
      {
        ...healthyRepo(),
        license: null,
        pushed_at: yearsAgo(4),
      },
      [], // no commits
      [], // no releases
      buildContributors(1)
    );
    const profile = await profiler.profile("orphan/pkg");
    expect(profile.signals.commit_velocity_90d).toBeUndefined();
    expect(profile.signals.release_cadence_days).toBeUndefined();
    expect(profile.signals.license_deprecated).toBe(true);
    // Should still produce a valid risk assessment
    expect(profile.healthResult.riskLevel).toBeDefined();
  });

  it("handles repo where GitHub returns 202 for contributors (computing)", async () => {
    const fetchFn = vi.fn(async (url: string) => {
      if (url.includes("/contributors")) return mockResponse(202, []);
      if (url.includes("/commits")) return mockResponse(200, buildCommits(5));
      if (url.includes("/releases")) return mockResponse(200, buildReleases(2));
      return mockResponse(200, healthyRepo());
    });
    const profiler = new GitHubRepositoryProfiler({
      token: "t",
      fetch: fetchFn,
      cacheTtlMs: 0,
    });
    const profile = await profiler.profile("test/computing-stats");
    expect(profile.signals.contributor_turnover).toBeUndefined();
    expect(profile.healthResult).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// buildHealthResult
// ---------------------------------------------------------------------------

describe("GitHubRepositoryProfiler — buildHealthResult", () => {
  it("produces a health result with all required fields", () => {
    const { profiler } = makeMockedProfiler();
    const signals: GitHubMaintenanceSignals = {
      commit_velocity_90d: 15,
      release_cadence_days: 30,
      contributor_turnover: 0.0,
      dependency_age_percentile: 20,
      license_deprecated: false,
      spdxKey: "MIT",
      lastCommitAt: daysAgo(5),
      lastReleaseAt: daysAgo(30),
      activeContributorCount: 5,
      totalReleases: 10,
    };
    const result = profiler.buildHealthResult(
      "test-pkg",
      "1.0.0",
      "npm",
      signals,
      healthyRepo()
    );
    expect(result.packageName).toBe("test-pkg");
    expect(result.version).toBe("1.0.0");
    expect(result.ecosystem).toBe("npm");
    expect(result.riskScore).toBeGreaterThanOrEqual(0);
    expect(result.riskScore).toBeLessThanOrEqual(100);
    expect(result.analyzedAt).toBeDefined();
    expect(Array.isArray(result.findings)).toBe(true);
  });

  it("produces high/critical risk for abandoned package with bad license", () => {
    const { profiler } = makeMockedProfiler();
    const signals: GitHubMaintenanceSignals = {
      commit_velocity_90d: 0,
      release_cadence_days: 800,
      contributor_turnover: 0.9,
      dependency_age_percentile: 95,
      license_deprecated: true,
      spdxKey: "UNLICENSED",
      lastCommitAt: yearsAgo(3),
      lastReleaseAt: yearsAgo(3),
      activeContributorCount: 1,
      totalReleases: 2,
    };
    const result = profiler.buildHealthResult(
      "abandoned-pkg",
      "1.0.0",
      "npm",
      signals,
      healthyRepo()
    );
    expect(["high", "critical"]).toContain(result.riskLevel);
  });

  it("overrides ecosystem to pypi when specified", () => {
    const { profiler } = makeMockedProfiler();
    const signals: GitHubMaintenanceSignals = {
      commit_velocity_90d: 10,
      release_cadence_days: 30,
      contributor_turnover: 0.2,
      dependency_age_percentile: 30,
      license_deprecated: false,
      spdxKey: "MIT",
      lastCommitAt: daysAgo(5),
      lastReleaseAt: daysAgo(30),
      activeContributorCount: 4,
      totalReleases: 5,
    };
    const result = profiler.buildHealthResult(
      "my-pypi-pkg",
      "2.0.0",
      "pypi",
      signals,
      healthyRepo()
    );
    expect(result.ecosystem).toBe("pypi");
  });
});

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
