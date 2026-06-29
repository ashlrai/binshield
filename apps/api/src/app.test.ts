import { beforeEach, describe, expect, it, vi } from "vitest";

import { createApp } from "./app";
import { app } from "./app";
import {
  fetchNpmMetadata,
  fetchPypiMetadata,
  parseCycloneDxSbom,
  parseLockfile,
  verifySbomProvenance,
} from "./lib/sbom-provenance-checker";

const headers = {
  "Content-Type": "application/json",
  "x-binshield-api-key": "binshield-dev-key"
};

describe("api", () => {
  beforeEach(() => {});

  it("returns search results", async () => {
    const response = await app.request("/packages/search?q=bcrypt");
    expect(response.status).toBe(200);

    const body = await response.json();
    expect(body.total).toBeGreaterThan(0);
  });

  it("supports search pagination", async () => {
    const response = await app.request("/packages/search?limit=1&offset=0");
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.items.length).toBeLessThanOrEqual(1);
    expect(body.total).toBeGreaterThan(0);
  });

  it("creates a scan job with api key auth", async () => {
    const response = await app.request("/scans/packages", {
      method: "POST",
      headers,
      body: JSON.stringify({
        ecosystem: "npm",
        packageName: "bcrypt",
        version: "5.1.1"
      })
    });

    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.status).toBe("complete");
  });

  it("rejects invalid ecosystem on scan", async () => {
    const response = await app.request("/scans/packages", {
      method: "POST",
      headers,
      body: JSON.stringify({
        ecosystem: "rubygems",
        packageName: "bcrypt",
        version: "5.1.1"
      })
    });

    expect(response.status).toBe(400);
    const body = await response.json();
    expect(body.error).toContain("Invalid ecosystem");
  });

  it("requires auth for scan endpoints", async () => {
    const response = await app.request("/scans/packages", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ecosystem: "npm", packageName: "bcrypt", version: "5.1.1" })
    });
    expect(response.status).toBe(401);
  });

  it("creates org-scoped resources", async () => {
    const watchlistResponse = await app.request("/orgs/org_demo/watchlists", {
      method: "POST",
      headers,
      body: JSON.stringify({
        name: "Runtime dependencies",
        channel: "email",
        destination: "security@binshield.dev"
      })
    });

    expect(watchlistResponse.status).toBe(201);
    const watchlist = await watchlistResponse.json();
    expect(watchlist.name).toBe("Runtime dependencies");

    const subscriptionResponse = await app.request("/orgs/org_demo/subscription", {
      method: "POST",
      headers,
      body: JSON.stringify({
        plan: "pro",
        status: "active"
      })
    });

    expect(subscriptionResponse.status).toBe(200);
    const subscription = await subscriptionResponse.json();
    expect(subscription.plan).toBe("pro");
  });

  it("creates and revokes an API key", async () => {
    const createResponse = await app.request("/orgs/org_demo/api-keys", {
      method: "POST",
      headers,
      body: JSON.stringify({ label: "test-key" })
    });

    expect(createResponse.status).toBe(201);
    const created = await createResponse.json();
    expect(created.plaintextKey).toBeTruthy();
    expect(created.summary.label).toBe("test-key");

    // Revoke the key
    const revokeResponse = await app.request(`/orgs/org_demo/api-keys/${created.summary.id}`, {
      method: "DELETE",
      headers,
    });
    expect(revokeResponse.status).toBe(200);

    // Revoking again should 404
    const revokeAgain = await app.request(`/orgs/org_demo/api-keys/${created.summary.id}`, {
      method: "DELETE",
      headers,
    });
    expect(revokeAgain.status).toBe(404);
  });

  it("returns package advisories", async () => {
    const response = await app.request("/packages/npm/bcrypt/advisories");
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.items.length).toBeGreaterThan(0);
    expect(body.items[0].title).toBeTruthy();
  });

  it("returns recent advisories", async () => {
    const response = await app.request("/advisories/recent?limit=3");
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.items.length).toBeLessThanOrEqual(3);
    expect(body.items.length).toBeGreaterThan(0);
  });

  it("generates SBOM for a package", async () => {
    const response = await app.request("/packages/npm/bcrypt/versions/5.1.1/sbom");
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.bomFormat).toBe("CycloneDX");
    expect(body.specVersion).toBe("1.5");
    expect(body.components.length).toBeGreaterThan(0);
  });

  it("enforces feature gate on compliance reports", async () => {
    const response = await app.request("/orgs/org_demo/reports", {
      method: "POST",
      headers,
      body: JSON.stringify({ reportType: "soc2" })
    });
    // Demo org is on "free" plan, compliance_reports requires "enterprise"
    expect(response.status).toBe(403);
    const body = await response.json();
    expect(body.error).toContain("compliance_reports");
  });

  it("rejects unrecognized lockfile format", async () => {
    const response = await app.request("/scans/lockfile", {
      method: "POST",
      headers,
      body: JSON.stringify({ filename: "random.txt", content: "hello world" })
    });
    expect(response.status).toBe(400);
    const body = await response.json();
    expect(body.error).toContain("Unrecognized lockfile format");
  });

  // ---------------------------------------------------------------------------
  // Public scan
  // ---------------------------------------------------------------------------

  it("allows anonymous public scan without API key", async () => {
    const response = await app.request("/public/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ecosystem: "npm", packageName: "bcrypt", version: "5.1.1" })
    });
    // LocalRepository has bcrypt pre-seeded, so it returns 200 complete
    expect([200, 202]).toContain(response.status);
    const body = await response.json();
    expect(body.id).toBeTruthy();
    expect(body.status).toMatch(/^(queued|complete)$/);
  });

  it("rejects invalid ecosystem on public scan", async () => {
    const response = await app.request("/public/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ecosystem: "rubygems", packageName: "bcrypt", version: "1.0.0" })
    });
    expect(response.status).toBe(400);
  });

  // ---------------------------------------------------------------------------
  // Finding suppressions
  // ---------------------------------------------------------------------------

  it("creates, lists, and deletes a suppression", async () => {
    // Create
    const createRes = await app.request("/orgs/org_demo/suppressions", {
      method: "POST",
      headers,
      body: JSON.stringify({
        ecosystem: "npm",
        packageName: "bcrypt",
        reason: "false positive — internal audit confirmed benign"
      })
    });
    expect(createRes.status).toBe(201);
    const created = await createRes.json();
    expect(created.id).toBeTruthy();
    expect(created.packageName).toBe("bcrypt");

    // List
    const listRes = await app.request("/orgs/org_demo/suppressions", { headers });
    expect(listRes.status).toBe(200);
    const listed = await listRes.json();
    expect(listed.items.length).toBeGreaterThan(0);
    expect(listed.items.some((s: { id: string }) => s.id === created.id)).toBe(true);

    // Delete
    const deleteRes = await app.request(`/orgs/org_demo/suppressions/${created.id}`, {
      method: "DELETE",
      headers
    });
    expect(deleteRes.status).toBe(200);

    // Confirm removed
    const listAfter = await app.request("/orgs/org_demo/suppressions", { headers });
    const afterBody = await listAfter.json();
    expect(afterBody.items.some((s: { id: string }) => s.id === created.id)).toBe(false);
  });

  it("requires auth for suppression endpoints", async () => {
    const res = await app.request("/orgs/org_demo/suppressions", {
      headers: { "Content-Type": "application/json" }
    });
    expect(res.status).toBe(401);
  });

  it("filters suppressed findings from package analysis", async () => {
    // Use a fresh app instance to avoid cross-test suppression state
    const freshApp = createApp();

    // Get unfiltered analysis — findings live on binaries
    const before = await freshApp.request("/packages/npm/bcrypt/versions/5.1.1", { headers });
    expect(before.status).toBe(200);
    const beforeBody = await before.json();

    // Find a binary that has findings
    const binaryWithFindings = (beforeBody.binaries ?? []).find(
      (b: { findings?: unknown[] }) => (b.findings ?? []).length > 0
    );

    if (binaryWithFindings) {
      const firstFinding = binaryWithFindings.findings[0] as { title: string };
      const originalCount = binaryWithFindings.findings.length;

      // Create a suppression targeting the first finding's title
      await freshApp.request("/orgs/org_demo/suppressions", {
        method: "POST",
        headers,
        body: JSON.stringify({
          ecosystem: "npm",
          packageName: "bcrypt",
          findingTitle: firstFinding.title,
          reason: "test suppression"
        })
      });

      // The filtered response should have one fewer finding on that binary
      const after = await freshApp.request("/packages/npm/bcrypt/versions/5.1.1", { headers });
      const afterBody = await after.json();
      const filteredBinary = (afterBody.binaries ?? []).find(
        (b: { id: string }) => b.id === binaryWithFindings.id
      ) as { findings?: unknown[] } | undefined;
      expect((filteredBinary?.findings ?? []).length).toBe(originalCount - 1);
    }
  });
});

// ---------------------------------------------------------------------------
// EPSS / risk-correlation endpoint
// ---------------------------------------------------------------------------

describe("risk-correlation endpoint", () => {
  it("returns risk-correlation for a known package with CVEs (bcrypt)", async () => {
    const response = await app.request("/packages/npm/bcrypt/versions/5.1.1/risk-correlation");
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.ecosystem).toBe("npm");
    expect(body.packageName).toBe("bcrypt");
    expect(body.version).toBe("5.1.1");
    expect(Array.isArray(body.cves)).toBe(true);
    expect(Array.isArray(body.cvssScores)).toBe(true);
    expect(Array.isArray(body.epssScores)).toBe(true);
    expect(typeof body.compositeExploitRisk).toBe("number");
    expect(body.compositeExploitRisk).toBeGreaterThanOrEqual(0);
    expect(body.compositeExploitRisk).toBeLessThanOrEqual(100);
  });

  it("returns risk-correlation for a package with no advisories", async () => {
    const response = await app.request("/packages/npm/unknown-pkg/versions/1.0.0/risk-correlation");
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.cves).toEqual([]);
    expect(body.cvssScores).toEqual([]);
    expect(body.epssScores).toEqual([]);
    expect(body.compositeExploitRisk).toBe(0);
  });

  it("compositeExploitRisk is bounded 0-100", async () => {
    const response = await app.request("/packages/npm/bcrypt/versions/5.1.1/risk-correlation");
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.compositeExploitRisk).toBeGreaterThanOrEqual(0);
    expect(body.compositeExploitRisk).toBeLessThanOrEqual(100);
  });

  it("cvssScores items have required fields", async () => {
    const response = await app.request("/packages/npm/bcrypt/versions/5.1.1/risk-correlation");
    expect(response.status).toBe(200);
    const body = await response.json();
    for (const entry of body.cvssScores) {
      expect(typeof entry.cveId).toBe("string");
      expect(typeof entry.cvssScore).toBe("number");
    }
  });
});

describe("suppression repository methods", () => {
  it("round-trips create / list / delete on LocalRepository", async () => {
    const app2 = createApp();

    const createRes = await app2.request("/orgs/org_demo/suppressions", {
      method: "POST",
      headers,
      body: JSON.stringify({
        ecosystem: "npm",
        packageName: "lodash",
        version: "4.17.21",
        findingCategory: "network",
        findingTitle: "unexpected outbound connection",
        reason: "confirmed false positive"
      })
    });
    expect(createRes.status).toBe(201);
    const s = await createRes.json();
    expect(s.version).toBe("4.17.21");
    expect(s.findingCategory).toBe("network");

    const listRes = await app2.request("/orgs/org_demo/suppressions", { headers });
    const { items } = await listRes.json();
    expect(items.length).toBe(1);

    const delRes = await app2.request(`/orgs/org_demo/suppressions/${s.id}`, {
      method: "DELETE",
      headers
    });
    expect(delRes.status).toBe(200);

    const listAfter = await app2.request("/orgs/org_demo/suppressions", { headers });
    const { items: afterItems } = await listAfter.json();
    expect(afterItems.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// /advisories/:cveId/exploit-activity — CISA KEV + NVD exploit-activity endpoint
// ---------------------------------------------------------------------------

describe("exploit-activity endpoint", () => {
  it("returns 400 for non-CVE identifiers", async () => {
    const res = await app.request("/advisories/GHSA-abcd-1234-wxyz/exploit-activity");
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toContain("CVE");
  });

  it("returns 404 for a CVE that does not exist in the local advisory store", async () => {
    const res = await app.request("/advisories/CVE-9999-99999/exploit-activity");
    expect(res.status).toBe(404);
  });

  it("returns exploit-activity shape for a seeded CVE", async () => {
    // CVE-2025-1234 is seeded in the local repository (adv_3 / sqlite3)
    const res = await app.request("/advisories/CVE-2025-1234/exploit-activity");
    expect(res.status).toBe(200);
    const body = await res.json() as {
      cveId: string;
      cisa_confirmed: boolean;
      first_seen_date: string | null;
      exploit_maturity: string | null;
      affected_versions: string[];
    };
    expect(body.cveId).toBe("CVE-2025-1234");
    expect(typeof body.cisa_confirmed).toBe("boolean");
    expect(body.first_seen_date === null || typeof body.first_seen_date === "string").toBe(true);
    expect(body.exploit_maturity === null || typeof body.exploit_maturity === "string").toBe(true);
    expect(Array.isArray(body.affected_versions)).toBe(true);
  });

  it("is case-insensitive on CVE ID", async () => {
    const upper = await app.request("/advisories/CVE-2025-1234/exploit-activity");
    const lower = await app.request("/advisories/cve-2025-1234/exploit-activity");
    expect(upper.status).toBe(200);
    expect(lower.status).toBe(200);
    const bodyUpper = await upper.json() as { cveId: string };
    const bodyLower = await lower.json() as { cveId: string };
    expect(bodyUpper.cveId).toBe(bodyLower.cveId);
  });

  it("returns affected_versions as an array of strings", async () => {
    const res = await app.request("/advisories/CVE-2025-1234/exploit-activity");
    const body = await res.json() as { affected_versions: unknown };
    expect(Array.isArray(body.affected_versions)).toBe(true);
    for (const v of body.affected_versions as string[]) {
      expect(typeof v).toBe("string");
    }
  });
});

// ---------------------------------------------------------------------------
// SBOM Provenance Checker — unit tests
// ---------------------------------------------------------------------------

/** Minimal valid CycloneDX SBOM with one npm component. */
function makeSbom(components: object[]): string {
  return JSON.stringify({
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: "urn:uuid:test",
    version: 1,
    components,
  });
}

/** Factory for a mock npm registry response. */
function npmMeta(name: string, version: string, opts: {
  integrity?: string;
  shasum?: string;
  deprecated?: string;
} = {}) {
  return {
    name,
    versions: {
      [version]: {
        dist: {
          tarball: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
          shasum: opts.shasum ?? "aabbcc",
          integrity: opts.integrity,
        },
        deprecated: opts.deprecated,
      },
    },
    time: { [version]: new Date().toISOString() },
  };
}

/** Factory for a mock PyPI registry response. */
function pypiMeta(name: string, version: string, opts: {
  sha256?: string;
  yanked?: boolean;
  yanked_reason?: string;
} = {}) {
  return {
    info: { name, version },
    releases: {
      [version]: [
        {
          digests: { md5: "md5hash", sha256: opts.sha256 ?? "abc123" },
          url: `https://files.pythonhosted.org/${name}-${version}.tar.gz`,
          yanked: opts.yanked ?? false,
          yanked_reason: opts.yanked_reason ?? null,
        },
      ],
    },
  };
}

describe("parseCycloneDxSbom", () => {
  it("extracts npm components by purl", () => {
    const sbom = makeSbom([
      {
        type: "library",
        "bom-ref": "pkg:npm/lodash@4.17.21",
        name: "lodash",
        purl: "pkg:npm/lodash@4.17.21",
        hashes: [{ alg: "SHA-256", content: "sha256-lodash" }],
      },
    ]);
    const deps = parseCycloneDxSbom(sbom, "npm");
    expect(deps).toHaveLength(1);
    expect(deps[0]!.packageName).toBe("lodash");
    expect(deps[0]!.version).toBe("4.17.21");
    expect(deps[0]!.sbomHash).toBe("sha256-lodash");
  });

  it("filters out non-matching ecosystem purls", () => {
    const sbom = makeSbom([
      { type: "library", purl: "pkg:pypi/requests@2.28.0" },
    ]);
    const deps = parseCycloneDxSbom(sbom, "npm");
    expect(deps).toHaveLength(0);
  });

  it("throws on invalid JSON", () => {
    expect(() => parseCycloneDxSbom("not-json", "npm")).toThrow("not valid JSON");
  });

  it("throws on non-CycloneDX format", () => {
    expect(() => parseCycloneDxSbom(JSON.stringify({ bomFormat: "SPDX" }), "npm")).toThrow("Unsupported SBOM format");
  });

  it("handles scoped npm packages", () => {
    const sbom = makeSbom([
      { type: "library", purl: "pkg:npm/%40types/node@18.0.0" },
    ]);
    const deps = parseCycloneDxSbom(sbom, "npm");
    expect(deps).toHaveLength(1);
  });

  it("returns empty array when no components present", () => {
    const sbom = makeSbom([]);
    const deps = parseCycloneDxSbom(sbom, "npm");
    expect(deps).toHaveLength(0);
  });
});

describe("parseLockfile", () => {
  it("parses package-lock.json v2 packages section", () => {
    const lock = JSON.stringify({
      name: "my-app",
      lockfileVersion: 2,
      packages: {
        "": { name: "my-app", version: "1.0.0" },
        "node_modules/lodash": {
          version: "4.17.21",
          resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
          integrity: "sha512-v2kDE...",
        },
      },
    });
    const deps = parseLockfile(lock, "npm");
    expect(deps.some((d) => d.packageName === "lodash" && d.version === "4.17.21")).toBe(true);
    const lodash = deps.find((d) => d.packageName === "lodash")!;
    expect(lodash.resolvedUrl).toContain("registry.npmjs.org");
    expect(lodash.sbomHash).toBe("sha512-v2kDE...");
  });

  it("returns empty for pypi ecosystem", () => {
    const lock = JSON.stringify({ packages: {} });
    expect(parseLockfile(lock, "pypi")).toHaveLength(0);
  });
});

describe("verifySbomProvenance — npm", () => {
  it("passes when registry hash matches SBOM hash", async () => {
    const integrity = "sha512-AAABBBCCC";
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => npmMeta("lodash", "4.17.21", { integrity }),
    } as Response);

    const sbom = makeSbom([
      {
        type: "library",
        purl: "pkg:npm/lodash@4.17.21",
        hashes: [{ alg: "SHA-256", content: integrity }],
      },
    ]);

    const result = await verifySbomProvenance({ sbomText: sbom, packageFormat: "npm" }, mockFetch);
    expect(result.isValid).toBe(true);
    expect(result.riskLevel).toBe("none");
    expect(result.checks[0]!.passed).toBe(true);
  });

  it("detects registry-mismatch (HIGH) when SBOM hash differs from registry", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => npmMeta("evil-package", "1.0.0", { integrity: "sha512-REGISTRY_HASH" }),
    } as Response);

    const sbom = makeSbom([
      {
        type: "library",
        purl: "pkg:npm/evil-package@1.0.0",
        hashes: [{ alg: "SHA-256", content: "sha512-TAMPERED_HASH" }],
      },
    ]);

    const result = await verifySbomProvenance({ sbomText: sbom, packageFormat: "npm" }, mockFetch);
    expect(result.isValid).toBe(false);
    expect(result.checks[0]!.checkType).toBe("registry-mismatch");
    expect(result.checks[0]!.severity).toBe("high");
    expect(result.riskLevel).toBe("high");
  });

  it("detects yanked-version (HIGH) for unpublished package version", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        name: "old-package",
        versions: {},   // no version entry → yanked/unpublished
        time: {},
      }),
    } as Response);

    const sbom = makeSbom([
      { type: "library", purl: "pkg:npm/old-package@0.0.1" },
    ]);

    const result = await verifySbomProvenance({ sbomText: sbom, packageFormat: "npm" }, mockFetch);
    expect(result.isValid).toBe(false);
    expect(result.checks[0]!.checkType).toBe("yanked-version");
    expect(result.checks[0]!.severity).toBe("high");
  });

  it("detects yanked-version when deprecated with security keyword", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => npmMeta("bad-pkg", "2.0.0", { deprecated: "yanked due to security vulnerability" }),
    } as Response);

    const sbom = makeSbom([
      { type: "library", purl: "pkg:npm/bad-pkg@2.0.0" },
    ]);

    const result = await verifySbomProvenance({ sbomText: sbom, packageFormat: "npm" }, mockFetch);
    expect(result.isValid).toBe(false);
    expect(result.checks[0]!.checkType).toBe("yanked-version");
    expect(result.checks[0]!.severity).toBe("high");
  });

  it("detects unresolved-dependency (MEDIUM) for non-canonical resolved URL", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => npmMeta("internal-pkg", "1.0.0"),
    } as Response);

    const lock = JSON.stringify({
      lockfileVersion: 2,
      packages: {
        "node_modules/internal-pkg": {
          version: "1.0.0",
          resolved: "https://private.registry.internal/internal-pkg/-/internal-pkg-1.0.0.tgz",
          integrity: "sha512-localHash",
        },
      },
    });

    const sbom = makeSbom([
      { type: "library", purl: "pkg:npm/internal-pkg@1.0.0" },
    ]);

    const result = await verifySbomProvenance(
      { sbomText: sbom, packageFormat: "npm", lockfileContent: lock },
      mockFetch
    );
    expect(result.isValid).toBe(false);
    const check = result.checks.find((c) => c.packageName === "internal-pkg");
    expect(check!.checkType).toBe("unresolved-dependency");
    expect(check!.severity).toBe("medium");
  });

  it("handles offline registry gracefully (unresolved-dependency)", async () => {
    const mockFetch = vi.fn().mockRejectedValue(new Error("fetch failed: ECONNREFUSED"));

    const sbom = makeSbom([
      { type: "library", purl: "pkg:npm/some-package@1.2.3" },
    ]);

    const result = await verifySbomProvenance({ sbomText: sbom, packageFormat: "npm" }, mockFetch);
    expect(result.isValid).toBe(false);
    expect(result.checks[0]!.checkType).toBe("unresolved-dependency");
    expect(result.checks[0]!.severity).toBe("medium");
  });

  it("returns empty checks for SBOM with no components", async () => {
    const mockFetch = vi.fn();
    const sbom = makeSbom([]);
    const result = await verifySbomProvenance({ sbomText: sbom, packageFormat: "npm" }, mockFetch);
    expect(result.isValid).toBe(true);
    expect(result.checks).toHaveLength(0);
    expect(result.riskLevel).toBe("none");
    expect(mockFetch).not.toHaveBeenCalled();
  });
});

describe("verifySbomProvenance — pypi", () => {
  it("passes when PyPI sha256 matches SBOM hash", async () => {
    const sha256 = "deadbeefcafe1234";
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => pypiMeta("requests", "2.28.0", { sha256 }),
    } as Response);

    const sbom = makeSbom([
      {
        type: "library",
        purl: "pkg:pypi/requests@2.28.0",
        hashes: [{ alg: "SHA-256", content: sha256 }],
      },
    ]);

    const result = await verifySbomProvenance({ sbomText: sbom, packageFormat: "pypi" }, mockFetch);
    expect(result.isValid).toBe(true);
    expect(result.checks[0]!.passed).toBe(true);
  });

  it("detects yanked PyPI package version", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => pypiMeta("dangerous-lib", "0.1.0", {
        yanked: true,
        yanked_reason: "Contains malicious code",
      }),
    } as Response);

    const sbom = makeSbom([
      { type: "library", purl: "pkg:pypi/dangerous-lib@0.1.0" },
    ]);

    const result = await verifySbomProvenance({ sbomText: sbom, packageFormat: "pypi" }, mockFetch);
    expect(result.isValid).toBe(false);
    expect(result.checks[0]!.checkType).toBe("yanked-version");
    expect(result.checks[0]!.severity).toBe("high");
    expect(result.checks[0]!.detail).toContain("yanked");
  });

  it("detects registry-mismatch for PyPI tampered hash", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => pypiMeta("tampered-lib", "1.0.0", { sha256: "realregistryhash" }),
    } as Response);

    const sbom = makeSbom([
      {
        type: "library",
        purl: "pkg:pypi/tampered-lib@1.0.0",
        hashes: [{ alg: "SHA-256", content: "modifiedhash" }],
      },
    ]);

    const result = await verifySbomProvenance({ sbomText: sbom, packageFormat: "pypi" }, mockFetch);
    expect(result.isValid).toBe(false);
    expect(result.checks[0]!.checkType).toBe("registry-mismatch");
    expect(result.checks[0]!.severity).toBe("high");
  });

  it("handles offline PyPI registry gracefully", async () => {
    const mockFetch = vi.fn().mockRejectedValue(new Error("Network error"));

    const sbom = makeSbom([
      { type: "library", purl: "pkg:pypi/offline-package@3.0.0" },
    ]);

    const result = await verifySbomProvenance({ sbomText: sbom, packageFormat: "pypi" }, mockFetch);
    expect(result.isValid).toBe(false);
    expect(result.checks[0]!.checkType).toBe("unresolved-dependency");
    expect(result.riskLevel).toBe("medium");
  });
});

describe("POST /sbom/verify-provenance endpoint", () => {
  it("returns 400 for missing sbomText", async () => {
    const res = await app.request("/sbom/verify-provenance", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ packageFormat: "npm" }),
    });
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toContain("sbomText");
  });

  it("returns 400 for invalid packageFormat", async () => {
    const sbom = makeSbom([]);
    const res = await app.request("/sbom/verify-provenance", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sbomText: sbom, packageFormat: "rubygems" }),
    });
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toContain("packageFormat");
  });

  it("returns 400 for non-CycloneDX SBOM", async () => {
    const res = await app.request("/sbom/verify-provenance", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sbomText: JSON.stringify({ bomFormat: "SPDX" }),
        packageFormat: "npm",
      }),
    });
    expect(res.status).toBe(400);
  });

  it("returns 400 for invalid JSON body", async () => {
    const res = await app.request("/sbom/verify-provenance", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "not json at all",
    });
    expect(res.status).toBe(400);
  });

  it("returns valid provenance result for an SBOM with no components", async () => {
    const sbom = makeSbom([]);
    const res = await app.request("/sbom/verify-provenance", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sbomText: sbom, packageFormat: "npm" }),
    });
    expect(res.status).toBe(200);
    const body = await res.json() as {
      isValid: boolean;
      checks: unknown[];
      riskLevel: string;
      recommendations: string[];
    };
    expect(typeof body.isValid).toBe("boolean");
    expect(Array.isArray(body.checks)).toBe(true);
    expect(typeof body.riskLevel).toBe("string");
    expect(Array.isArray(body.recommendations)).toBe(true);
  });

  it("returns 400 for lockfileContent that is not a string", async () => {
    const sbom = makeSbom([]);
    const res = await app.request("/sbom/verify-provenance", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sbomText: sbom, packageFormat: "npm", lockfileContent: 42 }),
    });
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toContain("lockfileContent");
  });
});

// ---------------------------------------------------------------------------
// /packages/:ecosystem/:name/versions/:version/vulnerabilities/enriched
// EPSS + CISA KEV enrichment endpoint
// ---------------------------------------------------------------------------

describe("vulnerabilities/enriched endpoint", () => {
  it("returns 200 with structured enrichment for a package that has advisories (sqlite3)", async () => {
    const res = await app.request("/packages/npm/sqlite3/versions/5.1.6/vulnerabilities/enriched");
    expect(res.status).toBe(200);
    const body = await res.json() as {
      ecosystem: string;
      packageName: string;
      version: string;
      findings: unknown[];
      maxEpssPercentile: number;
      maxCvssV3Score: number;
      cisaKevMatches: string[];
      exploitMaturityStats: { proofOfConcept: number; activeExploitation: number; widespread: number };
      riskBoost: { baseScore: number; epssBoost: number; cisaKevBoost: number; finalScore: number };
      recommendations: string[];
      enrichedAt: string;
    };
    expect(body.ecosystem).toBe("npm");
    expect(body.packageName).toBe("sqlite3");
    expect(body.version).toBe("5.1.6");
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBeGreaterThan(0);
    expect(Array.isArray(body.cisaKevMatches)).toBe(true);
    expect(typeof body.maxEpssPercentile).toBe("number");
    expect(typeof body.maxCvssV3Score).toBe("number");
    expect(typeof body.enrichedAt).toBe("string");
  });

  it("returns required riskBoost shape", async () => {
    const res = await app.request("/packages/npm/sqlite3/versions/5.1.6/vulnerabilities/enriched");
    expect(res.status).toBe(200);
    const body = await res.json() as {
      riskBoost: { baseScore: number; epssBoost: number; cisaKevBoost: number; finalScore: number };
    };
    expect(typeof body.riskBoost.baseScore).toBe("number");
    expect(typeof body.riskBoost.epssBoost).toBe("number");
    expect(typeof body.riskBoost.cisaKevBoost).toBe("number");
    expect(typeof body.riskBoost.finalScore).toBe("number");
    // finalScore must be within [0, 100]
    expect(body.riskBoost.finalScore).toBeGreaterThanOrEqual(0);
    expect(body.riskBoost.finalScore).toBeLessThanOrEqual(100);
    // finalScore = baseScore + epssBoost + cisaKevBoost (capped)
    expect(body.riskBoost.finalScore).toBeLessThanOrEqual(
      body.riskBoost.baseScore + body.riskBoost.epssBoost + body.riskBoost.cisaKevBoost
    );
  });

  it("findings items have required fields", async () => {
    const res = await app.request("/packages/npm/sqlite3/versions/5.1.6/vulnerabilities/enriched");
    expect(res.status).toBe(200);
    const body = await res.json() as {
      findings: Array<{ cvId: string; title: string; severity: string; recommendation: string }>;
    };
    for (const f of body.findings) {
      expect(typeof f.cvId).toBe("string");
      expect(typeof f.title).toBe("string");
      expect(typeof f.severity).toBe("string");
      expect(typeof f.recommendation).toBe("string");
    }
  });

  it("exploitMaturityStats has correct numeric shape", async () => {
    const res = await app.request("/packages/npm/sqlite3/versions/5.1.6/vulnerabilities/enriched");
    expect(res.status).toBe(200);
    const body = await res.json() as {
      exploitMaturityStats: { proofOfConcept: number; activeExploitation: number; widespread: number };
    };
    expect(typeof body.exploitMaturityStats.proofOfConcept).toBe("number");
    expect(typeof body.exploitMaturityStats.activeExploitation).toBe("number");
    expect(typeof body.exploitMaturityStats.widespread).toBe("number");
  });

  it("returns empty findings for a package with no advisories", async () => {
    const res = await app.request("/packages/npm/unknown-no-advisory-pkg/versions/1.0.0/vulnerabilities/enriched");
    expect(res.status).toBe(200);
    const body = await res.json() as {
      findings: unknown[];
      maxCvssV3Score: number;
      maxEpssPercentile: number;
      cisaKevMatches: string[];
      riskBoost: { baseScore: number; finalScore: number };
      recommendations: string[];
    };
    expect(body.findings).toHaveLength(0);
    expect(body.maxCvssV3Score).toBe(0);
    expect(body.maxEpssPercentile).toBe(0);
    expect(body.cisaKevMatches).toHaveLength(0);
    expect(body.riskBoost.baseScore).toBe(0);
    expect(body.riskBoost.finalScore).toBe(0);
    expect(body.recommendations.length).toBeGreaterThan(0);
  });

  it("recommendations is a non-empty array of strings", async () => {
    const res = await app.request("/packages/npm/bcrypt/versions/5.1.1/vulnerabilities/enriched");
    expect(res.status).toBe(200);
    const body = await res.json() as { recommendations: unknown[] };
    expect(Array.isArray(body.recommendations)).toBe(true);
    expect(body.recommendations.length).toBeGreaterThan(0);
    for (const r of body.recommendations) {
      expect(typeof r).toBe("string");
    }
  });

  it("baseScore is derived from maxCvssV3Score (cvss/10 * 100, rounded)", async () => {
    const res = await app.request("/packages/npm/sqlite3/versions/5.1.6/vulnerabilities/enriched");
    expect(res.status).toBe(200);
    const body = await res.json() as {
      maxCvssV3Score: number;
      riskBoost: { baseScore: number };
    };
    const expectedBase = Math.round((body.maxCvssV3Score / 10) * 100);
    expect(body.riskBoost.baseScore).toBe(expectedBase);
  });
});

// ---------------------------------------------------------------------------
// EpssCache — unit tests for TTL, in-memory layer, and setMany/getMany
// ---------------------------------------------------------------------------

describe("EpssCache", () => {
  // Import directly from the module (no Supabase — in-memory only)
  it("returns null for unknown CVE", async () => {
    const { EpssCache } = await import("./lib/epss-cache");
    const cache = new EpssCache();
    const result = await cache.get("npm", "CVE-9999-00001");
    expect(result).toBeNull();
  });

  it("stores and retrieves an entry within TTL", async () => {
    const { EpssCache } = await import("./lib/epss-cache");
    const cache = new EpssCache();
    const entry = {
      ecosystem: "npm",
      cveId: "CVE-2025-0001",
      score: 0.12,
      percentile: 0.75,
      fetchedAt: new Date().toISOString()
    };
    await cache.setMany([entry]);
    const result = await cache.get("npm", "CVE-2025-0001");
    expect(result).not.toBeNull();
    expect(result!.score).toBe(0.12);
    expect(result!.percentile).toBe(0.75);
  });

  it("getMany returns all cached entries", async () => {
    const { EpssCache } = await import("./lib/epss-cache");
    const cache = new EpssCache();
    const now = new Date().toISOString();
    await cache.setMany([
      { ecosystem: "npm", cveId: "CVE-2025-0010", score: 0.05, percentile: 0.3, fetchedAt: now },
      { ecosystem: "npm", cveId: "CVE-2025-0011", score: 0.20, percentile: 0.85, fetchedAt: now }
    ]);
    const result = await cache.getMany("npm", ["CVE-2025-0010", "CVE-2025-0011", "CVE-2025-MISSING"]);
    expect(result.size).toBe(2);
    expect(result.has("CVE-2025-0010")).toBe(true);
    expect(result.has("CVE-2025-0011")).toBe(true);
    expect(result.has("CVE-2025-MISSING")).toBe(false);
  });

  it("evicts stale entries (past 7-day TTL)", async () => {
    const { EpssCache } = await import("./lib/epss-cache");
    const cache = new EpssCache();
    // fetchedAt = 8 days ago → stale
    const staleDate = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString();
    await cache.setMany([
      { ecosystem: "npm", cveId: "CVE-2020-STALE", score: 0.9, percentile: 0.99, fetchedAt: staleDate }
    ]);
    // Bypass setMany freshness to force stale entry into map directly
    // (setMany writes to the map; stale detection happens on get/getMany)
    const result = await cache.get("npm", "CVE-2020-STALE");
    expect(result).toBeNull();
  });

  it("is case-insensitive on CVE ID", async () => {
    const { EpssCache } = await import("./lib/epss-cache");
    const cache = new EpssCache();
    const now = new Date().toISOString();
    await cache.setMany([{ ecosystem: "npm", cveId: "cve-2025-9999", score: 0.3, percentile: 0.6, fetchedAt: now }]);
    const result = await cache.get("npm", "CVE-2025-9999");
    expect(result).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// AdvisoryService.fetchEpssScores — mocked FIRST EPSS API
// ---------------------------------------------------------------------------

describe("AdvisoryService.fetchEpssScores", () => {
  it("returns empty map when no CVE IDs given", async () => {
    const { AdvisoryService } = await import("./lib/advisory-service");
    const { EpssCache } = await import("./lib/epss-cache");
    const svc = new AdvisoryService({
      supabaseUrl: "https://fake.supabase.co",
      supabaseServiceRoleKey: "fake-key"
    });
    const cache = new EpssCache();
    const result = await svc.fetchEpssScores("npm", [], cache);
    expect(result.size).toBe(0);
  });

  it("returns scores from cache without hitting the network", async () => {
    const { AdvisoryService } = await import("./lib/advisory-service");
    const { EpssCache } = await import("./lib/epss-cache");
    const svc = new AdvisoryService({
      supabaseUrl: "https://fake.supabase.co",
      supabaseServiceRoleKey: "fake-key"
    });
    const cache = new EpssCache();
    const now = new Date().toISOString();
    await cache.setMany([
      { ecosystem: "npm", cveId: "CVE-2025-1111", score: 0.15, percentile: 0.72, fetchedAt: now }
    ]);

    // No global fetch mock set up — if live fetch were attempted it would fail in CI
    const result = await svc.fetchEpssScores("npm", ["CVE-2025-1111"], cache);
    expect(result.has("CVE-2025-1111")).toBe(true);
    expect(result.get("CVE-2025-1111")!.percentile).toBe(0.72);
  });

  it("fetches from FIRST EPSS API for cache-miss CVEs and caches result", async () => {
    const { AdvisoryService } = await import("./lib/advisory-service");
    const { EpssCache } = await import("./lib/epss-cache");

    // Monkey-patch global fetch for this test
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        status: "OK",
        status_code: 200,
        version: "1.0",
        access: "public",
        total: 1,
        offset: 0,
        limit: 100,
        data: [{ cve: "CVE-2025-9876", epss: "0.25", percentile: "0.88" }]
      })
    } as Response);

    try {
      const svc = new AdvisoryService({
        supabaseUrl: "https://fake.supabase.co",
        supabaseServiceRoleKey: "fake-key"
      });
      const cache = new EpssCache(); // no Supabase backing

      const result = await svc.fetchEpssScores("npm", ["CVE-2025-9876"], cache);
      expect(result.has("CVE-2025-9876")).toBe(true);
      expect(result.get("CVE-2025-9876")!.score).toBeCloseTo(0.25);
      expect(result.get("CVE-2025-9876")!.percentile).toBeCloseTo(0.88);

      // Result should now be in the in-memory cache
      const cached = await cache.get("npm", "CVE-2025-9876");
      expect(cached).not.toBeNull();
      expect(cached!.percentile).toBeCloseTo(0.88);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("handles EPSS API returning no data gracefully", async () => {
    const { AdvisoryService } = await import("./lib/advisory-service");
    const { EpssCache } = await import("./lib/epss-cache");

    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ status: "OK", status_code: 200, version: "1.0", access: "public", total: 0, offset: 0, limit: 100, data: [] })
    } as Response);

    try {
      const svc = new AdvisoryService({
        supabaseUrl: "https://fake.supabase.co",
        supabaseServiceRoleKey: "fake-key"
      });
      const result = await svc.fetchEpssScores("npm", ["CVE-2099-NOTFOUND"], new EpssCache());
      expect(result.size).toBe(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("handles EPSS API network failure gracefully", async () => {
    const { AdvisoryService } = await import("./lib/advisory-service");
    const { EpssCache } = await import("./lib/epss-cache");

    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockRejectedValue(new Error("ECONNREFUSED"));

    try {
      const svc = new AdvisoryService({
        supabaseUrl: "https://fake.supabase.co",
        supabaseServiceRoleKey: "fake-key"
      });
      // Should not throw — returns empty map
      const result = await svc.fetchEpssScores("npm", ["CVE-2025-FAIL"], new EpssCache());
      expect(result.size).toBe(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

// ---------------------------------------------------------------------------
// AdvisoryService.enrichCvesWithEpss — CISA KEV correlation
// ---------------------------------------------------------------------------

describe("AdvisoryService.enrichCvesWithEpss — CISA KEV correlation", () => {
  it("includes cisaKevDate in finding when advisory has cisaKevDate set", async () => {
    const { AdvisoryService } = await import("./lib/advisory-service");
    const { EpssCache } = await import("./lib/epss-cache");

    // Stub fetchEpssFromApi so no network calls are made
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        status: "OK", status_code: 200, version: "1.0", access: "public",
        total: 1, offset: 0, limit: 100,
        data: [{ cve: "CVE-2025-1234", epss: "0.7", percentile: "0.92" }]
      })
    } as Response);

    // Build a service that fetches from our mock advisory data
    // For this test we override getPackageAdvisories to inject a KEV-tagged advisory
    const svc = new AdvisoryService({
      supabaseUrl: "https://fake.supabase.co",
      supabaseServiceRoleKey: "fake-key"
    });

    // Inject a KEV advisory via prototype override
    const origGet = svc.getPackageAdvisories.bind(svc);
    svc.getPackageAdvisories = async () => [
      {
        id: "adv_kev_test",
        source: "nvd",
        sourceId: "CVE-2025-1234",
        title: "Test KEV Advisory",
        severity: "critical",
        cvssScore: 9.8,
        cweIds: [],
        references: [],
        affectedPackages: [{ ecosystem: "npm", packageName: "test-pkg", vulnerableRange: "<1.0.0" }],
        cisaKevDate: "2025-06-01"
      } as unknown as Awaited<ReturnType<typeof origGet>>[0]
    ];

    try {
      const result = await svc.enrichCvesWithEpss("npm", "test-pkg", "0.9.0", new EpssCache());
      expect(result.cisaKevMatches).toContain("CVE-2025-1234");
      expect(result.riskBoost.cisaKevBoost).toBe(30);
      expect(result.riskBoost.finalScore).toBeGreaterThan(result.riskBoost.baseScore);
      const finding = result.findings.find((f) => f.cvId === "CVE-2025-1234");
      expect(finding?.cisaKevDate).toBe("2025-06-01");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("riskBoost finalScore is capped at 100", async () => {
    const { AdvisoryService } = await import("./lib/advisory-service");
    const { EpssCache } = await import("./lib/epss-cache");

    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true, status: 200,
      json: async () => ({ status: "OK", status_code: 200, version: "1.0", access: "public", total: 1, offset: 0, limit: 100,
        data: [{ cve: "CVE-2025-MAXRISK", epss: "1.0", percentile: "1.0" }] })
    } as Response);

    const svc = new AdvisoryService({
      supabaseUrl: "https://fake.supabase.co",
      supabaseServiceRoleKey: "fake-key"
    });
    svc.getPackageAdvisories = async () => [
      {
        id: "adv_max",
        source: "nvd",
        sourceId: "CVE-2025-MAXRISK",
        title: "Maximum Risk Advisory",
        severity: "critical",
        cvssScore: 10.0,
        cweIds: [],
        references: [],
        affectedPackages: [],
        cisaKevDate: "2025-01-01"
      } as unknown as Awaited<ReturnType<typeof svc.getPackageAdvisories>>[0]
    ];

    try {
      const result = await svc.enrichCvesWithEpss("npm", "max-risk-pkg", "1.0.0", new EpssCache());
      expect(result.riskBoost.finalScore).toBeLessThanOrEqual(100);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("returns empty findings and zero scores for a package with no advisories", async () => {
    const { AdvisoryService } = await import("./lib/advisory-service");
    const { EpssCache } = await import("./lib/epss-cache");

    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true, status: 200,
      json: async () => ({ status: "OK", status_code: 200, version: "1.0", access: "public", total: 0, offset: 0, limit: 100, data: [] })
    } as Response);

    const svc = new AdvisoryService({
      supabaseUrl: "https://fake.supabase.co",
      supabaseServiceRoleKey: "fake-key"
    });
    svc.getPackageAdvisories = async () => [];

    try {
      const result = await svc.enrichCvesWithEpss("npm", "empty-pkg", "1.0.0", new EpssCache());
      expect(result.findings).toHaveLength(0);
      expect(result.maxEpssPercentile).toBe(0);
      expect(result.maxCvssV3Score).toBe(0);
      expect(result.cisaKevMatches).toHaveLength(0);
      expect(result.riskBoost.finalScore).toBe(0);
      expect(result.recommendations.length).toBeGreaterThan(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

// ---------------------------------------------------------------------------
// Scan Resilience + Dead-Letter Queue tests
// ---------------------------------------------------------------------------

describe("FailedScanQueue repository methods (LocalRepository)", () => {
  it("upserts a failed scan entry and retrieves it by scanId", async () => {
    const freshApp = createApp();
    const repo = freshApp.request; // we access repository via app services indirectly

    // Use the internal services by creating a fresh instance
    const { createServices: _cs } = await import("./lib/repository");
    const { readApiEnv } = await import("./lib/env");
    const services = _cs(readApiEnv());
    const repository = services.repository;

    const entry = await repository.upsertFailedScan({
      scanId: "job_test001",
      jobId: "job_test001",
      orgId: "org_demo",
      ecosystem: "npm",
      packageName: "test-pkg",
      version: "1.0.0",
      errorReason: "timeout: job remained queued for > 60s",
      failureCount: 1,
      lastAttemptAt: new Date().toISOString(),
      nextRetryAt: new Date(Date.now() + 1000).toISOString(),
      status: "pending",
      metadata: {}
    });

    expect(entry.scanId).toBe("job_test001");
    expect(entry.status).toBe("pending");
    expect(entry.failureCount).toBe(1);
    expect(entry.id).toBeTruthy();

    const fetched = await repository.getFailedScan("job_test001");
    expect(fetched).not.toBeNull();
    expect(fetched!.packageName).toBe("test-pkg");
  });

  it("upsert is idempotent: second call with same scanId updates the row", async () => {
    const { createServices: _cs } = await import("./lib/repository");
    const { readApiEnv } = await import("./lib/env");
    const services = _cs(readApiEnv());
    const repository = services.repository;

    const base = {
      scanId: "job_test002",
      jobId: "job_test002",
      orgId: "org_demo",
      ecosystem: "npm",
      packageName: "pkg-upsert",
      version: "2.0.0",
      errorReason: "first failure",
      failureCount: 1,
      lastAttemptAt: new Date().toISOString(),
      nextRetryAt: new Date(Date.now() + 1000).toISOString(),
      status: "pending" as const,
      metadata: {}
    };
    const first = await repository.upsertFailedScan(base);
    const second = await repository.upsertFailedScan({
      ...base,
      failureCount: 2,
      errorReason: "second failure",
      status: "retrying"
    });

    // Same id, updated fields
    expect(second.id).toBe(first.id);
    expect(second.failureCount).toBe(2);
    expect(second.status).toBe("retrying");
  });

  it("listPendingRetries only returns entries whose nextRetryAt is due", async () => {
    const { createServices: _cs } = await import("./lib/repository");
    const { readApiEnv } = await import("./lib/env");
    const services = _cs(readApiEnv());
    const repository = services.repository;

    const pastTime = new Date(Date.now() - 5000).toISOString();
    const futureTime = new Date(Date.now() + 300_000).toISOString();

    await repository.upsertFailedScan({
      scanId: "job_due001",
      jobId: "job_due001",
      orgId: "org_demo",
      ecosystem: "npm",
      packageName: "due-pkg",
      version: "1.0.0",
      errorReason: "timeout",
      failureCount: 1,
      lastAttemptAt: new Date().toISOString(),
      nextRetryAt: pastTime,
      status: "pending",
      metadata: {}
    });

    await repository.upsertFailedScan({
      scanId: "job_notdue001",
      jobId: "job_notdue001",
      orgId: "org_demo",
      ecosystem: "npm",
      packageName: "future-pkg",
      version: "1.0.0",
      errorReason: "timeout",
      failureCount: 1,
      lastAttemptAt: new Date().toISOString(),
      nextRetryAt: futureTime,
      status: "pending",
      metadata: {}
    });

    const pending = await repository.listPendingRetries();
    const dueIds = pending.map((e) => e.scanId);
    expect(dueIds).toContain("job_due001");
    expect(dueIds).not.toContain("job_notdue001");
  });

  it("markFailedScanAbandoned transitions status to abandoned", async () => {
    const { createServices: _cs } = await import("./lib/repository");
    const { readApiEnv } = await import("./lib/env");
    const services = _cs(readApiEnv());
    const repository = services.repository;

    await repository.upsertFailedScan({
      scanId: "job_abandon001",
      jobId: "job_abandon001",
      orgId: "org_demo",
      ecosystem: "npm",
      packageName: "abandon-pkg",
      version: "3.0.0",
      errorReason: "all retries exhausted",
      failureCount: 5,
      lastAttemptAt: new Date().toISOString(),
      nextRetryAt: new Date(Date.now() + 1000).toISOString(),
      status: "retrying",
      metadata: {}
    });

    await repository.markFailedScanAbandoned("job_abandon001");
    const entry = await repository.getFailedScan("job_abandon001");
    expect(entry?.status).toBe("abandoned");
  });

  it("resolveFailedScan transitions status to resolved", async () => {
    const { createServices: _cs } = await import("./lib/repository");
    const { readApiEnv } = await import("./lib/env");
    const services = _cs(readApiEnv());
    const repository = services.repository;

    await repository.upsertFailedScan({
      scanId: "job_resolve001",
      jobId: "job_resolve001",
      orgId: "org_demo",
      ecosystem: "npm",
      packageName: "resolved-pkg",
      version: "1.0.0",
      errorReason: "timeout",
      failureCount: 2,
      lastAttemptAt: new Date().toISOString(),
      nextRetryAt: new Date(Date.now() + 1000).toISOString(),
      status: "retrying",
      metadata: {}
    });

    await repository.resolveFailedScan("job_resolve001");
    const entry = await repository.getFailedScan("job_resolve001");
    expect(entry?.status).toBe("resolved");
  });

  it("appendScanAuditLog and listScanAuditLog round-trip", async () => {
    const { createServices: _cs } = await import("./lib/repository");
    const { readApiEnv } = await import("./lib/env");
    const services = _cs(readApiEnv());
    const repository = services.repository;

    const scanId = "job_audit001";

    await repository.appendScanAuditLog({
      scanId,
      orgId: "org_demo",
      eventType: "scan_queued",
      retryAttempt: 0,
      details: { packageName: "audit-pkg", version: "1.0.0" }
    });
    await repository.appendScanAuditLog({
      scanId,
      orgId: "org_demo",
      eventType: "scan_timeout",
      retryAttempt: 1,
      details: { reason: "queued > 60s" }
    });
    await repository.appendScanAuditLog({
      scanId,
      orgId: "org_demo",
      eventType: "retry_attempted",
      retryAttempt: 1,
      details: {}
    });

    const log = await repository.listScanAuditLog(scanId);
    expect(log.length).toBe(3);
    expect(log[0]!.eventType).toBe("scan_queued");
    expect(log[1]!.eventType).toBe("scan_timeout");
    expect(log[2]!.eventType).toBe("retry_attempted");
    expect(log.every((e) => e.scanId === scanId)).toBe(true);
  });
});

describe("scan timeout watcher — API-level integration", () => {
  it("scan for unknown package returns status queued (202)", async () => {
    const response = await app.request("/scans/packages", {
      method: "POST",
      headers,
      body: JSON.stringify({
        ecosystem: "npm",
        packageName: "unknown-package-xyz-timeout-test",
        version: "0.0.1"
      })
    });
    expect(response.status).toBe(202);
    const body = await response.json();
    expect(body.status).toBe("queued");
    expect(body.id).toBeTruthy();
  });

  it("scan for known package returns status complete (200) without entering queue", async () => {
    const response = await app.request("/scans/packages", {
      method: "POST",
      headers,
      body: JSON.stringify({
        ecosystem: "npm",
        packageName: "bcrypt",
        version: "5.1.1"
      })
    });
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.status).toBe("complete");
  });
});

describe("retry-handler — processRetry unit tests", () => {
  it("computeNextRetryAt uses exponential backoff delays", async () => {
    const { computeNextRetryAt } = await import("../../worker/src/retry-handler");
    const delays = [1, 2, 3, 4, 5].map((attempt) => {
      const before = Date.now();
      const ts = computeNextRetryAt(attempt);
      const after = Date.now();
      return new Date(ts).getTime() - before;
    });
    // delays should be approximately [1000, 4000, 16000, 60000, 300000]
    expect(delays[0]).toBeGreaterThanOrEqual(900);
    expect(delays[1]).toBeGreaterThanOrEqual(3900);
    expect(delays[2]).toBeGreaterThanOrEqual(15_900);
    expect(delays[3]).toBeGreaterThanOrEqual(59_900);
    expect(delays[4]).toBeGreaterThanOrEqual(299_900);
    // Each delay should be strictly longer than the previous
    for (let i = 1; i < delays.length; i++) {
      expect(delays[i]).toBeGreaterThan(delays[i - 1]!);
    }
  });

  it("processRetry: successful runScan resolves DLQ entry and writes audit log", async () => {
    const { processRetry } = await import("../../worker/src/retry-handler");
    const { createServices: _cs } = await import("./lib/repository");
    const { readApiEnv } = await import("./lib/env");
    const services = _cs(readApiEnv());
    const repository = services.repository;

    const scanId = "job_retry_success001";
    await repository.upsertFailedScan({
      scanId, jobId: scanId, orgId: "org_demo",
      ecosystem: "npm", packageName: "retry-success-pkg", version: "1.0.0",
      errorReason: "timeout", failureCount: 1,
      lastAttemptAt: new Date().toISOString(),
      nextRetryAt: new Date(Date.now() - 1000).toISOString(),
      status: "pending", metadata: {}
    });

    const entry = await repository.getFailedScan(scanId);
    const runScan = vi.fn().mockResolvedValue(true);
    const result = await processRetry(entry!, repository, runScan);

    expect(result).toBe(true);
    expect(runScan).toHaveBeenCalledOnce();

    const resolved = await repository.getFailedScan(scanId);
    expect(resolved?.status).toBe("resolved");

    const log = await repository.listScanAuditLog(scanId);
    const eventTypes = log.map((e) => e.eventType);
    expect(eventTypes).toContain("retry_attempted");
    expect(eventTypes).toContain("retry_succeeded");
  });

  it("processRetry: failed runScan increments failure count and schedules next retry", async () => {
    const { processRetry } = await import("../../worker/src/retry-handler");
    const { createServices: _cs } = await import("./lib/repository");
    const { readApiEnv } = await import("./lib/env");
    const services = _cs(readApiEnv());
    const repository = services.repository;

    const scanId = "job_retry_fail001";
    await repository.upsertFailedScan({
      scanId, jobId: scanId, orgId: "org_demo",
      ecosystem: "npm", packageName: "retry-fail-pkg", version: "1.0.0",
      errorReason: "timeout", failureCount: 1,
      lastAttemptAt: new Date().toISOString(),
      nextRetryAt: new Date(Date.now() - 1000).toISOString(),
      status: "pending", metadata: {}
    });

    const entry = await repository.getFailedScan(scanId);
    const runScan = vi.fn().mockResolvedValue(false);
    const result = await processRetry(entry!, repository, runScan, 5);

    expect(result).toBe(false);
    const updated = await repository.getFailedScan(scanId);
    expect(updated?.failureCount).toBe(2);
    expect(updated?.status).toBe("retrying");

    const log = await repository.listScanAuditLog(scanId);
    expect(log.some((e) => e.eventType === "scan_failed")).toBe(true);
  });

  it("processRetry: abandons scan after maxRetries failures and emits audit events", async () => {
    const { processRetry } = await import("../../worker/src/retry-handler");
    const { createServices: _cs } = await import("./lib/repository");
    const { readApiEnv } = await import("./lib/env");
    const services = _cs(readApiEnv());
    const repository = services.repository;

    const scanId = "job_retry_abandon001";
    await repository.upsertFailedScan({
      scanId, jobId: scanId, orgId: "org_demo",
      ecosystem: "npm", packageName: "abandon-retry-pkg", version: "1.0.0",
      errorReason: "worker crashed", failureCount: 4,
      lastAttemptAt: new Date().toISOString(),
      nextRetryAt: new Date(Date.now() - 1000).toISOString(),
      status: "retrying", metadata: {}
    });

    const entry = await repository.getFailedScan(scanId);
    const runScan = vi.fn().mockResolvedValue(false);
    const result = await processRetry(entry!, repository, runScan, 5);

    expect(result).toBe(false);
    const abandoned = await repository.getFailedScan(scanId);
    expect(abandoned?.status).toBe("abandoned");
    expect(abandoned?.failureCount).toBe(5);

    const log = await repository.listScanAuditLog(scanId);
    const eventTypes = log.map((e) => e.eventType);
    expect(eventTypes).toContain("scan_abandoned");
    expect(eventTypes).toContain("alert_sent");
  });

  it("processRetry: runScan throwing an error is treated as failure", async () => {
    const { processRetry } = await import("../../worker/src/retry-handler");
    const { createServices: _cs } = await import("./lib/repository");
    const { readApiEnv } = await import("./lib/env");
    const services = _cs(readApiEnv());
    const repository = services.repository;

    const scanId = "job_retry_throws001";
    await repository.upsertFailedScan({
      scanId, jobId: scanId, orgId: "org_demo",
      ecosystem: "npm", packageName: "throwing-pkg", version: "1.0.0",
      errorReason: "timeout", failureCount: 1,
      lastAttemptAt: new Date().toISOString(),
      nextRetryAt: new Date(Date.now() - 1000).toISOString(),
      status: "pending", metadata: {}
    });

    const entry = await repository.getFailedScan(scanId);
    const runScan = vi.fn().mockRejectedValue(new Error("worker process died"));
    const result = await processRetry(entry!, repository, runScan, 5);

    expect(result).toBe(false);
    const updated = await repository.getFailedScan(scanId);
    expect(updated?.failureCount).toBe(2);
    expect(updated?.errorReason).toContain("worker process died");
  });

  it("startRetryProcessor polls and processes due entries", async () => {
    const { startRetryProcessor } = await import("../../worker/src/retry-handler");
    const { createServices: _cs } = await import("./lib/repository");
    const { readApiEnv } = await import("./lib/env");
    const services = _cs(readApiEnv());
    const repository = services.repository;

    const scanId = "job_processor001";
    await repository.upsertFailedScan({
      scanId, jobId: scanId, orgId: "org_demo",
      ecosystem: "npm", packageName: "processor-pkg", version: "1.0.0",
      errorReason: "timeout", failureCount: 1,
      lastAttemptAt: new Date().toISOString(),
      nextRetryAt: new Date(Date.now() - 100).toISOString(), // already due
      status: "pending", metadata: {}
    });

    const runScan = vi.fn().mockResolvedValue(true);
    const handle = startRetryProcessor({
      repository,
      runScan,
      pollIntervalMs: 50, // very short for tests
      maxRetries: 5
    });

    // Wait for at least one poll tick
    await new Promise((resolve) => setTimeout(resolve, 200));
    handle.stop();

    expect(runScan).toHaveBeenCalled();
    const resolved = await repository.getFailedScan(scanId);
    expect(resolved?.status).toBe("resolved");
  });

  it("startRetryProcessor stop() halts polling", async () => {
    const { startRetryProcessor } = await import("../../worker/src/retry-handler");
    const { createServices: _cs } = await import("./lib/repository");
    const { readApiEnv } = await import("./lib/env");
    const services = _cs(readApiEnv());
    const repository = services.repository;

    const runScan = vi.fn().mockResolvedValue(true);
    const handle = startRetryProcessor({ repository, runScan, pollIntervalMs: 50 });
    handle.stop();

    const callsBefore = runScan.mock.calls.length;
    await new Promise((resolve) => setTimeout(resolve, 200));
    const callsAfter = runScan.mock.calls.length;

    // No additional calls after stop
    expect(callsAfter).toBe(callsBefore);
  });
});

describe("fetchNpmMetadata + fetchPypiMetadata helpers", () => {
  it("fetchNpmMetadata returns null on 404", async () => {
    const mockFetch = vi.fn().mockResolvedValue({ ok: false, status: 404 } as Response);
    const result = await fetchNpmMetadata("nonexistent-pkg", mockFetch);
    expect(result).toBeNull();
  });

  it("fetchNpmMetadata returns null on network error", async () => {
    const mockFetch = vi.fn().mockRejectedValue(new Error("ECONNREFUSED"));
    const result = await fetchNpmMetadata("some-pkg", mockFetch);
    expect(result).toBeNull();
  });

  it("fetchPypiMetadata returns null on 404", async () => {
    const mockFetch = vi.fn().mockResolvedValue({ ok: false, status: 404 } as Response);
    const result = await fetchPypiMetadata("nonexistent", "1.0.0", mockFetch);
    expect(result).toBeNull();
  });

  it("fetchPypiMetadata returns null on network error", async () => {
    const mockFetch = vi.fn().mockRejectedValue(new Error("timeout"));
    const result = await fetchPypiMetadata("some-lib", "2.0.0", mockFetch);
    expect(result).toBeNull();
  });
});
