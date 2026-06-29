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
