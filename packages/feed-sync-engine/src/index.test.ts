import { describe, it, expect, vi, beforeEach } from "vitest";

import {
  isFresh,
  parseNvdCveItem,
  computeNvdDelta,
  NvdFeedIngester,
  EpssPercentileFetcher,
  parseCisaKevEntry,
  CisaKevSyncer,
  coerceVersion,
  versionInRange,
  advisoryMatchesPackage,
  DepGraphEnricher,
  type NvdCveItem,
  type SyncedAdvisory,
  type CisaKevEntry,
  type DepGraphEntry
} from "./index";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const THIRTY_ONE_DAYS_MS = 31 * 24 * 60 * 60 * 1000;
const TWENTY_NINE_DAYS_MS = 29 * 24 * 60 * 60 * 1000;

function daysAgo(days: number): string {
  return new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
}

function makeNvdItem(overrides: Partial<NvdCveItem> = {}): NvdCveItem {
  return {
    cve: {
      CVE_data_meta: { ID: "CVE-2024-00001" },
      description: {
        description_data: [{ lang: "en", value: "A test vulnerability." }]
      }
    },
    impact: {
      baseMetricV3: {
        cvssV3: { baseScore: 7.5, baseSeverity: "HIGH" }
      }
    },
    configurations: {
      nodes: [
        {
          cpe_match: [
            {
              cpe23Uri: "cpe:2.3:a:example:lodash:4.17.20:*:*:*:*:node.js:*:*",
              versionStartIncluding: "4.0.0",
              versionEndIncluding: "4.17.20"
            }
          ]
        }
      ]
    },
    lastModifiedDate: "2024-03-15T00:00:00.000Z",
    ...overrides
  };
}

function makeSyncedAdvisory(overrides: Partial<SyncedAdvisory> = {}): SyncedAdvisory {
  return {
    cveId: "CVE-2024-00001",
    description: "A test vulnerability.",
    cvssV3Score: 7.5,
    cvssV3Severity: "HIGH",
    isKev: false,
    affectedProducts: ["cpe:2.3:a:example:lodash:4.17.20:*"],
    affectedVersionRanges: [{ minVersion: "4.0.0", maxVersion: "4.17.20" }],
    lastModifiedAt: "2024-03-15T00:00:00.000Z",
    ingestedAt: new Date().toISOString(),
    ...overrides
  };
}

function makeCisaKevEntry(overrides: Partial<CisaKevEntry> = {}): CisaKevEntry {
  return {
    cveID: "CVE-2024-00002",
    vendorProject: "Example Corp",
    product: "widgetlib",
    vulnerabilityName: "widgetlib RCE",
    dateAdded: "2024-06-01",
    shortDescription: "Remote code execution.",
    requiredAction: "Apply updates.",
    dueDate: "2024-06-15",
    knownRansomwareCampaignUse: "Unknown",
    ...overrides
  };
}

function makeFetchOk(body: unknown): typeof fetch {
  return vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    json: async () => body
  }) as unknown as typeof fetch;
}

function makeFetchError(status = 503): typeof fetch {
  return vi.fn().mockResolvedValue({
    ok: false,
    status
  }) as unknown as typeof fetch;
}

// ---------------------------------------------------------------------------
// 1. isFresh — staleness guard
// ---------------------------------------------------------------------------

describe("isFresh", () => {
  it("returns true for a timestamp 29 days ago", () => {
    expect(isFresh(daysAgo(29))).toBe(true);
  });

  it("returns false for a timestamp 31 days ago", () => {
    expect(isFresh(daysAgo(31))).toBe(false);
  });

  it("returns false for an invalid timestamp", () => {
    expect(isFresh("not-a-date")).toBe(false);
  });

  it("respects a custom maxAgeMs", () => {
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
    const twoHoursMs = 2 * 60 * 60 * 1000;
    expect(isFresh(oneHourAgo, twoHoursMs)).toBe(true);

    const thirtyMinMs = 30 * 60 * 1000;
    expect(isFresh(oneHourAgo, thirtyMinMs)).toBe(false);
  });

  it("returns true for a timestamp exactly at the boundary", () => {
    const maxAgeMs = TWENTY_NINE_DAYS_MS;
    const fetchedAt = new Date(Date.now() - maxAgeMs).toISOString();
    expect(isFresh(fetchedAt, maxAgeMs)).toBe(true);
  });

  it("returns false for a timestamp one ms past the boundary", () => {
    const maxAgeMs = TWENTY_NINE_DAYS_MS;
    const fetchedAt = new Date(Date.now() - maxAgeMs - 1).toISOString();
    expect(isFresh(fetchedAt, maxAgeMs)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 2. parseNvdCveItem — NVD feed parsing
// ---------------------------------------------------------------------------

describe("parseNvdCveItem", () => {
  it("parses CVE ID from data_meta", () => {
    const result = parseNvdCveItem(makeNvdItem());
    expect(result.cveId).toBe("CVE-2024-00001");
  });

  it("extracts English description", () => {
    const result = parseNvdCveItem(makeNvdItem());
    expect(result.description).toBe("A test vulnerability.");
  });

  it("extracts CVSS v3 score and severity", () => {
    const result = parseNvdCveItem(makeNvdItem());
    expect(result.cvssV3Score).toBe(7.5);
    expect(result.cvssV3Severity).toBe("HIGH");
  });

  it("extracts affected products (CPE URIs)", () => {
    const result = parseNvdCveItem(makeNvdItem());
    expect(result.affectedProducts).toContain(
      "cpe:2.3:a:example:lodash:4.17.20:*:*:*:*:node.js:*:*"
    );
  });

  it("extracts version ranges from cpe_match", () => {
    const result = parseNvdCveItem(makeNvdItem());
    expect(result.affectedVersionRanges).toHaveLength(1);
    expect(result.affectedVersionRanges[0].minVersion).toBe("4.0.0");
    expect(result.affectedVersionRanges[0].maxVersion).toBe("4.17.20");
  });

  it("handles missing CVSS data gracefully", () => {
    const item = makeNvdItem({ impact: {} });
    const result = parseNvdCveItem(item);
    expect(result.cvssV3Score).toBeUndefined();
    expect(result.cvssV3Severity).toBeUndefined();
  });

  it("falls back to first description when no English entry", () => {
    const item = makeNvdItem({
      cve: {
        CVE_data_meta: { ID: "CVE-2024-00001" },
        description: {
          description_data: [{ lang: "de", value: "Ein Test." }]
        }
      }
    });
    const result = parseNvdCveItem(item);
    expect(result.description).toBe("Ein Test.");
  });

  it("isKev defaults to false", () => {
    const result = parseNvdCveItem(makeNvdItem());
    expect(result.isKev).toBe(false);
  });

  it("epssPercentile is undefined on parse (enriched later)", () => {
    const result = parseNvdCveItem(makeNvdItem());
    expect(result.epssPercentile).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// 3. computeNvdDelta — deduplication + delta detection
// ---------------------------------------------------------------------------

describe("computeNvdDelta", () => {
  const advisory1 = makeSyncedAdvisory({ cveId: "CVE-2024-A", lastModifiedAt: "2024-01-01T00:00:00Z" });
  const advisory2 = makeSyncedAdvisory({ cveId: "CVE-2024-B", lastModifiedAt: "2024-02-01T00:00:00Z" });

  it("classifies all as added when existing map is empty", () => {
    const { added, updated, unchanged } = computeNvdDelta(
      [advisory1, advisory2],
      new Map()
    );
    expect(added).toEqual(expect.arrayContaining(["CVE-2024-A", "CVE-2024-B"]));
    expect(updated).toHaveLength(0);
    expect(unchanged).toHaveLength(0);
  });

  it("classifies unchanged when lastModifiedAt matches", () => {
    const existing = new Map([["CVE-2024-A", advisory1]]);
    const { unchanged, added, updated } = computeNvdDelta([advisory1], existing);
    expect(unchanged).toContain("CVE-2024-A");
    expect(added).toHaveLength(0);
    expect(updated).toHaveLength(0);
  });

  it("classifies updated when lastModifiedAt differs", () => {
    const existing = new Map([
      ["CVE-2024-A", { ...advisory1, lastModifiedAt: "2024-01-01T00:00:00Z" }]
    ]);
    const newer = { ...advisory1, lastModifiedAt: "2024-06-01T00:00:00Z" };
    const { updated } = computeNvdDelta([newer], existing);
    expect(updated).toContain("CVE-2024-A");
  });

  it("mixes all three categories correctly", () => {
    const existing = new Map([
      ["CVE-2024-A", advisory1],
      ["CVE-2024-B", advisory2]
    ]);
    const updatedAdvisory2 = { ...advisory2, lastModifiedAt: "2024-12-01T00:00:00Z" };
    const newAdvisory3 = makeSyncedAdvisory({ cveId: "CVE-2024-C" });

    const { unchanged, updated, added } = computeNvdDelta(
      [advisory1, updatedAdvisory2, newAdvisory3],
      existing
    );
    expect(unchanged).toContain("CVE-2024-A");
    expect(updated).toContain("CVE-2024-B");
    expect(added).toContain("CVE-2024-C");
  });
});

// ---------------------------------------------------------------------------
// 4. NvdFeedIngester — HTTP + snapshot management
// ---------------------------------------------------------------------------

describe("NvdFeedIngester", () => {
  it("parses and returns advisories from the feed", async () => {
    const envelope = { CVE_Items: [makeNvdItem()] };
    const ingester = new NvdFeedIngester({}, makeFetchOk(envelope));
    const result = await ingester.ingest();
    expect(result.advisories).toHaveLength(1);
    expect(result.advisories[0].cveId).toBe("CVE-2024-00001");
  });

  it("reports all as added on first ingest", async () => {
    const envelope = { CVE_Items: [makeNvdItem()] };
    const ingester = new NvdFeedIngester({}, makeFetchOk(envelope));
    const result = await ingester.ingest();
    expect(result.added).toContain("CVE-2024-00001");
    expect(result.unchanged).toHaveLength(0);
    expect(result.updated).toHaveLength(0);
  });

  it("reports unchanged on second ingest with same data", async () => {
    const envelope = { CVE_Items: [makeNvdItem()] };
    const ingester = new NvdFeedIngester({}, makeFetchOk(envelope));
    await ingester.ingest();
    const result = await ingester.ingest();
    expect(result.unchanged).toContain("CVE-2024-00001");
    expect(result.added).toHaveLength(0);
  });

  it("detects updated CVE when lastModifiedDate changes between ingests", async () => {
    const item = makeNvdItem({ lastModifiedDate: "2024-01-01T00:00:00.000Z" });
    const ingester = new NvdFeedIngester({}, makeFetchOk({ CVE_Items: [item] }));
    await ingester.ingest();

    const updatedItem = makeNvdItem({ lastModifiedDate: "2024-12-01T00:00:00.000Z" });
    const ingester2 = new NvdFeedIngester(
      {},
      makeFetchOk({ CVE_Items: [updatedItem] })
    );
    // Seed second ingester with snapshot from first
    (ingester2 as unknown as { snapshot: Map<string, SyncedAdvisory> }).snapshot =
      new Map(ingester.getSnapshot());
    const result = await ingester2.ingest();
    expect(result.updated).toContain("CVE-2024-00001");
  });

  it("throws on HTTP error", async () => {
    const ingester = new NvdFeedIngester({}, makeFetchError(503));
    await expect(ingester.ingest()).rejects.toThrow("HTTP 503");
  });

  it("isSnapshotFresh returns false before any ingest", () => {
    const ingester = new NvdFeedIngester({});
    expect(ingester.isSnapshotFresh()).toBe(false);
  });

  it("isSnapshotFresh returns true immediately after ingest", async () => {
    const envelope = { CVE_Items: [makeNvdItem()] };
    const ingester = new NvdFeedIngester({}, makeFetchOk(envelope));
    await ingester.ingest();
    expect(ingester.isSnapshotFresh()).toBe(true);
  });

  it("isSnapshotFresh returns false when maxFeedAgeMs has elapsed", async () => {
    const envelope = { CVE_Items: [] };
    const ingester = new NvdFeedIngester(
      { maxFeedAgeMs: 1000 },
      makeFetchOk(envelope)
    );
    await ingester.ingest();
    const future = Date.now() + 2000;
    expect(ingester.isSnapshotFresh(future)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 5. EpssPercentileFetcher — caching + batch fetch
// ---------------------------------------------------------------------------

describe("EpssPercentileFetcher", () => {
  it("returns undefined for uncached CVE", () => {
    const fetcher = new EpssPercentileFetcher();
    expect(fetcher.getCached("CVE-2024-00001")).toBeUndefined();
  });

  it("fetches and caches EPSS percentile for a batch", async () => {
    const body = {
      data: [{ cve: "CVE-2024-00001", epss: "0.00350", percentile: "0.88" }]
    };
    const fetcher = new EpssPercentileFetcher({}, makeFetchOk(body));
    const result = await fetcher.fetchBatch(["CVE-2024-00001"]);
    expect(result.get("CVE-2024-00001")).toBeCloseTo(0.88);
  });

  it("returns cached result without re-fetching within TTL", async () => {
    const body = {
      data: [{ cve: "CVE-2024-00001", epss: "0.00350", percentile: "0.88" }]
    };
    const fetchFn = makeFetchOk(body);
    const fetcher = new EpssPercentileFetcher({}, fetchFn);
    await fetcher.fetchBatch(["CVE-2024-00001"]);
    await fetcher.fetchBatch(["CVE-2024-00001"]); // should hit cache
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it("re-fetches after TTL expiry", async () => {
    const body = {
      data: [{ cve: "CVE-2024-00001", epss: "0.00350", percentile: "0.88" }]
    };
    const fetchFn = makeFetchOk(body);
    const fetcher = new EpssPercentileFetcher({ epssCacheTtlMs: 1000 }, fetchFn);
    const now = Date.now();
    await fetcher.fetchBatch(["CVE-2024-00001"], now);
    await fetcher.fetchBatch(["CVE-2024-00001"], now + 2000); // after TTL
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it("returns empty map for empty CVE list", async () => {
    const fetcher = new EpssPercentileFetcher({}, makeFetchOk({ data: [] }));
    const result = await fetcher.fetchBatch([]);
    expect(result.size).toBe(0);
  });

  it("throws on HTTP error", async () => {
    const fetcher = new EpssPercentileFetcher({}, makeFetchError(429));
    await expect(fetcher.fetchBatch(["CVE-2024-00001"])).rejects.toThrow("HTTP 429");
  });

  it("omits CVEs with no EPSS data from result map", async () => {
    const body = { data: [] }; // no data returned
    const fetcher = new EpssPercentileFetcher({}, makeFetchOk(body));
    const result = await fetcher.fetchBatch(["CVE-2024-UNKNOWN"]);
    expect(result.has("CVE-2024-UNKNOWN")).toBe(false);
  });

  it("pruneCache removes expired entries and returns eviction count", async () => {
    const body = {
      data: [{ cve: "CVE-2024-00001", epss: "0.00350", percentile: "0.88" }]
    };
    const fetcher = new EpssPercentileFetcher({ epssCacheTtlMs: 1000 }, makeFetchOk(body));
    const now = Date.now();
    await fetcher.fetchBatch(["CVE-2024-00001"], now);
    const evicted = fetcher.pruneCache(now + 2000);
    expect(evicted).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// 6. parseCisaKevEntry — KEV parsing
// ---------------------------------------------------------------------------

describe("parseCisaKevEntry", () => {
  it("parses cveId and dateAdded", () => {
    const entry = makeCisaKevEntry();
    const result = parseCisaKevEntry(entry);
    expect(result.cveId).toBe("CVE-2024-00002");
    expect(result.dateAdded).toBe("2024-06-01");
  });

  it("classifies non-ransomware as active-exploitation", () => {
    const result = parseCisaKevEntry(makeCisaKevEntry({ knownRansomwareCampaignUse: "Unknown" }));
    expect(result.exploitMaturity).toBe("active-exploitation");
    expect(result.isRansomware).toBe(false);
  });

  it("classifies ransomware CVEs as widespread", () => {
    const result = parseCisaKevEntry(makeCisaKevEntry({ knownRansomwareCampaignUse: "Known" }));
    expect(result.exploitMaturity).toBe("widespread");
    expect(result.isRansomware).toBe(true);
  });

  it("uses active-exploitation when ransomware field is absent", () => {
    const entry = makeCisaKevEntry();
    delete entry.knownRansomwareCampaignUse;
    const result = parseCisaKevEntry(entry);
    expect(result.exploitMaturity).toBe("active-exploitation");
  });
});

// ---------------------------------------------------------------------------
// 7. CisaKevSyncer — HTTP + lookup
// ---------------------------------------------------------------------------

describe("CisaKevSyncer", () => {
  it("syncs and stores KEV records", async () => {
    const body = { vulnerabilities: [makeCisaKevEntry()] };
    const syncer = new CisaKevSyncer({}, makeFetchOk(body));
    const result = await syncer.sync();
    expect(result.records).toHaveLength(1);
    expect(result.records[0].cveId).toBe("CVE-2024-00002");
  });

  it("isKev returns true for synced CVE", async () => {
    const body = { vulnerabilities: [makeCisaKevEntry()] };
    const syncer = new CisaKevSyncer({}, makeFetchOk(body));
    await syncer.sync();
    expect(syncer.isKev("CVE-2024-00002")).toBe(true);
  });

  it("isKev returns false for unsynced CVE", async () => {
    const body = { vulnerabilities: [makeCisaKevEntry()] };
    const syncer = new CisaKevSyncer({}, makeFetchOk(body));
    await syncer.sync();
    expect(syncer.isKev("CVE-9999-00000")).toBe(false);
  });

  it("reports newly added CVEs on first sync", async () => {
    const body = { vulnerabilities: [makeCisaKevEntry()] };
    const syncer = new CisaKevSyncer({}, makeFetchOk(body));
    const result = await syncer.sync();
    expect(result.added).toContain("CVE-2024-00002");
  });

  it("does not re-add existing CVEs on subsequent syncs", async () => {
    const body = { vulnerabilities: [makeCisaKevEntry()] };
    const fetchFn = makeFetchOk(body);
    const syncer = new CisaKevSyncer({}, fetchFn);
    await syncer.sync();
    const result = await syncer.sync();
    expect(result.added).toHaveLength(0);
  });

  it("throws on HTTP error", async () => {
    const syncer = new CisaKevSyncer({}, makeFetchError(404));
    await expect(syncer.sync()).rejects.toThrow("HTTP 404");
  });

  it("lookup returns the record when present", async () => {
    const body = { vulnerabilities: [makeCisaKevEntry()] };
    const syncer = new CisaKevSyncer({}, makeFetchOk(body));
    await syncer.sync();
    const record = syncer.lookup("CVE-2024-00002");
    expect(record).toBeDefined();
    expect(record?.exploitMaturity).toBe("active-exploitation");
  });

  it("isSnapshotFresh returns false before any sync", () => {
    const syncer = new CisaKevSyncer({});
    expect(syncer.isSnapshotFresh()).toBe(false);
  });

  it("isSnapshotFresh returns true immediately after sync", async () => {
    const body = { vulnerabilities: [] };
    const syncer = new CisaKevSyncer({}, makeFetchOk(body));
    await syncer.sync();
    expect(syncer.isSnapshotFresh()).toBe(true);
  });

  it("size reflects number of synced records", async () => {
    const body = {
      vulnerabilities: [
        makeCisaKevEntry({ cveID: "CVE-2024-00002" }),
        makeCisaKevEntry({ cveID: "CVE-2024-00003" })
      ]
    };
    const syncer = new CisaKevSyncer({}, makeFetchOk(body));
    await syncer.sync();
    expect(syncer.size).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// 8. coerceVersion — version tuple parsing
// ---------------------------------------------------------------------------

describe("coerceVersion", () => {
  it("parses standard semver", () => {
    expect(coerceVersion("1.2.3")).toEqual([1, 2, 3]);
  });

  it("strips leading v prefix", () => {
    expect(coerceVersion("v2.0.1")).toEqual([2, 0, 1]);
  });

  it("strips leading = prefix", () => {
    expect(coerceVersion("=3.1.0")).toEqual([3, 1, 0]);
  });

  it("handles major-only version", () => {
    expect(coerceVersion("4")).toEqual([4, 0, 0]);
  });

  it("handles major.minor version", () => {
    expect(coerceVersion("4.17")).toEqual([4, 17, 0]);
  });

  it("strips pre-release suffix", () => {
    expect(coerceVersion("1.2.3-alpha.1")).toEqual([1, 2, 3]);
  });

  it("strips build metadata", () => {
    expect(coerceVersion("1.2.3+build.42")).toEqual([1, 2, 3]);
  });

  it("returns null for non-parseable string", () => {
    expect(coerceVersion("not-a-version")).toBeNull();
  });

  it("returns null for empty string", () => {
    expect(coerceVersion("")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 9. versionInRange — range matching
// ---------------------------------------------------------------------------

describe("versionInRange", () => {
  it("matches version within closed range", () => {
    expect(versionInRange("4.17.15", { minVersion: "4.0.0", maxVersion: "4.17.20" })).toBe(true);
  });

  it("matches version at lower bound (inclusive)", () => {
    expect(versionInRange("4.0.0", { minVersion: "4.0.0", maxVersion: "4.17.20" })).toBe(true);
  });

  it("matches version at upper bound (inclusive)", () => {
    expect(versionInRange("4.17.20", { minVersion: "4.0.0", maxVersion: "4.17.20" })).toBe(true);
  });

  it("does not match version below lower bound", () => {
    expect(versionInRange("3.9.9", { minVersion: "4.0.0", maxVersion: "4.17.20" })).toBe(false);
  });

  it("does not match version above upper bound", () => {
    expect(versionInRange("4.17.21", { minVersion: "4.0.0", maxVersion: "4.17.20" })).toBe(false);
  });

  it("matches any version when range is empty object", () => {
    expect(versionInRange("99.99.99", {})).toBe(true);
  });

  it("matches when only maxVersion is set and version is below it", () => {
    expect(versionInRange("1.0.0", { maxVersion: "2.0.0" })).toBe(true);
  });

  it("does not match when only maxVersion is set and version exceeds it", () => {
    expect(versionInRange("3.0.0", { maxVersion: "2.0.0" })).toBe(false);
  });

  it("returns false for unparseable version string", () => {
    expect(versionInRange("latest", { minVersion: "1.0.0", maxVersion: "2.0.0" })).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 10. advisoryMatchesPackage — CPE + version cross-reference
// ---------------------------------------------------------------------------

describe("advisoryMatchesPackage", () => {
  it("matches when package name appears in CPE and version is in range", () => {
    const advisory = makeSyncedAdvisory({
      affectedProducts: ["cpe:2.3:a:example:lodash:4.17.20:*"],
      affectedVersionRanges: [{ minVersion: "4.0.0", maxVersion: "4.17.20" }]
    });
    expect(advisoryMatchesPackage(advisory, "lodash", "4.17.15")).toBe(true);
  });

  it("does not match when package name is absent from CPE", () => {
    const advisory = makeSyncedAdvisory({
      affectedProducts: ["cpe:2.3:a:example:express:4.17.20:*"],
      affectedVersionRanges: []
    });
    expect(advisoryMatchesPackage(advisory, "lodash", "4.17.15")).toBe(false);
  });

  it("matches any version when no ranges are provided", () => {
    const advisory = makeSyncedAdvisory({
      affectedProducts: ["cpe:2.3:a:example:lodash:*:*"],
      affectedVersionRanges: []
    });
    expect(advisoryMatchesPackage(advisory, "lodash", "99.0.0")).toBe(true);
  });

  it("does not match when version is outside all ranges", () => {
    const advisory = makeSyncedAdvisory({
      affectedProducts: ["cpe:2.3:a:example:lodash:*:*"],
      affectedVersionRanges: [{ minVersion: "4.0.0", maxVersion: "4.17.20" }]
    });
    expect(advisoryMatchesPackage(advisory, "lodash", "4.17.21")).toBe(false);
  });

  it("matches any version when affectedProducts is empty", () => {
    const advisory = makeSyncedAdvisory({
      affectedProducts: [],
      affectedVersionRanges: []
    });
    expect(advisoryMatchesPackage(advisory, "anything", "1.0.0")).toBe(true);
  });

  it("is case-insensitive on package name", () => {
    const advisory = makeSyncedAdvisory({
      affectedProducts: ["cpe:2.3:a:example:Lodash:*:*"],
      affectedVersionRanges: []
    });
    expect(advisoryMatchesPackage(advisory, "lodash", "4.0.0")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 11. DepGraphEnricher — cross-reference
// ---------------------------------------------------------------------------

describe("DepGraphEnricher", () => {
  const recentIngestedAt = new Date().toISOString();

  function makeAdvisoryMap(
    overrides: Partial<SyncedAdvisory> = {}
  ): Map<string, SyncedAdvisory> {
    return new Map([
      [
        "CVE-2024-00001",
        makeSyncedAdvisory({
          cveId: "CVE-2024-00001",
          epssPercentile: 0.85,
          ingestedAt: recentIngestedAt,
          affectedProducts: ["cpe:2.3:a:example:lodash:*:*"],
          affectedVersionRanges: [{ minVersion: "4.0.0", maxVersion: "4.17.20" }],
          ...overrides
        })
      ]
    ]);
  }

  it("returns vulnCount=0 for a package with no matches", () => {
    const enricher = new DepGraphEnricher(makeAdvisoryMap());
    const result = enricher.enrichOne({ packageName: "express", version: "4.18.0" });
    expect(result.vulnCount).toBe(0);
    expect(result.matchedCveIds).toHaveLength(0);
  });

  it("returns correct vulnCount for a matched package@version", () => {
    const enricher = new DepGraphEnricher(makeAdvisoryMap());
    const result = enricher.enrichOne({ packageName: "lodash", version: "4.17.15" });
    expect(result.vulnCount).toBe(1);
    expect(result.matchedCveIds).toContain("CVE-2024-00001");
  });

  it("captures highest EPSS percentile across all matches", () => {
    const advisories = new Map<string, SyncedAdvisory>([
      [
        "CVE-2024-00001",
        makeSyncedAdvisory({
          cveId: "CVE-2024-00001",
          epssPercentile: 0.85,
          ingestedAt: recentIngestedAt,
          affectedProducts: ["cpe:2.3:a:example:lodash:*:*"],
          affectedVersionRanges: []
        })
      ],
      [
        "CVE-2024-00002",
        makeSyncedAdvisory({
          cveId: "CVE-2024-00002",
          epssPercentile: 0.92,
          ingestedAt: recentIngestedAt,
          affectedProducts: ["cpe:2.3:a:example:lodash:*:*"],
          affectedVersionRanges: []
        })
      ]
    ]);
    const enricher = new DepGraphEnricher(advisories);
    const result = enricher.enrichOne({ packageName: "lodash", version: "4.17.15" });
    expect(result.highestEpssPercentile).toBeCloseTo(0.92);
  });

  it("sets hasKevMatch=true when advisory.isKev=true", () => {
    const advisories = makeAdvisoryMap({ isKev: true });
    const enricher = new DepGraphEnricher(advisories);
    const result = enricher.enrichOne({ packageName: "lodash", version: "4.17.15" });
    expect(result.hasKevMatch).toBe(true);
  });

  it("sets hasKevMatch=false when no KEV match", () => {
    const enricher = new DepGraphEnricher(makeAdvisoryMap({ isKev: false }));
    const result = enricher.enrichOne({ packageName: "lodash", version: "4.17.15" });
    expect(result.hasKevMatch).toBe(false);
  });

  it("skips stale feed entries (>30 days old)", () => {
    const staleAdvisory = makeSyncedAdvisory({
      cveId: "CVE-2024-00001",
      ingestedAt: new Date(Date.now() - THIRTY_ONE_DAYS_MS).toISOString(),
      affectedProducts: ["cpe:2.3:a:example:lodash:*:*"],
      affectedVersionRanges: []
    });
    const enricher = new DepGraphEnricher(new Map([["CVE-2024-00001", staleAdvisory]]));
    const result = enricher.enrichOne({ packageName: "lodash", version: "4.17.15" });
    expect(result.vulnCount).toBe(0);
  });

  it("enrich processes all deps and sorts by vulnCount desc", () => {
    const advisories = makeAdvisoryMap();
    const enricher = new DepGraphEnricher(advisories);
    const deps: DepGraphEntry[] = [
      { packageName: "express", version: "4.18.0" },  // 0 matches
      { packageName: "lodash", version: "4.17.15" }   // 1 match
    ];
    const results = enricher.enrich(deps);
    expect(results).toHaveLength(2);
    expect(results[0].packageName).toBe("lodash");
    expect(results[1].packageName).toBe("express");
  });

  it("enrichedAt is a valid ISO timestamp", () => {
    const enricher = new DepGraphEnricher(makeAdvisoryMap());
    const result = enricher.enrichOne({ packageName: "express", version: "1.0.0" });
    expect(() => new Date(result.enrichedAt)).not.toThrow();
    expect(new Date(result.enrichedAt).toISOString()).toBe(result.enrichedAt);
  });
});
