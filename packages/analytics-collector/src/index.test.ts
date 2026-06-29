import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import {
  validateEvent,
  makeEnvelope,
  EventValidationError,
  EventBuffer,
  SupabaseAdapter,
  AnalyticsCollector,
  DashboardAggregator,
  getCollector,
  setCollector,
  resetCollector,
  collector
} from "./index";

import type {
  AnalyticsEvent,
  ScanCompletedEvent,
  ScanFailedEvent,
  AlertTriggeredEvent,
  UserActionEvent,
  SupabaseFlushAdapter
} from "./index";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeScanCompleted(overrides: Partial<ScanCompletedEvent> = {}): ScanCompletedEvent {
  return {
    type: "scan_completed",
    timestamp: new Date().toISOString(),
    demo: false,
    orgId: "org-1",
    ecosystem: "npm",
    packageName: "lodash",
    version: "4.17.21",
    binaryCount: 2,
    durationMs: 1200,
    riskLevel: "low",
    riskScore: 15,
    cached: false,
    ...overrides
  };
}

function makeScanFailed(overrides: Partial<ScanFailedEvent> = {}): ScanFailedEvent {
  return {
    type: "scan_failed",
    timestamp: new Date().toISOString(),
    demo: false,
    orgId: "org-1",
    ecosystem: "npm",
    packageName: "evil-pkg",
    version: "1.0.0",
    errorCategory: "timeout",
    errorMessage: "scan timed out after 60s",
    durationMs: 60000,
    ...overrides
  };
}

function makeAlertTriggered(overrides: Partial<AlertTriggeredEvent> = {}): AlertTriggeredEvent {
  return {
    type: "alert_triggered",
    timestamp: new Date().toISOString(),
    demo: false,
    orgId: "org-2",
    ecosystem: "pypi",
    packageName: "requests",
    version: "2.31.0",
    riskLevel: "high",
    channel: "email",
    ...overrides
  };
}

function makeUserAction(overrides: Partial<UserActionEvent> = {}): UserActionEvent {
  return {
    type: "user_action",
    timestamp: new Date().toISOString(),
    demo: false,
    orgId: "org-3",
    action: "dashboard_viewed",
    metadata: { path: "/dashboard" },
    ...overrides
  };
}

class MockAdapter implements SupabaseFlushAdapter {
  calls: AnalyticsEvent[][] = [];
  shouldFail = false;

  async insertBatch(events: AnalyticsEvent[]): Promise<void> {
    if (this.shouldFail) throw new Error("Mock Supabase failure");
    this.calls.push([...events]);
  }
}

// ---------------------------------------------------------------------------
// 1. Schema validation — happy paths
// ---------------------------------------------------------------------------

describe("validateEvent — valid events", () => {
  it("accepts a valid scan_completed event", () => {
    expect(() => validateEvent(makeScanCompleted())).not.toThrow();
  });

  it("accepts a scan_completed without orgId", () => {
    const e = makeScanCompleted();
    delete (e as Partial<ScanCompletedEvent>).orgId;
    expect(() => validateEvent(e)).not.toThrow();
  });

  it("accepts a valid scan_failed event", () => {
    expect(() => validateEvent(makeScanFailed())).not.toThrow();
  });

  it("accepts a valid alert_triggered event", () => {
    expect(() => validateEvent(makeAlertTriggered())).not.toThrow();
  });

  it("accepts a valid user_action event", () => {
    expect(() => validateEvent(makeUserAction())).not.toThrow();
  });

  it("accepts a scan_completed with demo=true", () => {
    expect(() => validateEvent(makeScanCompleted({ demo: true }))).not.toThrow();
  });

  it("accepts all valid risk levels", () => {
    for (const level of ["none", "low", "medium", "high", "critical"] as const) {
      expect(() => validateEvent(makeScanCompleted({ riskLevel: level }))).not.toThrow();
    }
  });

  it("accepts cached=true", () => {
    expect(() => validateEvent(makeScanCompleted({ cached: true }))).not.toThrow();
  });

  it("accepts all valid user action names", () => {
    const actions = [
      "api_key_created", "api_key_revoked", "repo_connected",
      "watchlist_created", "suppression_created", "scan_submitted",
      "lockfile_uploaded", "report_generated", "billing_checkout_started",
      "dashboard_viewed"
    ] as const;
    for (const action of actions) {
      expect(() => validateEvent(makeUserAction({ action }))).not.toThrow();
    }
  });
});

// ---------------------------------------------------------------------------
// 2. Schema validation — error cases
// ---------------------------------------------------------------------------

describe("validateEvent — invalid events", () => {
  it("throws EventValidationError for null", () => {
    expect(() => validateEvent(null)).toThrow(EventValidationError);
  });

  it("throws for a non-object", () => {
    expect(() => validateEvent("string")).toThrow(EventValidationError);
  });

  it("throws for unknown event type", () => {
    expect(() => validateEvent({ ...makeScanCompleted(), type: "unknown_type" })).toThrow(EventValidationError);
  });

  it("throws for missing timestamp", () => {
    const e = { ...makeScanCompleted() };
    delete (e as Record<string, unknown>).timestamp;
    expect(() => validateEvent(e)).toThrow(EventValidationError);
  });

  it("throws for invalid timestamp string", () => {
    expect(() => validateEvent({ ...makeScanCompleted(), timestamp: "not-a-date" })).toThrow(EventValidationError);
  });

  it("throws when demo is not boolean", () => {
    expect(() => validateEvent({ ...makeScanCompleted(), demo: "yes" })).toThrow(EventValidationError);
  });

  it("throws when orgId is not a string", () => {
    expect(() => validateEvent({ ...makeScanCompleted(), orgId: 123 })).toThrow(EventValidationError);
  });

  it("throws for scan_completed missing binaryCount", () => {
    const e = { ...makeScanCompleted() };
    delete (e as Record<string, unknown>).binaryCount;
    expect(() => validateEvent(e)).toThrow(EventValidationError);
  });

  it("throws for scan_completed with invalid riskLevel", () => {
    expect(() => validateEvent({ ...makeScanCompleted(), riskLevel: "extreme" as never })).toThrow(EventValidationError);
  });

  it("throws for scan_completed with non-finite durationMs", () => {
    expect(() => validateEvent({ ...makeScanCompleted(), durationMs: Infinity })).toThrow(EventValidationError);
  });

  it("throws for scan_failed missing errorCategory", () => {
    const e = { ...makeScanFailed() };
    delete (e as Record<string, unknown>).errorCategory;
    expect(() => validateEvent(e)).toThrow(EventValidationError);
  });

  it("throws for alert_triggered missing channel", () => {
    const e = { ...makeAlertTriggered() };
    delete (e as Record<string, unknown>).channel;
    expect(() => validateEvent(e)).toThrow(EventValidationError);
  });

  it("throws for alert_triggered with invalid riskLevel", () => {
    expect(() => validateEvent({ ...makeAlertTriggered(), riskLevel: "ultra" as never })).toThrow(EventValidationError);
  });

  it("throws for user_action with array metadata", () => {
    expect(() => validateEvent({ ...makeUserAction(), metadata: [] as never })).toThrow(EventValidationError);
  });

  it("throws for user_action with null metadata", () => {
    expect(() => validateEvent({ ...makeUserAction(), metadata: null as never })).toThrow(EventValidationError);
  });
});

// ---------------------------------------------------------------------------
// 3. makeEnvelope
// ---------------------------------------------------------------------------

describe("makeEnvelope", () => {
  it("returns a valid ISO timestamp", () => {
    const env = makeEnvelope();
    expect(Date.parse(env.timestamp)).not.toBeNaN();
  });

  it("sets demo to false by default", () => {
    expect(makeEnvelope().demo).toBe(false);
  });

  it("forwards orgId", () => {
    expect(makeEnvelope("org-xyz").orgId).toBe("org-xyz");
  });

  it("forwards demo=true", () => {
    expect(makeEnvelope(undefined, true).demo).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 4. EventBuffer — basic behaviour
// ---------------------------------------------------------------------------

describe("EventBuffer — basic behaviour", () => {
  it("starts empty", () => {
    const buf = new EventBuffer();
    expect(buf.size).toBe(0);
  });

  it("appends events and reports size", () => {
    const buf = new EventBuffer();
    buf.append(makeScanCompleted());
    buf.append(makeScanCompleted());
    expect(buf.size).toBe(2);
  });

  it("snapshot returns a copy of buffered events", () => {
    const buf = new EventBuffer();
    const e = makeScanCompleted();
    buf.append(e);
    const snap = buf.snapshot();
    expect(snap).toHaveLength(1);
    expect(snap[0]).toEqual(e);
  });

  it("flush without adapter clears the buffer and returns 0", async () => {
    const buf = new EventBuffer();
    buf.append(makeScanCompleted());
    const count = await buf.flush();
    expect(count).toBe(0);
    expect(buf.size).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// 5. EventBuffer — overflow / eviction
// ---------------------------------------------------------------------------

describe("EventBuffer — overflow eviction", () => {
  it("evicts the oldest event when maxSize is exceeded", () => {
    // autoFlushThreshold set above maxSize to prevent background flush
    // from draining the buffer before we can assert on it.
    const buf = new EventBuffer({ maxSize: 3, autoFlushThreshold: 100 });
    const e1 = makeScanCompleted({ packageName: "pkg-1" });
    const e2 = makeScanCompleted({ packageName: "pkg-2" });
    const e3 = makeScanCompleted({ packageName: "pkg-3" });
    const e4 = makeScanCompleted({ packageName: "pkg-4" });
    buf.append(e1);
    buf.append(e2);
    buf.append(e3);
    buf.append(e4);
    expect(buf.size).toBe(3);
    const snap = buf.snapshot();
    const names = snap.map((e) => (e as ScanCompletedEvent).packageName);
    expect(names).toEqual(["pkg-2", "pkg-3", "pkg-4"]);
  });

  it("tracks evicted count in stats", () => {
    const buf = new EventBuffer({ maxSize: 2, autoFlushThreshold: 100 });
    buf.append(makeScanCompleted());
    buf.append(makeScanCompleted());
    buf.append(makeScanCompleted()); // triggers eviction
    expect(buf.stats().totalEvicted).toBe(1);
  });

  it("throws RangeError for maxSize < 1", () => {
    expect(() => new EventBuffer({ maxSize: 0 })).toThrow(RangeError);
  });

  it("throws RangeError for autoFlushThreshold < 1", () => {
    expect(() => new EventBuffer({ autoFlushThreshold: 0 })).toThrow(RangeError);
  });
});

// ---------------------------------------------------------------------------
// 6. EventBuffer — Supabase batch flush
// ---------------------------------------------------------------------------

describe("EventBuffer — Supabase batch flush", () => {
  it("calls adapter.insertBatch with buffered events", async () => {
    const adapter = new MockAdapter();
    const buf = new EventBuffer({ adapter, autoFlushThreshold: 1000 });
    const e1 = makeScanCompleted({ packageName: "pkg-a" });
    const e2 = makeScanFailed();
    buf.append(e1);
    buf.append(e2);
    const count = await buf.flush();
    expect(count).toBe(2);
    expect(adapter.calls).toHaveLength(1);
    expect(adapter.calls[0]).toHaveLength(2);
  });

  it("clears the buffer after flush", async () => {
    const adapter = new MockAdapter();
    const buf = new EventBuffer({ adapter, autoFlushThreshold: 1000 });
    buf.append(makeScanCompleted());
    await buf.flush();
    expect(buf.size).toBe(0);
  });

  it("returns 0 from flush when buffer is empty", async () => {
    const adapter = new MockAdapter();
    const buf = new EventBuffer({ adapter });
    const count = await buf.flush();
    expect(count).toBe(0);
  });

  it("propagates adapter errors on explicit flush", async () => {
    const adapter = new MockAdapter();
    adapter.shouldFail = true;
    const buf = new EventBuffer({ adapter, autoFlushThreshold: 1000 });
    buf.append(makeScanCompleted());
    await expect(buf.flush()).rejects.toThrow("Mock Supabase failure");
  });

  it("calls onFlushError on auto-flush failure (not throw)", async () => {
    const adapter = new MockAdapter();
    adapter.shouldFail = true;
    const errors: Error[] = [];
    const buf = new EventBuffer({
      adapter,
      autoFlushThreshold: 1,
      onFlushError: (e) => errors.push(e)
    });
    buf.append(makeScanCompleted()); // triggers auto-flush
    // Wait a tick for the async background flush
    await new Promise((r) => setTimeout(r, 10));
    expect(errors.length).toBeGreaterThan(0);
  });

  it("tracks totalFlushed in stats", async () => {
    const adapter = new MockAdapter();
    const buf = new EventBuffer({ adapter, autoFlushThreshold: 1000 });
    buf.append(makeScanCompleted());
    buf.append(makeScanCompleted());
    await buf.flush();
    expect(buf.stats().totalFlushed).toBe(2);
  });

  it("demoMode flush is a no-op and returns 0", async () => {
    const adapter = new MockAdapter();
    const buf = new EventBuffer({ adapter, demoMode: true });
    buf.append(makeScanCompleted());
    const count = await buf.flush();
    expect(count).toBe(0);
    expect(adapter.calls).toHaveLength(0);
    expect(buf.size).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// 7. AnalyticsCollector
// ---------------------------------------------------------------------------

describe("AnalyticsCollector", () => {
  it("emits scan_completed and stores in buffer", () => {
    const c = new AnalyticsCollector({ demoMode: false });
    c.scanCompleted({ ecosystem: "npm", packageName: "lodash", version: "4.0.0", binaryCount: 1, durationMs: 500, riskLevel: "none", riskScore: 0, cached: false });
    expect(c.bufferSize).toBe(1);
  });

  it("emits scan_failed", () => {
    const c = new AnalyticsCollector({ demoMode: false });
    c.scanFailed({ ecosystem: "npm", packageName: "evil", version: "1.0.0", errorCategory: "timeout", errorMessage: "timed out", durationMs: 30000 });
    expect(c.bufferSize).toBe(1);
  });

  it("emits alert_triggered", () => {
    const c = new AnalyticsCollector({ demoMode: false });
    c.alertTriggered({ ecosystem: "pypi", packageName: "requests", version: "2.0.0", riskLevel: "high", channel: "slack" });
    expect(c.bufferSize).toBe(1);
  });

  it("emits user_action", () => {
    const c = new AnalyticsCollector({ demoMode: false });
    c.userAction({ action: "dashboard_viewed", metadata: {} });
    expect(c.bufferSize).toBe(1);
  });

  it("stamps orgId from defaultOrgId when not supplied", () => {
    const c = new AnalyticsCollector({ demoMode: false, defaultOrgId: "org-default" });
    c.scanCompleted({ ecosystem: "npm", packageName: "p", version: "1.0.0", binaryCount: 0, durationMs: 100, riskLevel: "none", riskScore: 0, cached: false });
    const snap = c.snapshot();
    expect(snap[0]!.orgId).toBe("org-default");
  });

  it("per-call orgId overrides defaultOrgId", () => {
    const c = new AnalyticsCollector({ demoMode: false, defaultOrgId: "org-default" });
    c.scanCompleted({ ecosystem: "npm", packageName: "p", version: "1.0.0", binaryCount: 0, durationMs: 100, riskLevel: "none", riskScore: 0, cached: false }, "org-override");
    const snap = c.snapshot();
    expect(snap[0]!.orgId).toBe("org-override");
  });

  it("marks events with demo=true in demo mode", () => {
    const c = new AnalyticsCollector({ demoMode: true });
    c.scanCompleted({ ecosystem: "npm", packageName: "p", version: "1.0.0", binaryCount: 0, durationMs: 100, riskLevel: "none", riskScore: 0, cached: false });
    const snap = c.snapshot();
    expect(snap[0]!.demo).toBe(true);
  });

  it("flush returns flushed count via adapter", async () => {
    const adapter = new MockAdapter();
    const c = new AnalyticsCollector({ demoMode: false, adapter });
    c.scanCompleted({ ecosystem: "npm", packageName: "p", version: "1.0.0", binaryCount: 0, durationMs: 100, riskLevel: "none", riskScore: 0, cached: false });
    const n = await c.flush();
    expect(n).toBe(1);
  });

  it("isDemoMode returns correct value", () => {
    expect(new AnalyticsCollector({ demoMode: true }).isDemoMode()).toBe(true);
    expect(new AnalyticsCollector({ demoMode: false }).isDemoMode()).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 8. Singleton management
// ---------------------------------------------------------------------------

describe("collector singleton", () => {
  afterEach(() => {
    resetCollector();
  });

  it("getCollector returns a stable instance", () => {
    const a = getCollector();
    const b = getCollector();
    expect(a).toBe(b);
  });

  it("setCollector replaces the singleton", () => {
    const replacement = new AnalyticsCollector({ demoMode: true });
    setCollector(replacement);
    expect(getCollector()).toBe(replacement);
  });

  it("resetCollector clears the singleton", () => {
    const original = getCollector();
    resetCollector();
    const fresh = getCollector();
    expect(fresh).not.toBe(original);
  });

  it("collector convenience object delegates to singleton", () => {
    const c = new AnalyticsCollector({ demoMode: false });
    setCollector(c);
    collector.scanCompleted({ ecosystem: "npm", packageName: "p", version: "1.0.0", binaryCount: 0, durationMs: 100, riskLevel: "none", riskScore: 0, cached: false });
    expect(collector.snapshot()).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// 9. DashboardAggregator
// ---------------------------------------------------------------------------

describe("DashboardAggregator", () => {
  const agg = new DashboardAggregator();

  it("returns zeroes for empty event list", () => {
    const kpis = agg.compute([]);
    expect(kpis.total_scans_7d).toBe(0);
    expect(kpis.error_rate_pct).toBe(0);
    expect(kpis.p95_latency_ms).toBe(0);
    expect(kpis.active_orgs_7d).toBe(0);
    expect(kpis.top_packages_by_volume).toHaveLength(0);
    expect(kpis.conversion_rate).toBe(0);
  });

  it("counts completed scans in window", () => {
    const events = [makeScanCompleted(), makeScanCompleted()];
    const kpis = agg.compute(events);
    expect(kpis.total_scans_7d).toBe(2);
  });

  it("excludes demo events from total_scans_7d", () => {
    const events = [makeScanCompleted({ demo: false }), makeScanCompleted({ demo: true })];
    const kpis = agg.compute(events);
    expect(kpis.total_scans_7d).toBe(1);
  });

  it("excludes events outside the window", () => {
    const old = makeScanCompleted({ timestamp: new Date(Date.now() - 8 * 86400_000).toISOString() });
    const recent = makeScanCompleted();
    const kpis = agg.compute([old, recent]);
    expect(kpis.total_scans_7d).toBe(1);
  });

  it("computes error_rate_pct correctly", () => {
    const events: AnalyticsEvent[] = [
      makeScanCompleted(), makeScanCompleted(), makeScanFailed()
    ];
    const kpis = agg.compute(events);
    expect(kpis.error_rate_pct).toBeCloseTo(33.33, 1);
  });

  it("computes p95_latency_ms from completed scans", () => {
    const latencies = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 2000];
    const events = latencies.map((ms) => makeScanCompleted({ durationMs: ms }));
    const kpis = agg.compute(events);
    // p95 of 11 values → index ceil(0.95*11)-1 = 10 → 2000
    expect(kpis.p95_latency_ms).toBe(2000);
  });

  it("counts active_orgs_7d distinct orgs", () => {
    const events = [
      makeScanCompleted({ orgId: "org-a" }),
      makeScanCompleted({ orgId: "org-b" }),
      makeScanCompleted({ orgId: "org-a" })
    ];
    const kpis = agg.compute(events);
    expect(kpis.active_orgs_7d).toBe(2);
  });

  it("does not count undefined orgId as an active org", () => {
    const e = makeScanCompleted();
    delete (e as Partial<ScanCompletedEvent>).orgId;
    const kpis = agg.compute([e]);
    expect(kpis.active_orgs_7d).toBe(0);
  });

  it("top_packages_by_volume returns top 10 sorted by scanCount", () => {
    const events: AnalyticsEvent[] = [];
    for (let i = 0; i < 15; i++) {
      // pkg-0 gets 15 scans, pkg-1 gets 14, …, pkg-14 gets 1
      for (let j = 0; j <= 14 - i; j++) {
        events.push(makeScanCompleted({ packageName: `pkg-${i}` }));
      }
    }
    const kpis = agg.compute(events);
    expect(kpis.top_packages_by_volume).toHaveLength(10);
    expect(kpis.top_packages_by_volume[0]!.packageName).toBe("pkg-0");
    expect(kpis.top_packages_by_volume[0]!.scanCount).toBe(15);
  });

  it("conversion_rate is 100 when all active orgs have risky scans", () => {
    const events = [
      makeScanCompleted({ orgId: "org-a", riskLevel: "high" }),
      makeScanCompleted({ orgId: "org-b", riskLevel: "critical" })
    ];
    const kpis = agg.compute(events);
    expect(kpis.conversion_rate).toBe(100);
  });

  it("conversion_rate is 0 when all scans are risk-level none", () => {
    const events = [
      makeScanCompleted({ orgId: "org-a", riskLevel: "none" }),
      makeScanCompleted({ orgId: "org-b", riskLevel: "none" })
    ];
    const kpis = agg.compute(events);
    expect(kpis.conversion_rate).toBe(0);
  });

  it("conversion_rate is 50 when half orgs have risk", () => {
    const events = [
      makeScanCompleted({ orgId: "org-a", riskLevel: "none" }),
      makeScanCompleted({ orgId: "org-b", riskLevel: "high" })
    ];
    const kpis = agg.compute(events);
    expect(kpis.conversion_rate).toBe(50);
  });

  it("computed_at is a valid ISO string", () => {
    const kpis = agg.compute([]);
    expect(Date.parse(kpis.computed_at)).not.toBeNaN();
  });

  it("window_days reflects custom value", () => {
    const kpis = agg.compute([], 14);
    expect(kpis.window_days).toBe(14);
  });

  it("computeFromRows builds events from row objects", () => {
    const rows = [
      {
        event_type: "scan_completed",
        org_id: "org-1",
        demo: false,
        timestamp: new Date().toISOString(),
        payload: {
          ecosystem: "npm",
          packageName: "lodash",
          version: "4.0.0",
          binaryCount: 1,
          durationMs: 1000,
          riskLevel: "low",
          riskScore: 10,
          cached: false
        }
      }
    ];
    const kpis = agg.computeFromRows(rows as Parameters<typeof agg.computeFromRows>[0]);
    expect(kpis.total_scans_7d).toBe(1);
  });

  it("p95_latency_ms is 0 when no completed scans", () => {
    const kpis = agg.compute([makeScanFailed()]);
    expect(kpis.p95_latency_ms).toBe(0);
  });

  it("error_rate_pct is 100 when all attempts failed", () => {
    const kpis = agg.compute([makeScanFailed(), makeScanFailed()]);
    expect(kpis.error_rate_pct).toBe(100);
  });

  it("includes alert_triggered events in inWindow but not in scan counts", () => {
    const events: AnalyticsEvent[] = [makeScanCompleted({ orgId: "org-x" }), makeAlertTriggered({ orgId: "org-x" })];
    const kpis = agg.compute(events);
    expect(kpis.total_scans_7d).toBe(1);
    expect(kpis.active_orgs_7d).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// 10. SupabaseAdapter construction
// ---------------------------------------------------------------------------

describe("SupabaseAdapter", () => {
  it("constructs without throwing", () => {
    expect(() => new SupabaseAdapter("https://example.supabase.co", "service-key")).not.toThrow();
  });

  it("insertBatch skips fetch when events is empty", async () => {
    const fetchSpy = vi.spyOn(global, "fetch");
    const adapter = new SupabaseAdapter("https://example.supabase.co", "key");
    await adapter.insertBatch([]);
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });

  it("throws when fetch returns non-ok status", async () => {
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValue(
      new Response("error", { status: 400 })
    );
    const adapter = new SupabaseAdapter("https://example.supabase.co", "key");
    await expect(adapter.insertBatch([makeScanCompleted()])).rejects.toThrow("Supabase batch insert failed");
    fetchSpy.mockRestore();
  });

  it("resolves when fetch returns 201", async () => {
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValue(
      new Response("", { status: 201 })
    );
    const adapter = new SupabaseAdapter("https://example.supabase.co", "key");
    await expect(adapter.insertBatch([makeScanCompleted()])).resolves.toBeUndefined();
    fetchSpy.mockRestore();
  });
});
