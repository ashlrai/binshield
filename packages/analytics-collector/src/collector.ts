/**
 * AnalyticsCollector — singleton façade for emitting structured events.
 *
 * Usage:
 *   import { collector } from "@binshield/analytics-collector";
 *   collector.scanCompleted({ ... });
 *
 * In demo mode (BINSHIELD_DEMO=true or explicit demoMode option) all emit
 * calls are no-ops and flushes write nothing to Supabase.
 */

import { EventBuffer, SupabaseAdapter } from "./buffer";
import type { EventBufferOptions } from "./buffer";
import { makeEnvelope, validateEvent } from "./schema";
import type {
  AlertTriggeredPayload,
  AnalyticsEvent,
  ScanCompletedPayload,
  ScanFailedPayload,
  UserActionPayload
} from "./schema";

// ---------------------------------------------------------------------------
// Collector options
// ---------------------------------------------------------------------------

export interface CollectorOptions extends EventBufferOptions {
  supabaseUrl?: string;
  supabaseServiceRoleKey?: string;
  /** Override demo mode detection. Defaults to BINSHIELD_DEMO env var. */
  demoMode?: boolean;
  /** Default orgId stamped on every event when none is supplied per-call. */
  defaultOrgId?: string;
}

// ---------------------------------------------------------------------------
// AnalyticsCollector
// ---------------------------------------------------------------------------

export class AnalyticsCollector {
  private readonly buffer: EventBuffer;
  private readonly demo: boolean;
  private readonly defaultOrgId: string | undefined;

  constructor(options: CollectorOptions = {}) {
    const demo =
      options.demoMode ??
      (typeof process !== "undefined" && process.env.BINSHIELD_DEMO === "true");

    this.demo = demo;
    this.defaultOrgId = options.defaultOrgId;

    // Build Supabase adapter if credentials provided and not in demo mode
    const adapter =
      !demo && options.supabaseUrl && options.supabaseServiceRoleKey
        ? new SupabaseAdapter(options.supabaseUrl, options.supabaseServiceRoleKey)
        : options.adapter;

    this.buffer = new EventBuffer({
      ...options,
      adapter,
      demoMode: demo
    });
  }

  // -------------------------------------------------------------------------
  // Typed emit helpers
  // -------------------------------------------------------------------------

  scanCompleted(
    payload: Omit<ScanCompletedPayload, "type">,
    orgId?: string
  ): void {
    this._emit({
      ...makeEnvelope(orgId ?? this.defaultOrgId, this.demo),
      type: "scan_completed",
      ...payload
    });
  }

  scanFailed(
    payload: Omit<ScanFailedPayload, "type">,
    orgId?: string
  ): void {
    this._emit({
      ...makeEnvelope(orgId ?? this.defaultOrgId, this.demo),
      type: "scan_failed",
      ...payload
    });
  }

  alertTriggered(
    payload: Omit<AlertTriggeredPayload, "type">,
    orgId?: string
  ): void {
    this._emit({
      ...makeEnvelope(orgId ?? this.defaultOrgId, this.demo),
      type: "alert_triggered",
      ...payload
    });
  }

  userAction(
    payload: Omit<UserActionPayload, "type">,
    orgId?: string
  ): void {
    this._emit({
      ...makeEnvelope(orgId ?? this.defaultOrgId, this.demo),
      type: "user_action",
      ...payload
    });
  }

  // -------------------------------------------------------------------------
  // Low-level emit
  // -------------------------------------------------------------------------

  emit(event: AnalyticsEvent): void {
    this._emit(event);
  }

  // -------------------------------------------------------------------------
  // Buffer management
  // -------------------------------------------------------------------------

  async flush(): Promise<number> {
    return this.buffer.flush();
  }

  get bufferSize(): number {
    return this.buffer.size;
  }

  snapshot(): readonly AnalyticsEvent[] {
    return this.buffer.snapshot();
  }

  stats() {
    return this.buffer.stats();
  }

  isDemoMode(): boolean {
    return this.demo;
  }

  // -------------------------------------------------------------------------
  // Private
  // -------------------------------------------------------------------------

  private _emit(event: AnalyticsEvent): void {
    // Validate in development; swallow validation errors in production so a
    // bad instrumentation call never crashes the hot path.
    try {
      validateEvent(event);
    } catch (err) {
      if (typeof process !== "undefined" && process.env.NODE_ENV !== "production") {
        console.warn("[analytics-collector] invalid event dropped:", err instanceof Error ? err.message : err);
      }
      return;
    }

    this.buffer.append(event);
  }
}

// ---------------------------------------------------------------------------
// Module-level singleton (lazily initialised)
// ---------------------------------------------------------------------------

let _singleton: AnalyticsCollector | null = null;

export function getCollector(): AnalyticsCollector {
  if (!_singleton) {
    _singleton = new AnalyticsCollector({
      supabaseUrl: typeof process !== "undefined" ? process.env.SUPABASE_URL : undefined,
      supabaseServiceRoleKey:
        typeof process !== "undefined" ? process.env.SUPABASE_SERVICE_ROLE_KEY : undefined
    });
  }
  return _singleton;
}

/**
 * Replace the singleton (useful for tests or server bootstrap).
 * Returns the previous instance.
 */
export function setCollector(collector: AnalyticsCollector): AnalyticsCollector | null {
  const prev = _singleton;
  _singleton = collector;
  return prev;
}

/** Reset the singleton to null (useful between tests). */
export function resetCollector(): void {
  _singleton = null;
}

/** Convenience re-export of the singleton's typed helpers. */
export const collector = {
  scanCompleted: (...args: Parameters<AnalyticsCollector["scanCompleted"]>) =>
    getCollector().scanCompleted(...args),
  scanFailed: (...args: Parameters<AnalyticsCollector["scanFailed"]>) =>
    getCollector().scanFailed(...args),
  alertTriggered: (...args: Parameters<AnalyticsCollector["alertTriggered"]>) =>
    getCollector().alertTriggered(...args),
  userAction: (...args: Parameters<AnalyticsCollector["userAction"]>) =>
    getCollector().userAction(...args),
  flush: () => getCollector().flush(),
  snapshot: () => getCollector().snapshot(),
  stats: () => getCollector().stats()
} as const;
