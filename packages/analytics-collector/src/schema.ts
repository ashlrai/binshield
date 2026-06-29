/**
 * Structured event schema for BinShield product analytics.
 *
 * Every event has a common envelope (type, timestamp, orgId, demo) plus a
 * discriminated-union payload specific to the event type.
 */

// ---------------------------------------------------------------------------
// Shared envelope
// ---------------------------------------------------------------------------

export interface EventEnvelope {
  /** ISO-8601 UTC timestamp. */
  timestamp: string;
  /** Originating org; undefined for anonymous / pre-auth events. */
  orgId?: string;
  /** When true the event was emitted in demo/local mode and should not be
   *  counted toward production KPIs. */
  demo: boolean;
}

// ---------------------------------------------------------------------------
// scan_completed
// ---------------------------------------------------------------------------

export interface ScanCompletedPayload {
  type: "scan_completed";
  ecosystem: string;
  packageName: string;
  version: string;
  /** Total native binaries found. */
  binaryCount: number;
  /** Wall-clock duration of the scan in milliseconds. */
  durationMs: number;
  /** Aggregate risk level returned by the risk engine. */
  riskLevel: "none" | "low" | "medium" | "high" | "critical";
  /** 0–100 aggregate risk score. */
  riskScore: number;
  /** Whether the result was served from cache. */
  cached: boolean;
}

export type ScanCompletedEvent = EventEnvelope & ScanCompletedPayload;

// ---------------------------------------------------------------------------
// scan_failed
// ---------------------------------------------------------------------------

export interface ScanFailedPayload {
  type: "scan_failed";
  ecosystem: string;
  packageName: string;
  version: string;
  /** Short error category (e.g. "timeout", "decompiler_error", "network"). */
  errorCategory: string;
  /** Human-readable error message (may be empty). */
  errorMessage: string;
  /** Wall-clock duration until failure, in milliseconds. */
  durationMs: number;
}

export type ScanFailedEvent = EventEnvelope & ScanFailedPayload;

// ---------------------------------------------------------------------------
// alert_triggered
// ---------------------------------------------------------------------------

export interface AlertTriggeredPayload {
  type: "alert_triggered";
  ecosystem: string;
  packageName: string;
  version: string;
  riskLevel: "none" | "low" | "medium" | "high" | "critical";
  /** Alert channel: email | slack | webhook */
  channel: string;
}

export type AlertTriggeredEvent = EventEnvelope & AlertTriggeredPayload;

// ---------------------------------------------------------------------------
// user_action
// ---------------------------------------------------------------------------

export type UserActionName =
  | "api_key_created"
  | "api_key_revoked"
  | "repo_connected"
  | "watchlist_created"
  | "suppression_created"
  | "scan_submitted"
  | "lockfile_uploaded"
  | "report_generated"
  | "billing_checkout_started"
  | "dashboard_viewed";

export interface UserActionPayload {
  type: "user_action";
  action: UserActionName;
  /** Arbitrary key/value metadata (route params, feature flags, etc.). */
  metadata: Record<string, string | number | boolean | null>;
}

export type UserActionEvent = EventEnvelope & UserActionPayload;

// ---------------------------------------------------------------------------
// Union
// ---------------------------------------------------------------------------

export type AnalyticsEvent =
  | ScanCompletedEvent
  | ScanFailedEvent
  | AlertTriggeredEvent
  | UserActionEvent;

export type AnalyticsEventType = AnalyticsEvent["type"];

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

const VALID_TYPES = new Set<string>(["scan_completed", "scan_failed", "alert_triggered", "user_action"]);
const VALID_RISK_LEVELS = new Set<string>(["none", "low", "medium", "high", "critical"]);

export class EventValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EventValidationError";
  }
}

/** Throws EventValidationError if the event is structurally invalid. */
export function validateEvent(event: unknown): asserts event is AnalyticsEvent {
  if (!event || typeof event !== "object") {
    throw new EventValidationError("Event must be an object");
  }

  const e = event as Record<string, unknown>;

  if (typeof e.type !== "string" || !VALID_TYPES.has(e.type)) {
    throw new EventValidationError(
      `Invalid or missing event type. Must be one of: ${[...VALID_TYPES].join(", ")}`
    );
  }

  if (typeof e.timestamp !== "string" || isNaN(Date.parse(e.timestamp))) {
    throw new EventValidationError("Event must have a valid ISO-8601 timestamp");
  }

  if (typeof e.demo !== "boolean") {
    throw new EventValidationError("Event must have a boolean 'demo' field");
  }

  if (e.orgId !== undefined && typeof e.orgId !== "string") {
    throw new EventValidationError("orgId must be a string when present");
  }

  switch (e.type) {
    case "scan_completed":
      requireString(e, "ecosystem");
      requireString(e, "packageName");
      requireString(e, "version");
      requireNumber(e, "binaryCount");
      requireNumber(e, "durationMs");
      requireRiskLevel(e, "riskLevel");
      requireNumber(e, "riskScore");
      requireBoolean(e, "cached");
      break;

    case "scan_failed":
      requireString(e, "ecosystem");
      requireString(e, "packageName");
      requireString(e, "version");
      requireString(e, "errorCategory");
      requireString(e, "errorMessage");
      requireNumber(e, "durationMs");
      break;

    case "alert_triggered":
      requireString(e, "ecosystem");
      requireString(e, "packageName");
      requireString(e, "version");
      requireRiskLevel(e, "riskLevel");
      requireString(e, "channel");
      break;

    case "user_action":
      requireString(e, "action");
      if (!e.metadata || typeof e.metadata !== "object" || Array.isArray(e.metadata)) {
        throw new EventValidationError("user_action event must have a metadata object");
      }
      break;
  }
}

function requireString(e: Record<string, unknown>, field: string): void {
  if (typeof e[field] !== "string") {
    throw new EventValidationError(`Field '${field}' must be a string`);
  }
}

function requireNumber(e: Record<string, unknown>, field: string): void {
  if (typeof e[field] !== "number" || !isFinite(e[field] as number)) {
    throw new EventValidationError(`Field '${field}' must be a finite number`);
  }
}

function requireBoolean(e: Record<string, unknown>, field: string): void {
  if (typeof e[field] !== "boolean") {
    throw new EventValidationError(`Field '${field}' must be a boolean`);
  }
}

function requireRiskLevel(e: Record<string, unknown>, field: string): void {
  if (typeof e[field] !== "string" || !VALID_RISK_LEVELS.has(e[field] as string)) {
    throw new EventValidationError(
      `Field '${field}' must be one of: ${[...VALID_RISK_LEVELS].join(", ")}`
    );
  }
}

/** Build a minimal valid event envelope. */
export function makeEnvelope(orgId?: string, demo = false): EventEnvelope {
  return {
    timestamp: new Date().toISOString(),
    orgId,
    demo
  };
}
