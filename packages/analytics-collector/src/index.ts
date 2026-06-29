// Public API for @binshield/analytics-collector

export type {
  AnalyticsEvent,
  AnalyticsEventType,
  EventEnvelope,
  ScanCompletedEvent,
  ScanCompletedPayload,
  ScanFailedEvent,
  ScanFailedPayload,
  AlertTriggeredEvent,
  AlertTriggeredPayload,
  UserActionEvent,
  UserActionPayload,
  UserActionName
} from "./schema";

export { validateEvent, makeEnvelope, EventValidationError } from "./schema";

export type { SupabaseFlushAdapter, EventBufferOptions } from "./buffer";
export { EventBuffer, SupabaseAdapter } from "./buffer";

export type { CollectorOptions } from "./collector";
export {
  AnalyticsCollector,
  collector,
  getCollector,
  setCollector,
  resetCollector
} from "./collector";

export type { DashboardKPIs, TopPackageEntry } from "./aggregator";
export { DashboardAggregator, aggregator } from "./aggregator";
