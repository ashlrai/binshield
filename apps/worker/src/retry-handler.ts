/**
 * Retry Handler — Dead-Letter Queue processor for failed scans.
 *
 * The worker calls `startRetryProcessor()` to begin polling the
 * `FailedScanQueue` for scans that need to be retried.
 *
 * Exponential backoff schedule (seconds):
 *   attempt 1 →  1 s
 *   attempt 2 →  4 s
 *   attempt 3 → 16 s
 *   attempt 4 → 60 s
 *   attempt 5 → 300 s (5 min) — then abandoned
 *
 * On success the entry is removed from the failed queue and a
 * `retry_succeeded` row is appended to `scan_audit_log`.
 *
 * All retry events are written to `scan_audit_log` for compliance.
 */

import type { BinShieldRepository, FailedScanEntry } from "../../api/src/lib/repository";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Exponential backoff delays in milliseconds (index = attempt - 1). */
export const RETRY_BACKOFF_MS = [1_000, 4_000, 16_000, 60_000, 300_000] as const;

/** Maximum retry attempts before a scan is permanently abandoned. */
export const MAX_RETRY_ATTEMPTS = 5;

/** How often the retry processor polls the FailedScanQueue (ms). */
const POLL_INTERVAL_MS = 5_000;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface RetryProcessorOptions {
  /** Repository to read/write the FailedScanQueue and audit log. */
  repository: BinShieldRepository;
  /**
   * Callback that actually attempts to re-run the scan.
   * Returns true on success, throws or returns false on failure.
   */
  runScan: (entry: FailedScanEntry, retryAttempt: number) => Promise<boolean>;
  /** Override poll interval for testing. */
  pollIntervalMs?: number;
  /** Override max retries for testing. */
  maxRetries?: number;
}

export interface RetryProcessorHandle {
  stop(): void;
}

// ---------------------------------------------------------------------------
// Backoff helper
// ---------------------------------------------------------------------------

/**
 * Compute the ISO timestamp for the next retry given a (1-based) failure count.
 */
export function computeNextRetryAt(failureCount: number): string {
  const delayMs = RETRY_BACKOFF_MS[Math.min(failureCount - 1, RETRY_BACKOFF_MS.length - 1)] ?? 300_000;
  return new Date(Date.now() + delayMs).toISOString();
}

// ---------------------------------------------------------------------------
// Core processor
// ---------------------------------------------------------------------------

/**
 * Process a single FailedScanEntry: attempt the scan, update the DLQ row,
 * and write compliance audit-log entries.
 *
 * Returns `true` if the scan succeeded, `false` if it failed again.
 */
export async function processRetry(
  entry: FailedScanEntry,
  repository: BinShieldRepository,
  runScan: (entry: FailedScanEntry, retryAttempt: number) => Promise<boolean>,
  maxRetries = MAX_RETRY_ATTEMPTS
): Promise<boolean> {
  const retryAttempt = entry.failureCount + 1;

  // Log: retry_attempted
  await repository.appendScanAuditLog({
    scanId: entry.scanId,
    orgId: entry.orgId,
    eventType: "retry_attempted",
    retryAttempt,
    details: {
      ecosystem: entry.ecosystem,
      packageName: entry.packageName,
      version: entry.version,
      previousError: entry.errorReason
    }
  });

  let succeeded = false;
  let errorMessage = "unknown";

  try {
    succeeded = await runScan(entry, retryAttempt);
  } catch (err) {
    errorMessage = err instanceof Error ? err.message : String(err);
    succeeded = false;
  }

  if (succeeded) {
    // Mark DLQ entry resolved
    await repository.resolveFailedScan(entry.scanId);

    // Log: retry_succeeded
    await repository.appendScanAuditLog({
      scanId: entry.scanId,
      orgId: entry.orgId,
      eventType: "retry_succeeded",
      retryAttempt,
      details: {
        ecosystem: entry.ecosystem,
        packageName: entry.packageName,
        version: entry.version
      }
    });

    console.info(
      `[BinShield/RetryHandler] Retry #${retryAttempt} succeeded for ` +
      `${entry.ecosystem}/${entry.packageName}@${entry.version} (scanId=${entry.scanId})`
    );
    return true;
  }

  // Retry failed — update failure count and schedule next attempt
  const newFailureCount = entry.failureCount + 1;
  const abandoned = newFailureCount >= maxRetries;

  await repository.upsertFailedScan({
    scanId: entry.scanId,
    jobId: entry.jobId,
    orgId: entry.orgId,
    ecosystem: entry.ecosystem,
    packageName: entry.packageName,
    version: entry.version,
    errorReason: errorMessage,
    failureCount: newFailureCount,
    lastAttemptAt: new Date().toISOString(),
    nextRetryAt: abandoned ? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString() : computeNextRetryAt(newFailureCount),
    status: abandoned ? "abandoned" : "retrying",
    metadata: {
      ...entry.metadata,
      retryAttempt,
      lastError: errorMessage
    }
  });

  // Log: scan_failed
  await repository.appendScanAuditLog({
    scanId: entry.scanId,
    orgId: entry.orgId,
    eventType: "scan_failed",
    retryAttempt,
    details: {
      ecosystem: entry.ecosystem,
      packageName: entry.packageName,
      version: entry.version,
      errorReason: errorMessage,
      failureCount: newFailureCount,
      abandoned
    }
  });

  if (abandoned) {
    await repository.markFailedScanAbandoned(entry.scanId);

    // Log: scan_abandoned
    await repository.appendScanAuditLog({
      scanId: entry.scanId,
      orgId: entry.orgId,
      eventType: "scan_abandoned",
      retryAttempt,
      details: {
        ecosystem: entry.ecosystem,
        packageName: entry.packageName,
        version: entry.version,
        totalFailures: newFailureCount
      }
    });

    // Log: alert_sent (placeholder — wire to email/webhook as needed)
    await repository.appendScanAuditLog({
      scanId: entry.scanId,
      orgId: entry.orgId,
      eventType: "alert_sent",
      retryAttempt,
      details: { alertChannel: "console", orgId: entry.orgId }
    });

    console.warn(
      `[BinShield/RetryHandler] Scan permanently abandoned after ${newFailureCount} attempts: ` +
      `${entry.ecosystem}/${entry.packageName}@${entry.version} (scanId=${entry.scanId}, org=${entry.orgId}). ` +
      "Alert emitted — configure email/webhook notification channel for delivery."
    );
  } else {
    console.warn(
      `[BinShield/RetryHandler] Retry #${retryAttempt} failed for ` +
      `${entry.ecosystem}/${entry.packageName}@${entry.version} (scanId=${entry.scanId}). ` +
      `Next attempt scheduled at ${computeNextRetryAt(newFailureCount)}`
    );
  }

  return false;
}

// ---------------------------------------------------------------------------
// Long-running poll loop
// ---------------------------------------------------------------------------

/**
 * Start the retry processor.  Polls the FailedScanQueue every `pollIntervalMs`
 * and processes any due entries.
 *
 * Returns a handle with a `stop()` method to halt the loop (useful in tests).
 */
export function startRetryProcessor(options: RetryProcessorOptions): RetryProcessorHandle {
  const { repository, runScan } = options;
  const pollMs = options.pollIntervalMs ?? POLL_INTERVAL_MS;
  const maxRetries = options.maxRetries ?? MAX_RETRY_ATTEMPTS;

  let running = true;
  let pollHandle: ReturnType<typeof setTimeout> | undefined;

  async function tick(): Promise<void> {
    if (!running) return;
    try {
      const pending = await repository.listPendingRetries(10);
      for (const entry of pending) {
        if (!running) break;
        await processRetry(entry, repository, runScan, maxRetries);
      }
    } catch (err) {
      console.error(
        "[BinShield/RetryHandler] Poll tick error:",
        err instanceof Error ? err.message : err
      );
    }
    if (running) {
      pollHandle = setTimeout(() => { void tick(); }, pollMs);
    }
  }

  // Start first tick immediately
  pollHandle = setTimeout(() => { void tick(); }, pollMs);

  return {
    stop() {
      running = false;
      if (pollHandle !== undefined) {
        clearTimeout(pollHandle);
        pollHandle = undefined;
      }
    }
  };
}
