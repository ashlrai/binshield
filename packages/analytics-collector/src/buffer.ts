/**
 * In-memory event buffer with configurable capacity and Supabase batch flush.
 *
 * Design:
 *  - Events are appended to a circular/capped ring buffer (oldest evicted on
 *    overflow rather than throwing, to keep the hot path non-blocking).
 *  - A flush is triggered automatically when the buffer reaches
 *    `autoFlushThreshold` events, or on an explicit `flush()` call.
 *  - In demo mode all flushes are no-ops (events are discarded, not written
 *    to Supabase) so local dev never hits the DB.
 */

import type { AnalyticsEvent } from "./schema";

// ---------------------------------------------------------------------------
// Supabase flush adapter (thin interface so it can be swapped in tests)
// ---------------------------------------------------------------------------

export interface SupabaseFlushAdapter {
  insertBatch(events: AnalyticsEvent[]): Promise<void>;
}

/** Real Supabase adapter that posts to the `analytics_events` table. */
export class SupabaseAdapter implements SupabaseFlushAdapter {
  constructor(
    private readonly supabaseUrl: string,
    private readonly serviceRoleKey: string
  ) {}

  async insertBatch(events: AnalyticsEvent[]): Promise<void> {
    if (events.length === 0) return;

    const rows = events.map((e) => ({
      event_type: e.type,
      org_id: e.orgId ?? null,
      demo: e.demo,
      timestamp: e.timestamp,
      payload: e
    }));

    const res = await fetch(
      `${this.supabaseUrl.replace(/\/$/, "")}/rest/v1/analytics_events`,
      {
        method: "POST",
        headers: {
          apikey: this.serviceRoleKey,
          authorization: `Bearer ${this.serviceRoleKey}`,
          "content-type": "application/json",
          Prefer: "return=minimal"
        },
        body: JSON.stringify(rows)
      }
    );

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`Supabase batch insert failed (${res.status}): ${text}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Buffer options
// ---------------------------------------------------------------------------

export interface EventBufferOptions {
  /**
   * Maximum number of events to hold before the oldest events are evicted.
   * Default: 1000.
   */
  maxSize?: number;
  /**
   * Number of buffered events that triggers an automatic background flush.
   * Must be ≤ maxSize. Default: 100.
   */
  autoFlushThreshold?: number;
  /**
   * Supabase adapter used for batch writes. When undefined, flushes are
   * no-ops (useful for tests and demo mode).
   */
  adapter?: SupabaseFlushAdapter;
  /**
   * When true, flush calls are always no-ops regardless of adapter presence.
   * Default: false.
   */
  demoMode?: boolean;
  /**
   * Called when a background auto-flush fails. Default: console.error.
   */
  onFlushError?: (err: Error) => void;
}

// ---------------------------------------------------------------------------
// EventBuffer
// ---------------------------------------------------------------------------

export class EventBuffer {
  private readonly buffer: AnalyticsEvent[] = [];
  private readonly maxSize: number;
  private readonly autoFlushThreshold: number;
  private readonly adapter: SupabaseFlushAdapter | undefined;
  private readonly demoMode: boolean;
  private readonly onFlushError: (err: Error) => void;

  /** Total events ever appended (including evicted and flushed). */
  private _totalAppended = 0;
  /** Total events successfully flushed to Supabase. */
  private _totalFlushed = 0;
  /** Total events evicted due to buffer overflow. */
  private _totalEvicted = 0;
  /** Whether a flush is currently in progress. */
  private _flushing = false;

  constructor(options: EventBufferOptions = {}) {
    this.maxSize = options.maxSize ?? 1000;
    // autoFlushThreshold is intentionally NOT clamped to maxSize — callers
    // can set it higher than maxSize to effectively disable auto-flush.
    this.autoFlushThreshold = options.autoFlushThreshold ?? 100;
    this.adapter = options.adapter;
    this.demoMode = options.demoMode ?? false;
    this.onFlushError = options.onFlushError ?? ((err) => console.error("[analytics-collector] flush error:", err.message));

    if (this.maxSize < 1) throw new RangeError("maxSize must be >= 1");
    if (this.autoFlushThreshold < 1) throw new RangeError("autoFlushThreshold must be >= 1");
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  /** Append an event to the buffer. Evicts oldest event on overflow. */
  append(event: AnalyticsEvent): void {
    this._totalAppended++;

    if (this.buffer.length >= this.maxSize) {
      this.buffer.shift(); // evict oldest
      this._totalEvicted++;
    }

    this.buffer.push(event);

    // Trigger background flush when threshold is reached
    if (this.buffer.length >= this.autoFlushThreshold && !this._flushing) {
      void this._backgroundFlush();
    }
  }

  /**
   * Drain the buffer and write all events to Supabase.
   *
   * Returns the number of events flushed. In demo mode always returns 0.
   * Throws if the Supabase write fails (callers should handle accordingly).
   */
  async flush(): Promise<number> {
    if (this.demoMode || !this.adapter) {
      this.buffer.length = 0;
      return 0;
    }

    const batch = this.buffer.splice(0);
    if (batch.length === 0) return 0;

    await this.adapter.insertBatch(batch);
    this._totalFlushed += batch.length;
    return batch.length;
  }

  /** Current number of events waiting in the buffer. */
  get size(): number {
    return this.buffer.length;
  }

  /** Snapshot of all buffered events (read-only copy). */
  snapshot(): readonly AnalyticsEvent[] {
    return [...this.buffer];
  }

  /** Cumulative stats since construction. */
  stats(): {
    totalAppended: number;
    totalFlushed: number;
    totalEvicted: number;
    currentSize: number;
  } {
    return {
      totalAppended: this._totalAppended,
      totalFlushed: this._totalFlushed,
      totalEvicted: this._totalEvicted,
      currentSize: this.buffer.length
    };
  }

  // -------------------------------------------------------------------------
  // Internal helpers
  // -------------------------------------------------------------------------

  private async _backgroundFlush(): Promise<void> {
    if (this._flushing) return;
    this._flushing = true;
    try {
      await this.flush();
    } catch (err) {
      this.onFlushError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      this._flushing = false;
    }
  }
}
