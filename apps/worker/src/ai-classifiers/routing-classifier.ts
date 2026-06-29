/**
 * RoutingClassifierProvider — latency-aware, cost-optimised AI classifier router.
 *
 * Routing rules (spec M49):
 *   1. Try providers in the configured order (default: grok → gemini → claude).
 *   2. If the primary provider's last LATENCY_WINDOW_SIZE calls all exceeded
 *      LATENCY_SLA_MS, skip it and try the next provider immediately.
 *   3. On any provider failure the next provider in the fallback chain is tried.
 *   4. A/B accuracy metrics are recorded so callers can compare model quality.
 *
 * Configuration via environment variables:
 *   AI_CLASSIFIER_PROVIDER  — name of the preferred primary provider
 *                             (grok | gemini | claude); default "grok"
 *   AI_FALLBACK_ORDER       — comma-separated provider names; default "grok,gemini,claude"
 */

import type { ClassifiedArtifact, ClassifierProvider } from "../types";
import type { DecompiledArtifact, FingerprintedArtifact, WorkerScanRequest } from "../types";
import type { AIClassifierProvider, ClassifierUsageRepository } from "./types";
import {
  ENV_AI_CLASSIFIER_PROVIDER,
  ENV_AI_FALLBACK_ORDER,
  LATENCY_SLA_MS,
  LATENCY_WINDOW_SIZE,
} from "./types";

// ---------------------------------------------------------------------------
// A/B accuracy metrics
// ---------------------------------------------------------------------------

export interface ABMetricRecord {
  model: string;
  latencyMs: number;
  success: boolean;
  wasRoutedAsFallback: boolean;
  classifiedAt: string;
}

// ---------------------------------------------------------------------------
// Per-provider latency window
// ---------------------------------------------------------------------------

class LatencyWindow {
  private readonly samples: number[] = [];

  record(ms: number): void {
    this.samples.push(ms);
    if (this.samples.length > LATENCY_WINDOW_SIZE) {
      this.samples.shift();
    }
  }

  /** True if we have a full window and all samples exceeded the SLA. */
  isBreachingSlA(slaMs: number): boolean {
    return (
      this.samples.length >= LATENCY_WINDOW_SIZE &&
      this.samples.every((s) => s > slaMs)
    );
  }

  getSamples(): readonly number[] {
    return this.samples;
  }
}

// ---------------------------------------------------------------------------
// RoutingClassifierProvider
// ---------------------------------------------------------------------------

export class RoutingClassifierProvider implements ClassifierProvider {
  readonly name = "routing-classifier";

  private readonly providers: Map<string, AIClassifierProvider>;
  private readonly order: string[];
  private readonly latencyWindows = new Map<string, LatencyWindow>();
  private readonly abMetrics: ABMetricRecord[] = [];
  private readonly usageRepo?: ClassifierUsageRepository;

  constructor(options: {
    providers: AIClassifierProvider[];
    usageRepository?: ClassifierUsageRepository;
    /**
     * Override fallback order. When omitted the order of `providers` is used,
     * optionally overridden by the AI_FALLBACK_ORDER env var.
     */
    fallbackOrder?: string[];
  }) {
    this.providers = new Map(options.providers.map((p) => [p.name, p]));
    this.usageRepo = options.usageRepository;

    // Resolve order: explicit > env > declaration order
    const envOrder = process.env[ENV_AI_FALLBACK_ORDER];
    if (options.fallbackOrder) {
      this.order = options.fallbackOrder;
    } else if (envOrder) {
      this.order = envOrder.split(",").map((s) => s.trim()).filter(Boolean);
    } else {
      this.order = options.providers.map((p) => p.name);
    }

    // Apply primary provider override from env
    const primary = process.env[ENV_AI_CLASSIFIER_PROVIDER];
    if (primary && this.providers.has(primary) && this.order[0] !== primary) {
      this.order = [primary, ...this.order.filter((n) => n !== primary)];
    }

    for (const name of this.providers.keys()) {
      this.latencyWindows.set(name, new LatencyWindow());
    }
  }

  async classify(input: {
    packageRequest: WorkerScanRequest;
    packageRoot: string;
    artifact: FingerprintedArtifact;
    decompiled: DecompiledArtifact;
  }): Promise<ClassifiedArtifact> {
    const errors: string[] = [];
    let isFallback = false;

    for (const providerName of this.order) {
      const provider = this.providers.get(providerName);
      if (!provider) {
        errors.push(`${providerName}: not registered`);
        isFallback = true;
        continue;
      }

      // Skip provider if it is consistently breaching the latency SLA
      const window = this.latencyWindows.get(providerName)!;
      if (window.isBreachingSlA(LATENCY_SLA_MS)) {
        console.warn(
          `[routing-classifier] ${providerName} breached latency SLA ` +
            `(${LATENCY_SLA_MS}ms) for last ${LATENCY_WINDOW_SIZE} calls — skipping.`
        );
        errors.push(`${providerName}: latency SLA breach, skipped`);
        isFallback = true;
        continue;
      }

      const start = Date.now();
      try {
        const result = await provider.classify(input);
        const latencyMs = Date.now() - start;

        window.record(latencyMs);
        this.recordABMetric({
          model: provider.model,
          latencyMs,
          success: true,
          wasRoutedAsFallback: isFallback,
        });

        console.info(
          `[routing-classifier] Used ${providerName} (model: ${provider.model}), ` +
            `latency: ${latencyMs}ms, fallback: ${isFallback}`
        );

        return result;
      } catch (error) {
        const latencyMs = Date.now() - start;
        const message = error instanceof Error ? error.message : String(error);

        window.record(latencyMs);
        this.recordABMetric({
          model: provider.model,
          latencyMs,
          success: false,
          wasRoutedAsFallback: isFallback,
        });

        errors.push(`${providerName}: ${message}`);
        console.warn(`[routing-classifier] ${providerName} failed: ${message}`);
        isFallback = true;
      }
    }

    throw new Error(
      `All AI classifiers failed. Errors: ${errors.join("; ")}`
    );
  }

  // -------------------------------------------------------------------------
  // Observability
  // -------------------------------------------------------------------------

  getABMetrics(): readonly ABMetricRecord[] {
    return this.abMetrics;
  }

  getLatencyWindow(providerName: string): readonly number[] {
    return this.latencyWindows.get(providerName)?.getSamples() ?? [];
  }

  /** Aggregate A/B accuracy-parity stats per model. */
  getABSummary(): Record<string, { calls: number; successRate: number; avgLatencyMs: number; fallbackCalls: number }> {
    const byModel: Record<string, { calls: number; successes: number; totalLatency: number; fallbackCalls: number }> = {};

    for (const record of this.abMetrics) {
      if (!byModel[record.model]) {
        byModel[record.model] = { calls: 0, successes: 0, totalLatency: 0, fallbackCalls: 0 };
      }
      byModel[record.model].calls += 1;
      byModel[record.model].totalLatency += record.latencyMs;
      if (record.success) byModel[record.model].successes += 1;
      if (record.wasRoutedAsFallback) byModel[record.model].fallbackCalls += 1;
    }

    const summary: Record<string, { calls: number; successRate: number; avgLatencyMs: number; fallbackCalls: number }> = {};
    for (const [model, stats] of Object.entries(byModel)) {
      summary[model] = {
        calls: stats.calls,
        successRate: stats.calls > 0 ? stats.successes / stats.calls : 0,
        avgLatencyMs: stats.calls > 0 ? Math.round(stats.totalLatency / stats.calls) : 0,
        fallbackCalls: stats.fallbackCalls,
      };
    }
    return summary;
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  private recordABMetric(fields: Omit<ABMetricRecord, "classifiedAt">): void {
    this.abMetrics.push({ ...fields, classifiedAt: new Date().toISOString() });
  }
}
