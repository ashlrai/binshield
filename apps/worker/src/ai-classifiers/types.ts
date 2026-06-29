/**
 * Shared types for the AI classifier layer.
 *
 * `AIClassifierProvider` extends `ClassifierProvider` with a `model` field so
 * callers can identify which model produced a result and route by latency/cost.
 */

import type { ClassifiedArtifact, ClassifierProvider, DecompiledArtifact, FingerprintedArtifact, WorkerScanRequest } from "../types";

// ---------------------------------------------------------------------------
// Core interface
// ---------------------------------------------------------------------------

export interface AIClassifierProvider extends ClassifierProvider {
  /** Fully-qualified model identifier, e.g. "gemini-2.0-flash" */
  readonly model: string;
}

// ---------------------------------------------------------------------------
// Cost constants (USD per 1 000 tokens — input / output)
// ---------------------------------------------------------------------------

export interface ModelCostConfig {
  /** Cost per 1 000 input tokens in USD */
  inputPer1kTokens: number;
  /** Cost per 1 000 output tokens in USD */
  outputPer1kTokens: number;
}

export const MODEL_COSTS: Record<string, ModelCostConfig> = {
  "grok-4.3": { inputPer1kTokens: 0.005, outputPer1kTokens: 0.015 },
  "gemini-2.0-flash": { inputPer1kTokens: 0.00035, outputPer1kTokens: 0.00105 },
  "claude-opus-4-1": { inputPer1kTokens: 0.015, outputPer1kTokens: 0.075 },
};

// ---------------------------------------------------------------------------
// Usage tracking
// ---------------------------------------------------------------------------

export interface ClassifierUsageRecord {
  model: string;
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  estimatedCostUsd: number;
  classifiedAt: string;
}

/**
 * In-memory repository for per-model token and cost tracking.
 *
 * In production the daemon can replace or extend this with a persistent store.
 * `trackClassifierUsage(model, tokens)` is the primary write path; callers
 * read aggregated stats via `getUsageSummary()`.
 */
export class ClassifierUsageRepository {
  private readonly records: ClassifierUsageRecord[] = [];

  trackClassifierUsage(
    model: string,
    tokens: { promptTokens: number; completionTokens: number; totalTokens: number }
  ): ClassifierUsageRecord {
    const costs = MODEL_COSTS[model] ?? { inputPer1kTokens: 0, outputPer1kTokens: 0 };
    const estimatedCostUsd =
      (tokens.promptTokens / 1000) * costs.inputPer1kTokens +
      (tokens.completionTokens / 1000) * costs.outputPer1kTokens;

    const record: ClassifierUsageRecord = {
      model,
      promptTokens: tokens.promptTokens,
      completionTokens: tokens.completionTokens,
      totalTokens: tokens.totalTokens,
      estimatedCostUsd,
      classifiedAt: new Date().toISOString(),
    };

    this.records.push(record);
    return record;
  }

  getUsageSummary(): Record<string, { calls: number; totalTokens: number; totalCostUsd: number }> {
    const summary: Record<string, { calls: number; totalTokens: number; totalCostUsd: number }> = {};

    for (const record of this.records) {
      if (!summary[record.model]) {
        summary[record.model] = { calls: 0, totalTokens: 0, totalCostUsd: 0 };
      }
      summary[record.model].calls += 1;
      summary[record.model].totalTokens += record.totalTokens;
      summary[record.model].totalCostUsd += record.estimatedCostUsd;
    }

    return summary;
  }

  getAllRecords(): readonly ClassifierUsageRecord[] {
    return this.records;
  }

  clear(): void {
    this.records.length = 0;
  }
}

// ---------------------------------------------------------------------------
// Routing config env keys
// ---------------------------------------------------------------------------

/** Env var: primary AI classifier provider. Defaults to "grok". */
export const ENV_AI_CLASSIFIER_PROVIDER = "AI_CLASSIFIER_PROVIDER";

/**
 * Env var: comma-separated fallback order.
 * E.g. "grok,gemini,claude" (default) or "gemini,claude".
 */
export const ENV_AI_FALLBACK_ORDER = "AI_FALLBACK_ORDER";

/** Latency SLA in ms — if grok p3 average exceeds this, route to gemini. */
export const LATENCY_SLA_MS = 5_000;

/** Number of recent calls to track for latency windowing. */
export const LATENCY_WINDOW_SIZE = 3;

// ---------------------------------------------------------------------------
// Shared response types (OpenAI-compatible chat completions)
// ---------------------------------------------------------------------------

export interface ChatCompletionUsage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
}

export interface ChatCompletionResponse {
  model: string;
  choices: Array<{ message: { content: string | null } }>;
  usage?: ChatCompletionUsage;
}

// ---------------------------------------------------------------------------
// Input contract (same as ClassifierProvider.classify but exported)
// ---------------------------------------------------------------------------

export interface ClassifyInput {
  packageRequest: WorkerScanRequest;
  packageRoot: string;
  artifact: FingerprintedArtifact;
  decompiled: DecompiledArtifact;
}

export type { ClassifiedArtifact };
