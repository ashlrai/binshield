/**
 * Tests for the AI classifier layer:
 *   - ClassifierUsageRepository cost tracking
 *   - GeminiClassifier stubbed API
 *   - ClaudeClassifier stubbed API
 *   - RoutingClassifierProvider routing / fallback / latency-SLA logic
 *   - GrokAIClassifierAdapter model field
 *   - env validation helpers (AI_CLASSIFIER_PROVIDER / AI_FALLBACK_ORDER)
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { emptyBehaviorSummary } from "@binshield/analysis-types";

import type { ClassifiedArtifact, ClassifierProvider } from "../types";
import type { DecompiledArtifact, FingerprintedArtifact, WorkerScanRequest } from "../types";
import { GeminiClassifier } from "./gemini-classifier";
import { ClaudeClassifier } from "./claude-classifier";
import { GrokAIClassifierAdapter } from "./grok-adapter";
import { RoutingClassifierProvider } from "./routing-classifier";
import {
  ClassifierUsageRepository,
  MODEL_COSTS,
  LATENCY_SLA_MS,
  LATENCY_WINDOW_SIZE,
  ENV_AI_CLASSIFIER_PROVIDER,
  ENV_AI_FALLBACK_ORDER,
} from "./types";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeArtifact(): FingerprintedArtifact {
  return {
    filename: "addon.node",
    absolutePath: "/tmp/addon.node",
    relativePath: "addon.node",
    fileSize: 4096,
    sha256: "deadbeef01234567",
    format: "ELF",
    architecture: "x86_64",
    kind: "native-addon",
    bytes: new Uint8Array(0),
    strings: [],
    interestingStrings: [],
  };
}

function makeDecompiled(): DecompiledArtifact {
  return {
    pseudoSource: "int main() { return 0; }",
    imports: ["connect", "open"],
    strings: ["https://example.com"],
    functionCount: 3,
    callTargets: ["network_request"],
    confidence: 0.8,
  };
}

function makeRequest(): WorkerScanRequest {
  return {
    ecosystem: "npm",
    packageName: "test-pkg",
    version: "1.0.0",
  };
}

function makeClassifyInput() {
  return {
    packageRequest: makeRequest(),
    packageRoot: "/tmp/test-pkg",
    artifact: makeArtifact(),
    decompiled: makeDecompiled(),
  };
}

const STUB_RESULT: ClassifiedArtifact = {
  summary: "Stub result",
  explanation: "Stubbed for tests",
  sourceMatchConfidence: "medium",
  behaviors: emptyBehaviorSummary(),
  findings: [],
  riskNotes: [],
};

const VALID_JSON_RESPONSE = JSON.stringify({
  summary: "Test binary — low risk",
  explanation: "No suspicious behaviour detected.",
  sourceMatchConfidence: "high",
  behaviors: {
    network: { detected: true, details: ["outbound HTTP"] },
    filesystem: { detected: false, details: [] },
    process: { detected: false, details: [] },
    crypto: { detected: false, details: [] },
    obfuscation: { detected: false, details: [] },
    dataExfiltration: { detected: false, details: [] },
  },
  findings: [
    {
      severity: "medium",
      title: "Network access",
      description: "Makes outbound HTTP connections.",
      location: "main",
      recommendation: "Verify destinations.",
    },
  ],
  riskNotes: ["Low overall risk."],
});

// ---------------------------------------------------------------------------
// ClassifierUsageRepository
// ---------------------------------------------------------------------------

describe("ClassifierUsageRepository", () => {
  it("tracks usage and computes cost correctly for gemini-2.0-flash", () => {
    const repo = new ClassifierUsageRepository();
    const record = repo.trackClassifierUsage("gemini-2.0-flash", {
      promptTokens: 1000,
      completionTokens: 500,
      totalTokens: 1500,
    });

    const costs = MODEL_COSTS["gemini-2.0-flash"]!;
    const expectedCost =
      (1000 / 1000) * costs.inputPer1kTokens + (500 / 1000) * costs.outputPer1kTokens;

    expect(record.model).toBe("gemini-2.0-flash");
    expect(record.totalTokens).toBe(1500);
    expect(record.estimatedCostUsd).toBeCloseTo(expectedCost, 8);
    expect(repo.getAllRecords()).toHaveLength(1);
  });

  it("tracks usage and computes cost correctly for claude-opus-4-1", () => {
    const repo = new ClassifierUsageRepository();
    repo.trackClassifierUsage("claude-opus-4-1", {
      promptTokens: 2000,
      completionTokens: 800,
      totalTokens: 2800,
    });

    const summary = repo.getUsageSummary();
    expect(summary["claude-opus-4-1"]).toBeDefined();
    expect(summary["claude-opus-4-1"].calls).toBe(1);
    expect(summary["claude-opus-4-1"].totalTokens).toBe(2800);
    expect(summary["claude-opus-4-1"].totalCostUsd).toBeGreaterThan(0);
  });

  it("accumulates multiple calls per model", () => {
    const repo = new ClassifierUsageRepository();
    repo.trackClassifierUsage("gemini-2.0-flash", { promptTokens: 100, completionTokens: 50, totalTokens: 150 });
    repo.trackClassifierUsage("gemini-2.0-flash", { promptTokens: 200, completionTokens: 100, totalTokens: 300 });
    repo.trackClassifierUsage("claude-opus-4-1", { promptTokens: 500, completionTokens: 200, totalTokens: 700 });

    const summary = repo.getUsageSummary();
    expect(summary["gemini-2.0-flash"].calls).toBe(2);
    expect(summary["gemini-2.0-flash"].totalTokens).toBe(450);
    expect(summary["claude-opus-4-1"].calls).toBe(1);
  });

  it("handles unknown model without crashing (zero cost)", () => {
    const repo = new ClassifierUsageRepository();
    const record = repo.trackClassifierUsage("unknown-model-xyz", {
      promptTokens: 100,
      completionTokens: 50,
      totalTokens: 150,
    });
    expect(record.estimatedCostUsd).toBe(0);
  });

  it("clear() resets all records", () => {
    const repo = new ClassifierUsageRepository();
    repo.trackClassifierUsage("gemini-2.0-flash", { promptTokens: 100, completionTokens: 50, totalTokens: 150 });
    expect(repo.getAllRecords()).toHaveLength(1);
    repo.clear();
    expect(repo.getAllRecords()).toHaveLength(0);
  });

  it("MODEL_COSTS contains expected models", () => {
    expect(MODEL_COSTS["grok-4.3"]).toBeDefined();
    expect(MODEL_COSTS["gemini-2.0-flash"]).toBeDefined();
    expect(MODEL_COSTS["claude-opus-4-1"]).toBeDefined();
    // Claude should cost more per output token than Gemini
    expect(MODEL_COSTS["claude-opus-4-1"].outputPer1kTokens).toBeGreaterThan(
      MODEL_COSTS["gemini-2.0-flash"].outputPer1kTokens
    );
  });
});

// ---------------------------------------------------------------------------
// GeminiClassifier — stubbed fetch
// ---------------------------------------------------------------------------

describe("GeminiClassifier", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("throws when GEMINI_API_KEY is not configured", async () => {
    const classifier = new GeminiClassifier({ apiKey: "" });
    await expect(classifier.classify(makeClassifyInput())).rejects.toThrow(
      "GEMINI_API_KEY is not configured"
    );
  });

  it("parses a valid JSON response correctly", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        model: "gemini-2.0-flash",
        choices: [{ message: { content: VALID_JSON_RESPONSE } }],
        usage: { prompt_tokens: 100, completion_tokens: 50, total_tokens: 150 },
      }),
    });
    vi.stubGlobal("fetch", mockFetch);

    const repo = new ClassifierUsageRepository();
    const classifier = new GeminiClassifier({ apiKey: "test-key", usageRepository: repo });
    const result = await classifier.classify(makeClassifyInput());

    expect(result.summary).toBe("Test binary — low risk");
    expect(result.behaviors.network.detected).toBe(true);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("medium");
    expect(repo.getAllRecords()).toHaveLength(1);
    expect(repo.getAllRecords()[0].model).toBe("gemini-2.0-flash");
  });

  it("tracks usage to the repository on success", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        model: "gemini-2.0-flash",
        choices: [{ message: { content: VALID_JSON_RESPONSE } }],
        usage: { prompt_tokens: 200, completion_tokens: 80, total_tokens: 280 },
      }),
    });
    vi.stubGlobal("fetch", mockFetch);

    const repo = new ClassifierUsageRepository();
    const classifier = new GeminiClassifier({ apiKey: "test-key", usageRepository: repo });
    await classifier.classify(makeClassifyInput());

    const records = repo.getAllRecords();
    expect(records).toHaveLength(1);
    expect(records[0].promptTokens).toBe(200);
    expect(records[0].completionTokens).toBe(80);
    expect(records[0].totalTokens).toBe(280);
    expect(records[0].estimatedCostUsd).toBeGreaterThan(0);
  });

  it("throws on non-OK HTTP response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 429,
        statusText: "Too Many Requests",
        text: async () => "rate limited",
      })
    );
    const classifier = new GeminiClassifier({ apiKey: "test-key" });
    await expect(classifier.classify(makeClassifyInput())).rejects.toThrow("429");
  });

  it("throws on invalid JSON response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          model: "gemini-2.0-flash",
          choices: [{ message: { content: "not valid json{{" } }],
        }),
      })
    );
    const classifier = new GeminiClassifier({ apiKey: "test-key" });
    await expect(classifier.classify(makeClassifyInput())).rejects.toThrow(
      "invalid JSON"
    );
  });

  it("throws when response is missing required fields", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          model: "gemini-2.0-flash",
          choices: [{ message: { content: JSON.stringify({ riskNotes: [] }) } }],
        }),
      })
    );
    const classifier = new GeminiClassifier({ apiKey: "test-key" });
    await expect(classifier.classify(makeClassifyInput())).rejects.toThrow(
      "missing required fields"
    );
  });

  it("has the correct model identifier", () => {
    const classifier = new GeminiClassifier({ apiKey: "k" });
    expect(classifier.model).toBe("gemini-2.0-flash");
  });

  it("uses a custom model when provided", () => {
    const classifier = new GeminiClassifier({ apiKey: "k", model: "gemini-pro" });
    expect(classifier.model).toBe("gemini-pro");
  });
});

// ---------------------------------------------------------------------------
// ClaudeClassifier — stubbed fetch
// ---------------------------------------------------------------------------

describe("ClaudeClassifier", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("throws when ANTHROPIC_API_KEY is not configured", async () => {
    const classifier = new ClaudeClassifier({ apiKey: "" });
    await expect(classifier.classify(makeClassifyInput())).rejects.toThrow(
      "ANTHROPIC_API_KEY is not configured"
    );
  });

  it("parses a valid JSON response from the Messages API", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        id: "msg_test",
        type: "message",
        role: "assistant",
        model: "claude-opus-4-1",
        content: [{ type: "text", text: VALID_JSON_RESPONSE }],
        stop_reason: "end_turn",
        usage: { input_tokens: 150, output_tokens: 60 },
      }),
    });
    vi.stubGlobal("fetch", mockFetch);

    const repo = new ClassifierUsageRepository();
    const classifier = new ClaudeClassifier({ apiKey: "test-key", usageRepository: repo });
    const result = await classifier.classify(makeClassifyInput());

    expect(result.summary).toBe("Test binary — low risk");
    expect(result.behaviors.network.detected).toBe(true);
    expect(result.sourceMatchConfidence).toBe("high");
    expect(repo.getAllRecords()).toHaveLength(1);
    expect(repo.getAllRecords()[0].model).toBe("claude-opus-4-1");
  });

  it("strips markdown code fences from Claude response", async () => {
    const fencedResponse = "```json\n" + VALID_JSON_RESPONSE + "\n```";
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          id: "msg_test",
          type: "message",
          role: "assistant",
          model: "claude-opus-4-1",
          content: [{ type: "text", text: fencedResponse }],
          stop_reason: "end_turn",
          usage: { input_tokens: 100, output_tokens: 50 },
        }),
      })
    );

    const classifier = new ClaudeClassifier({ apiKey: "test-key" });
    const result = await classifier.classify(makeClassifyInput());
    expect(result.summary).toBe("Test binary — low risk");
  });

  it("tracks usage with input_tokens + output_tokens from Messages API", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          id: "msg_test",
          type: "message",
          role: "assistant",
          model: "claude-opus-4-1",
          content: [{ type: "text", text: VALID_JSON_RESPONSE }],
          stop_reason: "end_turn",
          usage: { input_tokens: 300, output_tokens: 120 },
        }),
      })
    );

    const repo = new ClassifierUsageRepository();
    const classifier = new ClaudeClassifier({ apiKey: "test-key", usageRepository: repo });
    await classifier.classify(makeClassifyInput());

    const records = repo.getAllRecords();
    expect(records[0].promptTokens).toBe(300);
    expect(records[0].completionTokens).toBe(120);
    expect(records[0].totalTokens).toBe(420);
  });

  it("throws on non-OK HTTP response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 529,
        statusText: "Overloaded",
        text: async () => "overloaded",
      })
    );
    const classifier = new ClaudeClassifier({ apiKey: "test-key" });
    await expect(classifier.classify(makeClassifyInput())).rejects.toThrow("529");
  });

  it("has correct model identifier", () => {
    const classifier = new ClaudeClassifier({ apiKey: "k" });
    expect(classifier.model).toBe("claude-opus-4-1");
  });

  it("uses anthropic-version header", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        id: "msg_test",
        type: "message",
        role: "assistant",
        model: "claude-opus-4-1",
        content: [{ type: "text", text: VALID_JSON_RESPONSE }],
        stop_reason: "end_turn",
        usage: { input_tokens: 100, output_tokens: 40 },
      }),
    });
    vi.stubGlobal("fetch", mockFetch);

    const classifier = new ClaudeClassifier({ apiKey: "test-key" });
    await classifier.classify(makeClassifyInput());

    const callArgs = mockFetch.mock.calls[0];
    const headers = callArgs[1].headers as Record<string, string>;
    expect(headers["anthropic-version"]).toBeDefined();
    expect(headers["x-api-key"]).toBe("test-key");
  });
});

// ---------------------------------------------------------------------------
// GrokAIClassifierAdapter
// ---------------------------------------------------------------------------

describe("GrokAIClassifierAdapter", () => {
  it("exposes the model field from the constructor", () => {
    const inner: ClassifierProvider = {
      name: "grok-xai",
      classify: vi.fn().mockResolvedValue(STUB_RESULT),
    };
    const adapter = new GrokAIClassifierAdapter(inner, "grok-4.3");
    expect(adapter.model).toBe("grok-4.3");
    expect(adapter.name).toBe("grok-xai");
  });

  it("delegates classify() to the inner provider", async () => {
    const inner: ClassifierProvider = {
      name: "grok-xai",
      classify: vi.fn().mockResolvedValue(STUB_RESULT),
    };
    const adapter = new GrokAIClassifierAdapter(inner);
    const result = await adapter.classify(makeClassifyInput());
    expect(result).toBe(STUB_RESULT);
    expect(inner.classify).toHaveBeenCalledOnce();
  });

  it("propagates errors from the inner provider", async () => {
    const inner: ClassifierProvider = {
      name: "grok-xai",
      classify: vi.fn().mockRejectedValue(new Error("API down")),
    };
    const adapter = new GrokAIClassifierAdapter(inner);
    await expect(adapter.classify(makeClassifyInput())).rejects.toThrow("API down");
  });
});

// ---------------------------------------------------------------------------
// RoutingClassifierProvider
// ---------------------------------------------------------------------------

describe("RoutingClassifierProvider", () => {
  function makeAIProvider(name: string, model: string, result: ClassifiedArtifact | Error) {
    return {
      name,
      model,
      classify: vi.fn().mockImplementation(() =>
        result instanceof Error ? Promise.reject(result) : Promise.resolve(result)
      ),
    };
  }

  it("uses the first provider when it succeeds", async () => {
    const p1 = makeAIProvider("grok-xai", "grok-4.3", STUB_RESULT);
    const p2 = makeAIProvider("gemini-classifier", "gemini-2.0-flash", STUB_RESULT);
    const router = new RoutingClassifierProvider({ providers: [p1, p2] });

    const result = await router.classify(makeClassifyInput());
    expect(result).toBe(STUB_RESULT);
    expect(p1.classify).toHaveBeenCalledOnce();
    expect(p2.classify).not.toHaveBeenCalled();
  });

  it("falls back to the second provider when the first fails", async () => {
    const p1 = makeAIProvider("grok-xai", "grok-4.3", new Error("xAI down"));
    const p2 = makeAIProvider("gemini-classifier", "gemini-2.0-flash", STUB_RESULT);
    const router = new RoutingClassifierProvider({ providers: [p1, p2] });

    const result = await router.classify(makeClassifyInput());
    expect(result).toBe(STUB_RESULT);
    expect(p1.classify).toHaveBeenCalledOnce();
    expect(p2.classify).toHaveBeenCalledOnce();
  });

  it("falls back to the third provider when both prior fail", async () => {
    const p1 = makeAIProvider("grok-xai", "grok-4.3", new Error("xAI down"));
    const p2 = makeAIProvider("gemini-classifier", "gemini-2.0-flash", new Error("Gemini down"));
    const p3 = makeAIProvider("claude-classifier", "claude-opus-4-1", STUB_RESULT);
    const router = new RoutingClassifierProvider({ providers: [p1, p2, p3] });

    const result = await router.classify(makeClassifyInput());
    expect(result).toBe(STUB_RESULT);
    expect(p3.classify).toHaveBeenCalledOnce();
  });

  it("throws when all providers fail", async () => {
    const p1 = makeAIProvider("grok-xai", "grok-4.3", new Error("fail1"));
    const p2 = makeAIProvider("gemini-classifier", "gemini-2.0-flash", new Error("fail2"));
    const router = new RoutingClassifierProvider({ providers: [p1, p2] });

    await expect(router.classify(makeClassifyInput())).rejects.toThrow(
      "All AI classifiers failed"
    );
  });

  it("skips a provider after LATENCY_WINDOW_SIZE calls all exceed SLA", async () => {
    const slowResult: ClassifiedArtifact = { ...STUB_RESULT, summary: "slow result" };
    const fastResult: ClassifiedArtifact = { ...STUB_RESULT, summary: "fast result" };

    // p1 always succeeds but we'll manually prime its latency window
    const p1 = makeAIProvider("grok-xai", "grok-4.3", slowResult);
    const p2 = makeAIProvider("gemini-classifier", "gemini-2.0-flash", fastResult);
    const router = new RoutingClassifierProvider({ providers: [p1, p2] });

    // Prime the latency window by injecting fake slow samples
    const window = (router as unknown as { latencyWindows: Map<string, { record(ms: number): void; isBreachingSlA(sla: number): boolean }> })
      .latencyWindows.get("grok-xai")!;
    for (let i = 0; i < LATENCY_WINDOW_SIZE; i++) {
      window.record(LATENCY_SLA_MS + 1000);
    }

    const result = await router.classify(makeClassifyInput());
    // p1 should be skipped due to SLA breach, p2 used
    expect(result.summary).toBe("fast result");
    expect(p1.classify).not.toHaveBeenCalled();
    expect(p2.classify).toHaveBeenCalledOnce();
  });

  it("does not skip a provider if latency window is not full", async () => {
    const p1 = makeAIProvider("grok-xai", "grok-4.3", STUB_RESULT);
    const router = new RoutingClassifierProvider({ providers: [p1] });

    // Inject fewer samples than the window size
    const window = (router as unknown as { latencyWindows: Map<string, { record(ms: number): void }> })
      .latencyWindows.get("grok-xai")!;
    for (let i = 0; i < LATENCY_WINDOW_SIZE - 1; i++) {
      window.record(LATENCY_SLA_MS + 1000);
    }

    await router.classify(makeClassifyInput());
    expect(p1.classify).toHaveBeenCalledOnce();
  });

  it("records A/B metrics on success", async () => {
    const p1 = makeAIProvider("grok-xai", "grok-4.3", STUB_RESULT);
    const router = new RoutingClassifierProvider({ providers: [p1] });

    await router.classify(makeClassifyInput());
    const metrics = router.getABMetrics();
    expect(metrics).toHaveLength(1);
    expect(metrics[0].model).toBe("grok-4.3");
    expect(metrics[0].success).toBe(true);
    expect(metrics[0].wasRoutedAsFallback).toBe(false);
    expect(metrics[0].latencyMs).toBeGreaterThanOrEqual(0);
  });

  it("records fallback A/B metrics when primary fails", async () => {
    const p1 = makeAIProvider("grok-xai", "grok-4.3", new Error("fail"));
    const p2 = makeAIProvider("gemini-classifier", "gemini-2.0-flash", STUB_RESULT);
    const router = new RoutingClassifierProvider({ providers: [p1, p2] });

    await router.classify(makeClassifyInput());
    const metrics = router.getABMetrics();
    expect(metrics).toHaveLength(2);
    expect(metrics[0].success).toBe(false);
    expect(metrics[0].wasRoutedAsFallback).toBe(false);
    expect(metrics[1].success).toBe(true);
    expect(metrics[1].wasRoutedAsFallback).toBe(true);
  });

  it("getABSummary aggregates per-model stats", async () => {
    const p1 = makeAIProvider("grok-xai", "grok-4.3", STUB_RESULT);
    const router = new RoutingClassifierProvider({ providers: [p1] });

    await router.classify(makeClassifyInput());
    await router.classify(makeClassifyInput());

    const summary = router.getABSummary();
    expect(summary["grok-4.3"].calls).toBe(2);
    expect(summary["grok-4.3"].successRate).toBe(1);
    expect(summary["grok-4.3"].fallbackCalls).toBe(0);
  });

  it("respects AI_FALLBACK_ORDER env var", async () => {
    const original = process.env[ENV_AI_FALLBACK_ORDER];
    process.env[ENV_AI_FALLBACK_ORDER] = "gemini-classifier,grok-xai";

    const p1 = makeAIProvider("grok-xai", "grok-4.3", STUB_RESULT);
    const p2 = makeAIProvider("gemini-classifier", "gemini-2.0-flash", STUB_RESULT);
    const router = new RoutingClassifierProvider({ providers: [p1, p2] });

    await router.classify(makeClassifyInput());
    // gemini should be tried first per env var order
    expect(p2.classify).toHaveBeenCalledOnce();
    expect(p1.classify).not.toHaveBeenCalled();

    process.env[ENV_AI_FALLBACK_ORDER] = original;
  });

  it("respects explicit fallbackOrder constructor option over env var", async () => {
    const original = process.env[ENV_AI_FALLBACK_ORDER];
    process.env[ENV_AI_FALLBACK_ORDER] = "gemini-classifier,grok-xai";

    const p1 = makeAIProvider("grok-xai", "grok-4.3", STUB_RESULT);
    const p2 = makeAIProvider("gemini-classifier", "gemini-2.0-flash", STUB_RESULT);
    // Explicit fallbackOrder should win over env var
    const router = new RoutingClassifierProvider({
      providers: [p1, p2],
      fallbackOrder: ["grok-xai", "gemini-classifier"],
    });

    await router.classify(makeClassifyInput());
    expect(p1.classify).toHaveBeenCalledOnce();
    expect(p2.classify).not.toHaveBeenCalled();

    process.env[ENV_AI_FALLBACK_ORDER] = original;
  });

  it("respects AI_CLASSIFIER_PROVIDER to reorder primary", async () => {
    const original = process.env[ENV_AI_CLASSIFIER_PROVIDER];
    process.env[ENV_AI_CLASSIFIER_PROVIDER] = "gemini-classifier";

    const p1 = makeAIProvider("grok-xai", "grok-4.3", STUB_RESULT);
    const p2 = makeAIProvider("gemini-classifier", "gemini-2.0-flash", STUB_RESULT);
    const router = new RoutingClassifierProvider({ providers: [p1, p2] });

    await router.classify(makeClassifyInput());
    expect(p2.classify).toHaveBeenCalledOnce();
    expect(p1.classify).not.toHaveBeenCalled();

    process.env[ENV_AI_CLASSIFIER_PROVIDER] = original;
  });
});

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

describe("AI classifier constants", () => {
  it("LATENCY_SLA_MS is 5000", () => {
    expect(LATENCY_SLA_MS).toBe(5_000);
  });

  it("LATENCY_WINDOW_SIZE is 3", () => {
    expect(LATENCY_WINDOW_SIZE).toBe(3);
  });

  it("ENV_AI_CLASSIFIER_PROVIDER and ENV_AI_FALLBACK_ORDER are correct strings", () => {
    expect(ENV_AI_CLASSIFIER_PROVIDER).toBe("AI_CLASSIFIER_PROVIDER");
    expect(ENV_AI_FALLBACK_ORDER).toBe("AI_FALLBACK_ORDER");
  });
});
