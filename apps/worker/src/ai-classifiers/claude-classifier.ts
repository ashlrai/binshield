/**
 * ClaudeClassifier — AI-powered binary behavior classifier using Anthropic's
 * Claude model (claude-opus-4-1) via the Messages API.
 *
 * Implements the same `AIClassifierProvider` interface as `GrokClassifierProvider`
 * and `GeminiClassifier` so it can be used as a final fallback in the routing layer.
 */

import { emptyBehaviorSummary } from "@binshield/analysis-types";
import type { BehaviorSummary, Finding } from "@binshield/analysis-types";

import { buildAnalysisPrompt } from "../prompts/binary-analysis";
import type { ClassifiedArtifact } from "../types";
import type { AIClassifierProvider, ClassifierUsageRepository } from "./types";
import type { ClassifyInput } from "./types";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const CLAUDE_BASE_URL = "https://api.anthropic.com/v1/messages";
const DEFAULT_MODEL = "claude-opus-4-1";
const DEFAULT_TIMEOUT_MS = 60_000;
const ANTHROPIC_VERSION = "2023-06-01";
const MAX_RETRIES = 3;
const INITIAL_BACKOFF_MS = 1_000;

// ---------------------------------------------------------------------------
// Anthropic Messages API response types
// ---------------------------------------------------------------------------

interface ContentBlock {
  type: string;
  text?: string;
}

interface ClaudeMessagesResponse {
  id: string;
  type: string;
  role: string;
  content: ContentBlock[];
  model: string;
  stop_reason: string | null;
  usage?: {
    input_tokens: number;
    output_tokens: number;
  };
}

// ---------------------------------------------------------------------------
// Raw parsed response from the model (before validation)
// ---------------------------------------------------------------------------

interface RawClassification {
  summary?: string;
  explanation?: string;
  sourceMatchConfidence?: string;
  behaviors?: Partial<Record<keyof BehaviorSummary, { detected?: boolean; details?: string[] }>>;
  findings?: Array<Partial<Finding>>;
  riskNotes?: string[];
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export class ClaudeClassifier implements AIClassifierProvider {
  readonly name = "claude-classifier";
  readonly model: string;

  private readonly apiKey: string;
  private readonly timeoutMs: number;
  private readonly usageRepo?: ClassifierUsageRepository;

  constructor(options?: {
    apiKey?: string;
    model?: string;
    timeoutMs?: number;
    usageRepository?: ClassifierUsageRepository;
  }) {
    this.apiKey = options?.apiKey ?? process.env.ANTHROPIC_API_KEY ?? "";
    this.model = options?.model ?? process.env.CLAUDE_MODEL ?? DEFAULT_MODEL;
    this.timeoutMs = options?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.usageRepo = options?.usageRepository;
  }

  async classify(input: ClassifyInput): Promise<ClassifiedArtifact> {
    if (!this.apiKey) {
      throw new Error("ANTHROPIC_API_KEY is not configured — cannot use Claude classifier.");
    }

    const { system, user } = buildAnalysisPrompt({
      packageName: input.packageRequest.packageName,
      version: input.packageRequest.version,
      binaryFilename: input.artifact.filename,
      architecture: input.artifact.architecture,
      format: input.artifact.format,
      fileSize: input.artifact.fileSize,
      imports: input.decompiled.imports,
      strings: input.decompiled.strings,
      pseudoSource: input.decompiled.pseudoSource,
      functionCount: input.decompiled.functionCount,
      callTargets: input.decompiled.callTargets,
    });

    const body = JSON.stringify({
      model: this.model,
      max_tokens: 2048,
      system,
      messages: [{ role: "user", content: user }],
      temperature: 0.2,
    });

    const raw = await this.callWithRetry(body);
    return this.parseResponse(raw);
  }

  // -------------------------------------------------------------------------
  // Retry logic with exponential backoff
  // -------------------------------------------------------------------------

  private async callWithRetry(body: string): Promise<string> {
    let lastError: Error | undefined;

    for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
      if (attempt > 0) {
        await sleep(INITIAL_BACKOFF_MS * Math.pow(2, attempt - 1));
      }

      try {
        return await this.callApi(body);
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));

        if (lastError.message.includes("401") || lastError.message.includes("403")) {
          throw lastError;
        }

        console.warn(
          `[claude-classifier] Attempt ${attempt + 1}/${MAX_RETRIES} failed: ${lastError.message}`
        );
      }
    }

    throw new Error(
      `Claude classifier failed after ${MAX_RETRIES} retries: ${lastError?.message ?? "unknown error"}`
    );
  }

  // -------------------------------------------------------------------------
  // Single API call
  // -------------------------------------------------------------------------

  private async callApi(body: string): Promise<string> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(CLAUDE_BASE_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": this.apiKey,
          "anthropic-version": ANTHROPIC_VERSION,
        },
        body,
        signal: controller.signal,
      });

      if (!response.ok) {
        const errorBody = await response.text().catch(() => "(no body)");
        throw new Error(
          `Anthropic API returned ${response.status} ${response.statusText}: ${errorBody}`
        );
      }

      const data = (await response.json()) as ClaudeMessagesResponse;

      if (data.usage) {
        const usage = {
          promptTokens: data.usage.input_tokens,
          completionTokens: data.usage.output_tokens,
          totalTokens: data.usage.input_tokens + data.usage.output_tokens,
        };

        console.info(
          `[claude-classifier] Token usage — model: ${this.model}, ` +
            `input: ${usage.promptTokens}, output: ${usage.completionTokens}, total: ${usage.totalTokens}`
        );

        this.usageRepo?.trackClassifierUsage(this.model, usage);
      }

      const textBlock = data.content?.find((block) => block.type === "text");
      const content = textBlock?.text ?? null;
      if (!content) {
        throw new Error("Anthropic API returned an empty response (no text content block).");
      }

      // Claude may wrap JSON in markdown code fences — strip them
      const cleaned = content.replace(/^```(?:json)?\n?/, "").replace(/\n?```$/, "").trim();
      return cleaned;
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") {
        throw new Error(`Anthropic API request timed out after ${this.timeoutMs}ms`);
      }
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  // -------------------------------------------------------------------------
  // Response parsing & validation
  // -------------------------------------------------------------------------

  private parseResponse(raw: string): ClassifiedArtifact {
    let parsed: RawClassification;

    try {
      parsed = JSON.parse(raw) as RawClassification;
    } catch {
      throw new Error(`Claude classifier returned invalid JSON: ${raw.slice(0, 200)}`);
    }

    if (!parsed.summary || !parsed.explanation) {
      throw new Error(
        "Claude classifier response is missing required fields (summary, explanation)."
      );
    }

    return {
      summary: parsed.summary,
      explanation: parsed.explanation,
      sourceMatchConfidence: validateConfidence(parsed.sourceMatchConfidence),
      behaviors: validateBehaviors(parsed.behaviors),
      findings: validateFindings(parsed.findings),
      riskNotes: Array.isArray(parsed.riskNotes)
        ? parsed.riskNotes.filter((note): note is string => typeof note === "string")
        : [],
    };
  }
}

// ---------------------------------------------------------------------------
// Validation helpers (mirrors grok-classifier.ts)
// ---------------------------------------------------------------------------

const VALID_CONFIDENCE = new Set(["low", "medium", "high"]);

function validateConfidence(value: string | undefined): "low" | "medium" | "high" {
  if (value && VALID_CONFIDENCE.has(value)) {
    return value as "low" | "medium" | "high";
  }
  return "medium";
}

const VALID_SEVERITY = new Set(["info", "low", "medium", "high", "critical"]);
const BEHAVIOR_KEYS: Array<keyof BehaviorSummary> = [
  "network",
  "filesystem",
  "process",
  "crypto",
  "obfuscation",
  "dataExfiltration",
];

function validateBehaviors(
  raw: RawClassification["behaviors"] | undefined
): BehaviorSummary {
  const base = emptyBehaviorSummary();

  if (!raw || typeof raw !== "object") {
    return base;
  }

  for (const key of BEHAVIOR_KEYS) {
    const signal = raw[key];
    if (signal && typeof signal === "object") {
      base[key] = {
        detected: signal.detected === true,
        details: Array.isArray(signal.details)
          ? signal.details.filter((d): d is string => typeof d === "string")
          : [],
      };
    }
  }

  return base;
}

function validateFindings(raw: RawClassification["findings"] | undefined): Finding[] {
  if (!Array.isArray(raw)) {
    return [];
  }

  return raw
    .filter(
      (
        entry
      ): entry is Partial<Finding> & {
        title: string;
        description: string;
        recommendation: string;
      } =>
        typeof entry?.title === "string" &&
        typeof entry?.description === "string" &&
        typeof entry?.recommendation === "string"
    )
    .map((entry) => ({
      severity:
        entry.severity && VALID_SEVERITY.has(entry.severity)
          ? (entry.severity as Finding["severity"])
          : "info",
      title: entry.title,
      description: entry.description,
      location: typeof entry.location === "string" ? entry.location : undefined,
      recommendation: entry.recommendation,
    }));
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
