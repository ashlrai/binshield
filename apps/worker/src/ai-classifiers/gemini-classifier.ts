/**
 * GeminiClassifier — AI-powered binary behavior classifier using Google's
 * Gemini model (gemini-2.0-flash) via the OpenAI-compatible REST API.
 *
 * Implements the same `AIClassifierProvider` interface as `GrokClassifierProvider`
 * so it can be used as a drop-in fallback in the routing layer.
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

const GEMINI_BASE_URL =
  "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions";
const DEFAULT_MODEL = "gemini-2.0-flash";
const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_RETRIES = 3;
const INITIAL_BACKOFF_MS = 500;

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

export class GeminiClassifier implements AIClassifierProvider {
  readonly name = "gemini-classifier";
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
    this.apiKey = options?.apiKey ?? process.env.GEMINI_API_KEY ?? "";
    this.model = options?.model ?? process.env.GEMINI_MODEL ?? DEFAULT_MODEL;
    this.timeoutMs = options?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.usageRepo = options?.usageRepository;
  }

  async classify(input: ClassifyInput): Promise<ClassifiedArtifact> {
    if (!this.apiKey) {
      throw new Error("GEMINI_API_KEY is not configured — cannot use Gemini classifier.");
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
      messages: [
        { role: "system", content: system },
        { role: "user", content: user },
      ],
      response_format: { type: "json_object" },
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
          `[gemini-classifier] Attempt ${attempt + 1}/${MAX_RETRIES} failed: ${lastError.message}`
        );
      }
    }

    throw new Error(
      `Gemini classifier failed after ${MAX_RETRIES} retries: ${lastError?.message ?? "unknown error"}`
    );
  }

  // -------------------------------------------------------------------------
  // Single API call
  // -------------------------------------------------------------------------

  private async callApi(body: string): Promise<string> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const url = `${GEMINI_BASE_URL}?key=${this.apiKey}`;
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body,
        signal: controller.signal,
      });

      if (!response.ok) {
        const errorBody = await response.text().catch(() => "(no body)");
        throw new Error(
          `Gemini API returned ${response.status} ${response.statusText}: ${errorBody}`
        );
      }

      const data = (await response.json()) as {
        model?: string;
        choices: Array<{ message: { content: string | null } }>;
        usage?: { prompt_tokens: number; completion_tokens: number; total_tokens: number };
      };

      if (data.usage) {
        const usage = {
          promptTokens: data.usage.prompt_tokens,
          completionTokens: data.usage.completion_tokens,
          totalTokens: data.usage.total_tokens,
        };

        console.info(
          `[gemini-classifier] Token usage — model: ${this.model}, ` +
            `input: ${usage.promptTokens}, output: ${usage.completionTokens}, total: ${usage.totalTokens}`
        );

        this.usageRepo?.trackClassifierUsage(this.model, usage);
      }

      const content = data.choices?.[0]?.message?.content;
      if (!content) {
        throw new Error("Gemini API returned an empty response (no content in choices[0]).");
      }

      return content;
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") {
        throw new Error(`Gemini API request timed out after ${this.timeoutMs}ms`);
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
      throw new Error(`Gemini classifier returned invalid JSON: ${raw.slice(0, 200)}`);
    }

    if (!parsed.summary || !parsed.explanation) {
      throw new Error(
        "Gemini classifier response is missing required fields (summary, explanation)."
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
