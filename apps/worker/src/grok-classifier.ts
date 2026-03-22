/**
 * GrokClassifierProvider — AI-powered binary behavior classifier using xAI's
 * Grok model via the OpenAI-compatible chat completions API.
 *
 * Falls back through the composite provider chain when the API is unavailable
 * or returns errors after retries.
 */

import type { BehaviorSummary, Finding } from "@binshield/analysis-types";
import { emptyBehaviorSummary } from "@binshield/analysis-types";

import type {
  ClassifiedArtifact,
  ClassifierProvider,
  DecompiledArtifact,
  FingerprintedArtifact,
  WorkerScanRequest,
} from "./types";
import { buildAnalysisPrompt } from "./prompts/binary-analysis";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const XAI_BASE_URL = "https://api.x.ai/v1/chat/completions";
const DEFAULT_MODEL = "grok-4-1-fast-reasoning";
const DEFAULT_TIMEOUT_MS = 60_000;
const MAX_RETRIES = 3;
const INITIAL_BACKOFF_MS = 1_000;

// ---------------------------------------------------------------------------
// Types for the OpenAI-compatible API response
// ---------------------------------------------------------------------------

interface ChatCompletionMessage {
  role: string;
  content: string | null;
}

interface ChatCompletionChoice {
  index: number;
  message: ChatCompletionMessage;
  finish_reason: string;
}

interface ChatCompletionUsage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
}

interface ChatCompletionResponse {
  id: string;
  object: string;
  created: number;
  model: string;
  choices: ChatCompletionChoice[];
  usage?: ChatCompletionUsage;
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

export class GrokClassifierProvider implements ClassifierProvider {
  readonly name = "grok-xai";

  private readonly apiKey: string;
  private readonly model: string;
  private readonly timeoutMs: number;

  constructor(options?: { apiKey?: string; model?: string; timeoutMs?: number }) {
    this.apiKey = options?.apiKey ?? process.env.XAI_API_KEY ?? "";
    this.model = options?.model ?? process.env.XAI_MODEL ?? DEFAULT_MODEL;
    this.timeoutMs = options?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  async classify(input: {
    packageRequest: WorkerScanRequest;
    packageRoot: string;
    artifact: FingerprintedArtifact;
    decompiled: DecompiledArtifact;
  }): Promise<ClassifiedArtifact> {
    if (!this.apiKey) {
      throw new Error("XAI_API_KEY is not configured — cannot use Grok classifier.");
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
        const backoffMs = INITIAL_BACKOFF_MS * Math.pow(2, attempt - 1);
        await sleep(backoffMs);
      }

      try {
        return await this.callApi(body);
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));

        // Don't retry on auth errors — they won't resolve with backoff
        if (lastError.message.includes("401") || lastError.message.includes("403")) {
          throw lastError;
        }

        console.warn(
          `[grok-classifier] Attempt ${attempt + 1}/${MAX_RETRIES} failed: ${lastError.message}`
        );
      }
    }

    throw new Error(
      `Grok classifier failed after ${MAX_RETRIES} retries: ${lastError?.message ?? "unknown error"}`
    );
  }

  // -------------------------------------------------------------------------
  // Single API call
  // -------------------------------------------------------------------------

  private async callApi(body: string): Promise<string> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(XAI_BASE_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.apiKey}`,
        },
        body,
        signal: controller.signal,
      });

      if (!response.ok) {
        const errorBody = await response.text().catch(() => "(no body)");
        throw new Error(
          `xAI API returned ${response.status} ${response.statusText}: ${errorBody}`
        );
      }

      const data = (await response.json()) as ChatCompletionResponse;

      // Log token usage for cost monitoring
      if (data.usage) {
        console.info(
          `[grok-classifier] Token usage — model: ${data.model}, ` +
            `input: ${data.usage.prompt_tokens}, ` +
            `output: ${data.usage.completion_tokens}, ` +
            `total: ${data.usage.total_tokens}`
        );
      }

      const content = data.choices?.[0]?.message?.content;
      if (!content) {
        throw new Error("xAI API returned an empty response (no content in choices[0]).");
      }

      return content;
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") {
        throw new Error(`xAI API request timed out after ${this.timeoutMs}ms`);
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
      throw new Error(
        `Grok classifier returned invalid JSON: ${raw.slice(0, 200)}`
      );
    }

    if (!parsed.summary || !parsed.explanation) {
      throw new Error(
        "Grok classifier response is missing required fields (summary, explanation)."
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
// Validation helpers
// ---------------------------------------------------------------------------

const VALID_CONFIDENCE = new Set(["low", "medium", "high"]);

function validateConfidence(
  value: string | undefined
): "low" | "medium" | "high" {
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
      (entry): entry is Partial<Finding> & { title: string; description: string; recommendation: string } =>
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
