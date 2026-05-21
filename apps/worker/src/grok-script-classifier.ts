/**
 * GrokScriptAnalyzerProvider — AI-powered install-script behavior classifier
 * using xAI's Grok model via the OpenAI-compatible chat completions API.
 *
 * Parallels `grok-classifier.ts` (binary analysis). On any failure it throws,
 * and the composite script-analyzer falls back to the heuristic floor.
 */

import type {
  ManifestAnalysis,
  ScriptFinding,
  ScriptThreatCategory,
  ScriptThreatSummary,
  SourceMatchConfidence
} from "@binshield/analysis-types";
import { emptyScriptThreatSummary, SCRIPT_THREAT_CATEGORIES, SCRIPT_THREAT_KEYS } from "@binshield/analysis-types";
import { scoreManifest } from "@binshield/risk-engine";

import type { ScriptAnalysisInput, ScriptAnalyzerProvider } from "./types";
import { analyzeFromSources, collectScriptSources } from "./manifest-analyzer";
import { redactEvidence } from "./threat-patterns";
import { buildScriptAnalysisPrompt } from "./prompts/install-script-analysis";

const XAI_BASE_URL = "https://api.x.ai/v1/chat/completions";
const DEFAULT_MODEL = "grok-4.3";
const DEFAULT_TIMEOUT_MS = 60_000;
const MAX_RETRIES = 3;
const INITIAL_BACKOFF_MS = 1_000;

const VALID_CONFIDENCE = new Set<SourceMatchConfidence>(["low", "medium", "high"]);
const VALID_SEVERITY = new Set(["info", "low", "medium", "high", "critical"]);
const VALID_CATEGORY = new Set<ScriptThreatCategory>(SCRIPT_THREAT_CATEGORIES);

interface ChatCompletionResponse {
  model: string;
  choices: Array<{ message: { content: string | null } }>;
  usage?: { prompt_tokens: number; completion_tokens: number; total_tokens: number };
}

interface RawScriptClassification {
  explanation?: string;
  sourceMatchConfidence?: string;
  threats?: Partial<Record<keyof ScriptThreatSummary, { detected?: boolean; details?: string[] }>>;
  findings?: Array<Partial<ScriptFinding>>;
}

export class GrokScriptAnalyzerProvider implements ScriptAnalyzerProvider {
  readonly name = "grok-script-xai";

  private readonly apiKey: string;
  private readonly model: string;
  private readonly timeoutMs: number;

  constructor(options?: { apiKey?: string; model?: string; timeoutMs?: number }) {
    this.apiKey = options?.apiKey ?? process.env.XAI_API_KEY ?? "";
    this.model = options?.model ?? process.env.XAI_MODEL ?? DEFAULT_MODEL;
    this.timeoutMs = options?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  async analyze(input: ScriptAnalysisInput): Promise<ManifestAnalysis> {
    if (!this.apiKey) {
      throw new Error("XAI_API_KEY is not configured — cannot use Grok script analyzer.");
    }

    const sources = await collectScriptSources(input);
    // The heuristic pass gives us deterministic structure (lifecycleHooks,
    // analyzedFiles, hasInstallScripts) that we do not trust the model for.
    const heuristic = await analyzeFromSources(input, sources);

    const { system, user } = buildScriptAnalysisPrompt({
      packageName: input.manifest.name || input.packageRequest.packageName,
      version: input.manifest.version || input.packageRequest.version,
      ecosystem: input.packageRequest.ecosystem,
      lifecycleHooks: heuristic.lifecycleHooks,
      files: sources.map((source) => ({ label: source.label, content: source.content }))
    });

    const body = JSON.stringify({
      model: this.model,
      messages: [
        { role: "system", content: system },
        { role: "user", content: user }
      ],
      response_format: { type: "json_object" },
      temperature: 0.1
    });

    const raw = await this.callWithRetry(body);
    return this.parseResponse(raw, heuristic);
  }

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
        console.warn(`[grok-script] Attempt ${attempt + 1}/${MAX_RETRIES} failed: ${lastError.message}`);
      }
    }

    throw new Error(
      `Grok script analyzer failed after ${MAX_RETRIES} retries: ${lastError?.message ?? "unknown error"}`
    );
  }

  private async callApi(body: string): Promise<string> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(XAI_BASE_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.apiKey}`
        },
        body,
        signal: controller.signal
      });

      if (!response.ok) {
        const errorBody = await response.text().catch(() => "(no body)");
        throw new Error(`xAI API returned ${response.status} ${response.statusText}: ${errorBody}`);
      }

      const data = (await response.json()) as ChatCompletionResponse;
      if (data.usage) {
        console.info(
          `[grok-script] Token usage — model: ${data.model}, input: ${data.usage.prompt_tokens}, ` +
            `output: ${data.usage.completion_tokens}, total: ${data.usage.total_tokens}`
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

  private parseResponse(raw: string, heuristic: ManifestAnalysis): ManifestAnalysis {
    let parsed: RawScriptClassification;
    try {
      parsed = JSON.parse(raw) as RawScriptClassification;
    } catch {
      throw new Error(`Grok script analyzer returned invalid JSON: ${raw.slice(0, 200)}`);
    }

    if (!parsed.explanation || typeof parsed.explanation !== "string") {
      throw new Error("Grok script analyzer response is missing the required `explanation` field.");
    }

    const result: ManifestAnalysis = {
      ...heuristic,
      threats: validateThreats(parsed.threats),
      findings: validateFindings(parsed.findings),
      aiExplanation: parsed.explanation,
      sourceMatchConfidence: validateConfidence(parsed.sourceMatchConfidence),
      knownMalwareAdvisoryIds: [],
      analyzedAt: new Date().toISOString()
    };

    const scored = scoreManifest(result);
    result.riskScore = scored.riskScore;
    result.riskLevel = scored.riskLevel;
    return result;
  }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

function validateConfidence(value: string | undefined): SourceMatchConfidence {
  return value && VALID_CONFIDENCE.has(value as SourceMatchConfidence)
    ? (value as SourceMatchConfidence)
    : "medium";
}

function validateThreats(raw: RawScriptClassification["threats"]): ScriptThreatSummary {
  const base = emptyScriptThreatSummary();
  if (!raw || typeof raw !== "object") {
    return base;
  }
  for (const key of SCRIPT_THREAT_KEYS) {
    const signal = raw[key];
    if (signal && typeof signal === "object") {
      base[key] = {
        detected: signal.detected === true,
        details: Array.isArray(signal.details)
          ? signal.details.filter((detail): detail is string => typeof detail === "string").slice(0, 8)
          : []
      };
    }
  }
  return base;
}

function validateFindings(raw: RawScriptClassification["findings"]): ScriptFinding[] {
  if (!Array.isArray(raw)) {
    return [];
  }

  return raw
    .filter(
      (entry): entry is Partial<ScriptFinding> & { title: string; description: string } =>
        typeof entry?.title === "string" && typeof entry?.description === "string"
    )
    .map((entry) => ({
      category:
        entry.category && VALID_CATEGORY.has(entry.category as ScriptThreatCategory)
          ? (entry.category as ScriptThreatCategory)
          : "installHook",
      severity:
        entry.severity && VALID_SEVERITY.has(entry.severity)
          ? (entry.severity as ScriptFinding["severity"])
          : "info",
      title: entry.title,
      description: entry.description,
      filePath: typeof entry.filePath === "string" ? entry.filePath : "package.json",
      evidence: typeof entry.evidence === "string" ? redactEvidence(entry.evidence) : "",
      lifecycleHook: typeof entry.lifecycleHook === "string" ? entry.lifecycleHook : undefined,
      recommendation:
        typeof entry.recommendation === "string"
          ? entry.recommendation
          : "Review this install-script behavior before trusting the package."
    }));
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
