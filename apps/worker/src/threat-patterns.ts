/**
 * Install-script threat ruleset.
 *
 * Heuristic, deterministic, network-free pattern matching for JavaScript /
 * Python / shell install-script source — the vector used by npm/PyPI
 * supply-chain worms (malicious postinstall hooks, setup.py code). This is the
 * source-text counterpart of the binary YARA ruleset in `yara-scanner.ts`.
 *
 * Rules are intentionally conservative: bare `process.env` or a lone
 * `child_process` import is not flagged — only patterns that are genuinely
 * abnormal for a package's install phase.
 *
 * Pattern versioning
 * ------------------
 * Rule definitions live in `threat-pattern-set.json` (bundled at build time).
 * The JSON carries a `patternVersion` field so callers can record which version
 * of the ruleset produced a given finding set. The structure is intentionally
 * forward-compatible: a future loader could fetch an updated JSON from a remote
 * endpoint or database and call `loadPatternSet()` to hot-swap the active rules.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

import type { FindingSeverity, ScriptThreatCategory } from "@binshield/analysis-types";

// ---------------------------------------------------------------------------
// JSON schema for the bundled pattern set
// ---------------------------------------------------------------------------

interface PatternSpec {
  source: string;
  flags: string;
}

interface RuleSpec {
  id: string;
  category: string;
  severity: string;
  title: string;
  description: string;
  recommendation: string;
  patterns: PatternSpec[];
  minMatches: number;
}

interface PatternSetFile {
  patternVersion: string;
  rules: RuleSpec[];
}

// ---------------------------------------------------------------------------
// Runtime rule type (RegExp objects reconstructed from JSON)
// ---------------------------------------------------------------------------

export interface ScriptPatternRule {
  id: string;
  category: ScriptThreatCategory;
  severity: FindingSeverity;
  title: string;
  description: string;
  recommendation: string;
  /** Patterns to test. Defined without the `g` flag so `.exec` stays stateless. */
  patterns: RegExp[];
  /** Minimum distinct patterns that must match for the rule to fire. */
  minMatches: number;
}

// ---------------------------------------------------------------------------
// Pattern set loader
// ---------------------------------------------------------------------------

function loadPatternSetFile(): PatternSetFile {
  const jsonPath = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    "threat-pattern-set.json"
  );
  const raw = readFileSync(jsonPath, "utf8");
  return JSON.parse(raw) as PatternSetFile;
}

function buildRules(file: PatternSetFile): ScriptPatternRule[] {
  return file.rules.map((rule) => ({
    id: rule.id,
    category: rule.category as ScriptThreatCategory,
    severity: rule.severity as FindingSeverity,
    title: rule.title,
    description: rule.description,
    recommendation: rule.recommendation,
    // Reconstruct RegExp objects; strip the `g` flag so .exec stays stateless.
    patterns: rule.patterns.map(({ source, flags }) =>
      new RegExp(source, flags.replace("g", ""))
    ),
    minMatches: rule.minMatches
  }));
}

// Load once at module initialisation — synchronous so the exported constants
// are available immediately without top-level await.
const _patternSetFile: PatternSetFile = loadPatternSetFile();

/**
 * The active set of script pattern rules.
 * Re-exported as a named constant for backwards compatibility.
 */
export const SCRIPT_PATTERN_RULES: ScriptPatternRule[] = buildRules(_patternSetFile);

/**
 * Return the version string of the currently loaded threat-pattern set.
 * Callers can record this alongside findings to track which ruleset version
 * produced a given analysis result, and to detect when a remote update has
 * been applied.
 */
export function getPatternVersion(): string {
  return _patternSetFile.patternVersion;
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

export interface PatternHit {
  rule: ScriptPatternRule;
  matchedPatterns: number;
  evidence: string;
}

const SECRET_LIKE: RegExp[] = [
  /\b(?:xai|sk|pk|rk|ghp|gho|ghu|ghs|ghr|github_pat|npm|AKIA|ASIA)[-_][A-Za-z0-9_-]{12,}/g,
  /\bBearer\s+[A-Za-z0-9._-]{16,}/gi,
  /\beyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
  /\b[A-Fa-f0-9]{40,}\b/g
];

/** Truncate and scrub token-like strings from an evidence snippet before it is persisted or surfaced. */
export function redactEvidence(snippet: string): string {
  let cleaned = snippet.replace(/\s+/g, " ").trim();
  for (const pattern of SECRET_LIKE) {
    cleaned = cleaned.replace(pattern, "[REDACTED]");
  }
  if (cleaned.length > 240) {
    cleaned = `${cleaned.slice(0, 240)}…`;
  }
  return cleaned;
}

/** Return the source line containing the character at `index`. */
function lineAt(text: string, index: number): string {
  const start = text.lastIndexOf("\n", index - 1) + 1;
  const end = text.indexOf("\n", index);
  return text.slice(start, end === -1 ? undefined : end);
}

/**
 * Evaluate every rule against a block of script source. Returns one hit per
 * rule whose `minMatches` threshold is met, with a redacted evidence snippet.
 */
export function evaluateScriptPatterns(text: string): PatternHit[] {
  if (!text) {
    return [];
  }

  const hits: PatternHit[] = [];
  for (const rule of SCRIPT_PATTERN_RULES) {
    let matched = 0;
    let evidence = "";

    for (const pattern of rule.patterns) {
      pattern.lastIndex = 0;
      const result = pattern.exec(text);
      if (result) {
        matched += 1;
        if (!evidence) {
          evidence = redactEvidence(lineAt(text, result.index));
        }
      }
    }

    if (matched >= rule.minMatches) {
      hits.push({ rule, matchedPatterns: matched, evidence });
    }
  }

  return hits;
}
