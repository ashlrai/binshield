/**
 * PackageNameIntelligence — dependency confusion & typosquat detection layer
 *
 * Provides:
 *  1. Levenshtein distance + homoglyph analysis to find lookalikes of popular packages
 *  2. Cross-ecosystem domain-pattern matching (same name on npm + PyPI = credential-theft signal)
 *  3. Versioned typosquat corpus with match/update support
 *  4. Alert emission on discovery of risky new packages
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type Ecosystem = "npm" | "pypi";

export type ConfusableRiskLevel = "low" | "medium" | "high" | "critical";

export interface ConfusableMatch {
  /** The popular/legitimate package being impersonated */
  targetPackage: string;
  /** The ecosystem of the target */
  targetEcosystem: Ecosystem;
  /** Levenshtein edit distance (undefined for homoglyph/corpus matches) */
  editDistance?: number;
  /** Human-readable reason for the flag */
  reason: string;
  /** Computed risk level */
  riskLevel: ConfusableRiskLevel;
}

export interface NameIntelligenceResult {
  packageName: string;
  ecosystem: Ecosystem;
  /** True if this package appears risky */
  isRisky: boolean;
  riskLevel: ConfusableRiskLevel;
  /** All confusable matches found */
  matches: ConfusableMatch[];
  /** True when name appears in the known typosquat corpus */
  isKnownTyposquat: boolean;
  /** True when same name exists in both npm and PyPI (cross-ecosystem risk) */
  crossEcosystemFlag: boolean;
  analyzedAt: string;
}

export interface TyposquatEntry {
  name: string;
  ecosystem: Ecosystem;
  /** The legitimate package it impersonates */
  imitates: string;
  /** Short description of the attack vector */
  description: string;
  /** ISO date when this entry was added to the corpus */
  addedAt: string;
}

export interface PackageNameIntelligenceOptions {
  /**
   * Levenshtein distance threshold for flagging lookalikes.
   * Default: 2 (catches single-char typos, transpositions, insertions).
   */
  levenshteinThreshold?: number;
  /**
   * Popular packages to check against. Defaults to POPULAR_PACKAGES_CORPUS.
   */
  popularPackages?: PopularPackage[];
  /**
   * Additional typosquat entries beyond the built-in corpus.
   */
  extraTyposquats?: TyposquatEntry[];
}

export interface PopularPackage {
  name: string;
  ecosystem: Ecosystem;
  weeklyDownloads?: number;
}

// ---------------------------------------------------------------------------
// Homoglyph table — visually similar characters used in IDN/homograph attacks
// ---------------------------------------------------------------------------

/**
 * Maps confusable Unicode chars to their ASCII equivalents.
 * Covers the most common homoglyphs seen in real typosquat campaigns.
 */
const HOMOGLYPH_MAP: Record<string, string> = {
  // Cyrillic that looks Latin
  "а": "a", // а → a
  "е": "e", // е → e
  "х": "x", // х → x
  "о": "o", // о → o
  "р": "r", // р → r
  "с": "c", // с → c
  "у": "y", // у → y
  // Greek
  "α": "a", // α → a
  "ε": "e", // ε → e
  "ι": "i", // ι → i
  "ο": "o", // ο → o
  // Zero-width / look-alike punctuation
  "–": "-", // en-dash → hyphen
  "—": "-", // em-dash → hyphen
  "­": "",  // soft-hyphen → empty
  // Common visual swaps
  "0": "o",
  "1": "l",
  "3": "e",
  "5": "s",
  "!": "i",
  "@": "a",
};

// ---------------------------------------------------------------------------
// Popular packages corpus — well-known packages we protect against lookalikes
// ---------------------------------------------------------------------------

export const POPULAR_PACKAGES_CORPUS: PopularPackage[] = [
  // npm — utilities
  { name: "lodash", ecosystem: "npm" },
  { name: "lodash-es", ecosystem: "npm" },
  { name: "axios", ecosystem: "npm" },
  { name: "express", ecosystem: "npm" },
  { name: "react", ecosystem: "npm" },
  { name: "react-dom", ecosystem: "npm" },
  { name: "typescript", ecosystem: "npm" },
  { name: "webpack", ecosystem: "npm" },
  { name: "babel-core", ecosystem: "npm" },
  { name: "eslint", ecosystem: "npm" },
  { name: "prettier", ecosystem: "npm" },
  { name: "left-pad", ecosystem: "npm" },
  { name: "chalk", ecosystem: "npm" },
  { name: "commander", ecosystem: "npm" },
  { name: "moment", ecosystem: "npm" },
  { name: "dotenv", ecosystem: "npm" },
  { name: "uuid", ecosystem: "npm" },
  { name: "yargs", ecosystem: "npm" },
  { name: "cross-env", ecosystem: "npm" },
  { name: "rimraf", ecosystem: "npm" },
  { name: "glob", ecosystem: "npm" },
  { name: "semver", ecosystem: "npm" },
  { name: "underscore", ecosystem: "npm" },
  { name: "bluebird", ecosystem: "npm" },
  { name: "request", ecosystem: "npm" },
  { name: "node-fetch", ecosystem: "npm" },
  { name: "debug", ecosystem: "npm" },
  { name: "minimist", ecosystem: "npm" },
  { name: "inquirer", ecosystem: "npm" },
  { name: "jest", ecosystem: "npm" },
  { name: "mocha", ecosystem: "npm" },
  { name: "chai", ecosystem: "npm" },
  { name: "sinon", ecosystem: "npm" },
  { name: "bcrypt", ecosystem: "npm" },
  { name: "jsonwebtoken", ecosystem: "npm" },
  { name: "passport", ecosystem: "npm" },
  { name: "mongoose", ecosystem: "npm" },
  { name: "sequelize", ecosystem: "npm" },
  { name: "knex", ecosystem: "npm" },
  { name: "sharp", ecosystem: "npm" },
  { name: "canvas", ecosystem: "npm" },
  { name: "socket.io", ecosystem: "npm" },
  { name: "ws", ecosystem: "npm" },
  { name: "multer", ecosystem: "npm" },
  { name: "cors", ecosystem: "npm" },
  { name: "helmet", ecosystem: "npm" },
  { name: "body-parser", ecosystem: "npm" },
  { name: "cookie-parser", ecosystem: "npm" },
  { name: "compression", ecosystem: "npm" },
  { name: "morgan", ecosystem: "npm" },
  { name: "npm-helper", ecosystem: "npm" },
  { name: "colors", ecosystem: "npm" },
  { name: "ora", ecosystem: "npm" },
  { name: "execa", ecosystem: "npm" },
  { name: "fs-extra", ecosystem: "npm" },
  { name: "mkdirp", ecosystem: "npm" },
  { name: "nconf", ecosystem: "npm" },
  { name: "config", ecosystem: "npm" },
  { name: "node-gyp", ecosystem: "npm" },
  { name: "nan", ecosystem: "npm" },
  { name: "bindings", ecosystem: "npm" },
  // PyPI — popular packages
  { name: "requests", ecosystem: "pypi" },
  { name: "numpy", ecosystem: "pypi" },
  { name: "pandas", ecosystem: "pypi" },
  { name: "scipy", ecosystem: "pypi" },
  { name: "matplotlib", ecosystem: "pypi" },
  { name: "tensorflow", ecosystem: "pypi" },
  { name: "torch", ecosystem: "pypi" },
  { name: "scikit-learn", ecosystem: "pypi" },
  { name: "flask", ecosystem: "pypi" },
  { name: "django", ecosystem: "pypi" },
  { name: "fastapi", ecosystem: "pypi" },
  { name: "sqlalchemy", ecosystem: "pypi" },
  { name: "celery", ecosystem: "pypi" },
  { name: "boto3", ecosystem: "pypi" },
  { name: "botocore", ecosystem: "pypi" },
  { name: "cryptography", ecosystem: "pypi" },
  { name: "pycryptodome", ecosystem: "pypi" },
  { name: "paramiko", ecosystem: "pypi" },
  { name: "pillow", ecosystem: "pypi" },
  { name: "pydantic", ecosystem: "pypi" },
  { name: "aiohttp", ecosystem: "pypi" },
  { name: "httpx", ecosystem: "pypi" },
  { name: "pytest", ecosystem: "pypi" },
  { name: "setuptools", ecosystem: "pypi" },
  { name: "pip", ecosystem: "pypi" },
  { name: "wheel", ecosystem: "pypi" },
  { name: "twine", ecosystem: "pypi" },
  { name: "black", ecosystem: "pypi" },
  { name: "flake8", ecosystem: "pypi" },
  { name: "mypy", ecosystem: "pypi" },
  { name: "click", ecosystem: "pypi" },
  { name: "rich", ecosystem: "pypi" },
  { name: "typer", ecosystem: "pypi" },
  { name: "pyyaml", ecosystem: "pypi" },
  { name: "toml", ecosystem: "pypi" },
  { name: "attrs", ecosystem: "pypi" },
  { name: "six", ecosystem: "pypi" },
  { name: "urllib3", ecosystem: "pypi" },
  { name: "certifi", ecosystem: "pypi" },
  { name: "chardet", ecosystem: "pypi" },
  { name: "idna", ecosystem: "pypi" },
  { name: "packaging", ecosystem: "pypi" },
  { name: "psycopg2", ecosystem: "pypi" },
  { name: "redis", ecosystem: "pypi" },
  { name: "pymongo", ecosystem: "pypi" },
  { name: "elasticsearch", ecosystem: "pypi" },
  { name: "grpcio", ecosystem: "pypi" },
  { name: "protobuf", ecosystem: "pypi" },
  { name: "openai", ecosystem: "pypi" },
  { name: "anthropic", ecosystem: "pypi" },
  { name: "langchain", ecosystem: "pypi" },
];

// ---------------------------------------------------------------------------
// Known typosquat corpus (versioned, updateable)
// ---------------------------------------------------------------------------

/** Corpus version — bump when entries are added/removed. */
export const TYPOSQUAT_CORPUS_VERSION = "2026-06-29.1";

export const KNOWN_TYPOSQUATS: TyposquatEntry[] = [
  // npm — left-pad attacks
  { name: "leftpad", ecosystem: "npm", imitates: "left-pad", description: "Missing hyphen lookalike of left-pad", addedAt: "2024-01-01" },
  { name: "left-pads", ecosystem: "npm", imitates: "left-pad", description: "Pluralized left-pad clone", addedAt: "2024-01-01" },
  { name: "left_pad", ecosystem: "npm", imitates: "left-pad", description: "Underscore-dash swap of left-pad", addedAt: "2024-01-01" },
  // npm — lodash variants
  { name: "lodash-helper", ecosystem: "npm", imitates: "lodash", description: "Helper suffix on lodash to slip past auditors", addedAt: "2024-01-01" },
  { name: "lodash-util", ecosystem: "npm", imitates: "lodash", description: "Utility suffix on lodash", addedAt: "2024-01-01" },
  { name: "lodash-utils", ecosystem: "npm", imitates: "lodash", description: "Utils suffix on lodash", addedAt: "2024-01-01" },
  { name: "lodashjs", ecosystem: "npm", imitates: "lodash", description: "js suffix appended to lodash", addedAt: "2024-01-01" },
  { name: "load-ash", ecosystem: "npm", imitates: "lodash", description: "load-ash homophone split", addedAt: "2024-03-15" },
  // npm — npm-helper cluster (historically used for credential theft)
  { name: "npm-helpers", ecosystem: "npm", imitates: "npm-helper", description: "Plural of npm-helper", addedAt: "2024-01-01" },
  { name: "npmhelper", ecosystem: "npm", imitates: "npm-helper", description: "npm-helper without hyphen", addedAt: "2024-01-01" },
  { name: "npm-helpper", ecosystem: "npm", imitates: "npm-helper", description: "Double-p typo in npm-helper", addedAt: "2024-01-01" },
  // npm — colors hijack variants
  { name: "colour", ecosystem: "npm", imitates: "colors", description: "British spelling of colors", addedAt: "2024-01-01" },
  { name: "colours", ecosystem: "npm", imitates: "colors", description: "Plural British spelling of colors", addedAt: "2024-01-01" },
  // npm — axios variants
  { name: "axio", ecosystem: "npm", imitates: "axios", description: "Missing trailing s from axios", addedAt: "2024-01-01" },
  { name: "axois", ecosystem: "npm", imitates: "axios", description: "Transposition: axois instead of axios", addedAt: "2024-01-01" },
  { name: "axi0s", ecosystem: "npm", imitates: "axios", description: "Digit substitution: o→0 in axios", addedAt: "2024-01-01" },
  { name: "axios-helper", ecosystem: "npm", imitates: "axios", description: "Helper suffix typosquat on axios", addedAt: "2024-01-01" },
  // npm — cross-env
  { name: "crossenv", ecosystem: "npm", imitates: "cross-env", description: "crossenv without hyphen (historic RCE incident)", addedAt: "2024-01-01" },
  { name: "cross_env", ecosystem: "npm", imitates: "cross-env", description: "Underscore-dash swap of cross-env", addedAt: "2024-01-01" },
  // npm — babel
  { name: "bable-core", ecosystem: "npm", imitates: "babel-core", description: "Transposition: bable instead of babel", addedAt: "2024-01-01" },
  { name: "babel-cores", ecosystem: "npm", imitates: "babel-core", description: "Plural of babel-core", addedAt: "2024-01-01" },
  // npm — eslint
  { name: "es-lint", ecosystem: "npm", imitates: "eslint", description: "Hyphen injection into eslint", addedAt: "2024-01-01" },
  { name: "eslintt", ecosystem: "npm", imitates: "eslint", description: "Double-t typo in eslint", addedAt: "2024-01-01" },
  // npm — express
  { name: "expres", ecosystem: "npm", imitates: "express", description: "Missing trailing s from express", addedAt: "2024-01-01" },
  { name: "expresss", ecosystem: "npm", imitates: "express", description: "Triple-s typo in express", addedAt: "2024-01-01" },
  // npm — bcrypt
  { name: "bcryptt", ecosystem: "npm", imitates: "bcrypt", description: "Double-t typo in bcrypt", addedAt: "2024-01-01" },
  { name: "bcrpyt", ecosystem: "npm", imitates: "bcrypt", description: "Transposition: bcrpyt instead of bcrypt", addedAt: "2024-01-01" },
  // PyPI — requests
  { name: "requets", ecosystem: "pypi", imitates: "requests", description: "Transposition: requets instead of requests", addedAt: "2024-01-01" },
  { name: "requestss", ecosystem: "pypi", imitates: "requests", description: "Extra s in requests", addedAt: "2024-01-01" },
  { name: "request", ecosystem: "pypi", imitates: "requests", description: "Missing trailing s from requests", addedAt: "2024-01-01" },
  { name: "reqeusts", ecosystem: "pypi", imitates: "requests", description: "Transposition: reqeusts instead of requests", addedAt: "2024-01-01" },
  // PyPI — numpy
  { name: "nunpy", ecosystem: "pypi", imitates: "numpy", description: "Transposition: nunpy instead of numpy", addedAt: "2024-01-01" },
  { name: "numphy", ecosystem: "pypi", imitates: "numpy", description: "ph→p insertion in numpy", addedAt: "2024-01-01" },
  { name: "numpyy", ecosystem: "pypi", imitates: "numpy", description: "Double-y typo in numpy", addedAt: "2024-01-01" },
  // PyPI — setuptools
  { name: "setuptool", ecosystem: "pypi", imitates: "setuptools", description: "Missing trailing s from setuptools", addedAt: "2024-01-01" },
  { name: "setup-tools", ecosystem: "pypi", imitates: "setuptools", description: "Hyphen injection into setuptools", addedAt: "2024-01-01" },
  // PyPI — tensorflow
  { name: "tensorlfow", ecosystem: "pypi", imitates: "tensorflow", description: "Transposition: lf instead of fl in tensorflow", addedAt: "2024-01-01" },
  { name: "tensor-flow", ecosystem: "pypi", imitates: "tensorflow", description: "Hyphen injection into tensorflow", addedAt: "2024-01-01" },
  // PyPI — urllib3
  { name: "urllib", ecosystem: "pypi", imitates: "urllib3", description: "Missing version suffix from urllib3", addedAt: "2024-01-01" },
  { name: "url-lib3", ecosystem: "pypi", imitates: "urllib3", description: "Hyphen injection into urllib3", addedAt: "2024-01-01" },
  // Cross-ecosystem confusion (same name, different ecosystem)
  { name: "boto", ecosystem: "pypi", imitates: "boto3", description: "Dropped version suffix from boto3", addedAt: "2024-01-01" },
  { name: "botocore-helper", ecosystem: "pypi", imitates: "botocore", description: "Helper suffix on botocore", addedAt: "2024-01-01" },
];

// ---------------------------------------------------------------------------
// Levenshtein distance (Wagner-Fischer, O(m*n))
// ---------------------------------------------------------------------------

/**
 * Compute the Levenshtein edit distance between two strings.
 * Pure implementation — no external dependencies.
 */
export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  // Use two rows to save memory for long strings
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  let curr = new Array<number>(b.length + 1);

  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        (curr[j - 1] ?? 0) + 1,            // insertion
        (prev[j] ?? 0) + 1,                // deletion
        (prev[j - 1] ?? 0) + cost          // substitution
      );
    }
    [prev, curr] = [curr, prev];
  }

  return prev[b.length] ?? 0;
}

// ---------------------------------------------------------------------------
// Homoglyph normalisation
// ---------------------------------------------------------------------------

/**
 * Normalise a package name by replacing known homoglyphs with their ASCII
 * equivalents and lower-casing, so "lоdash" (Cyrillic о) → "lodash".
 */
export function normalizeHomoglyphs(name: string): string {
  let out = "";
  for (const char of name.toLowerCase()) {
    out += HOMOGLYPH_MAP[char] ?? char;
  }
  return out;
}

/**
 * Returns true if the two names differ only by homoglyphs (e.g. one contains
 * Cyrillic or Greek characters that look identical to ASCII counterparts).
 */
export function isHomoglyphVariant(a: string, b: string): boolean {
  if (a === b) return false; // identical — not a homoglyph attack
  return normalizeHomoglyphs(a) === normalizeHomoglyphs(b);
}

// ---------------------------------------------------------------------------
// Cross-ecosystem detection
// ---------------------------------------------------------------------------

/**
 * Determine whether a package name publishing in BOTH npm and PyPI is suspicious.
 *
 * Legitimate packages sometimes have the same name on both registries (e.g. "redis"),
 * but that is rare for scoped or deeply specific utility names. We flag when the
 * name is:
 *  - Not a known cross-listed benign package (see CROSS_LISTED_BENIGN)
 *  - Short (≤ 6 chars) or appears to be a credential/utility name
 *
 * The caller is responsible for verifying cross-ecosystem presence via registry
 * lookups; this function evaluates the name itself for structural risk.
 */
const CROSS_LISTED_BENIGN = new Set([
  "redis", "requests", "urllib3", "six", "certifi", "chardet", "idna",
  "packaging", "cryptography", "click", "rich", "toml", "attrs",
  "flask", "django", "numpy", "pandas", "pytest", "black", "flake8",
  "mypy", "twine", "wheel", "pip", "setuptools", "grpcio", "protobuf",
]);

export function isCrossEcosystemRisky(name: string): boolean {
  const lower = name.toLowerCase();
  if (CROSS_LISTED_BENIGN.has(lower)) return false;
  // Short utility-sounding names are risky cross-listed
  if (lower.length <= 6) return true;
  // Names containing credential-stealing keywords
  const riskyKeywords = ["helper", "utils", "util", "tool", "tools", "common", "core", "lib", "sdk"];
  return riskyKeywords.some((kw) => lower.includes(kw));
}

// ---------------------------------------------------------------------------
// Main intelligence service
// ---------------------------------------------------------------------------

export class PackageNameIntelligence {
  private readonly levenshteinThreshold: number;
  private readonly popularPackages: PopularPackage[];
  private readonly typosquats: TyposquatEntry[];

  constructor(options: PackageNameIntelligenceOptions = {}) {
    this.levenshteinThreshold = options.levenshteinThreshold ?? 2;
    this.popularPackages = options.popularPackages ?? POPULAR_PACKAGES_CORPUS;
    this.typosquats = [
      ...KNOWN_TYPOSQUATS,
      ...(options.extraTyposquats ?? []),
    ];
  }

  /**
   * Analyse a package name for confusable/typosquat patterns.
   *
   * @param packageName  The candidate package name to evaluate
   * @param ecosystem    The ecosystem it was discovered on
   * @param presentOnBothEcosystems  Set to true when the same name has been
   *   confirmed to exist on BOTH npm and PyPI (caller must verify via registry)
   */
  analyze(
    packageName: string,
    ecosystem: Ecosystem,
    presentOnBothEcosystems = false
  ): NameIntelligenceResult {
    const matches: ConfusableMatch[] = [];

    // 1. Typosquat corpus check (exact match against known bad names)
    const corpusMatch = this.typosquats.find(
      (e) => e.name.toLowerCase() === packageName.toLowerCase() && e.ecosystem === ecosystem
    );
    const isKnownTyposquat = Boolean(corpusMatch);

    if (corpusMatch) {
      matches.push({
        targetPackage: corpusMatch.imitates,
        targetEcosystem: ecosystem,
        reason: `Known typosquat: ${corpusMatch.description}`,
        riskLevel: "critical",
      });
    }

    // 2. Levenshtein + homoglyph analysis against popular packages
    for (const popular of this.popularPackages) {
      // Only compare within same ecosystem (or cross-ecosystem when flagged)
      if (popular.ecosystem !== ecosystem) continue;
      if (popular.name.toLowerCase() === packageName.toLowerCase()) continue;

      // Homoglyph check
      if (isHomoglyphVariant(packageName, popular.name)) {
        matches.push({
          targetPackage: popular.name,
          targetEcosystem: popular.ecosystem,
          reason: `Homoglyph attack: "${packageName}" is visually identical to "${popular.name}" when rendered`,
          riskLevel: "critical",
        });
        continue;
      }

      // Levenshtein check — skip if names are very different in length to avoid noise
      const lenDiff = Math.abs(packageName.length - popular.name.length);
      if (lenDiff > this.levenshteinThreshold + 1) continue;

      const dist = levenshtein(packageName.toLowerCase(), popular.name.toLowerCase());
      if (dist > 0 && dist <= this.levenshteinThreshold) {
        // Distinguish between an obviously related scoped package (e.g. lodash-es)
        // and a genuine typosquat. If one name is a prefix/suffix extension of
        // the other with a known safe separator, it's legitimate.
        if (isLegitimateExtension(packageName, popular.name)) continue;

        const riskLevel: ConfusableRiskLevel = dist === 1 ? "high" : "medium";
        matches.push({
          targetPackage: popular.name,
          targetEcosystem: popular.ecosystem,
          editDistance: dist,
          reason: `Levenshtein distance ${dist} from popular package "${popular.name}"`,
          riskLevel,
        });
      }
    }

    // 3. Cross-ecosystem flag
    const crossEcosystemFlag = presentOnBothEcosystems && isCrossEcosystemRisky(packageName);
    if (crossEcosystemFlag) {
      matches.push({
        targetPackage: packageName,
        targetEcosystem: ecosystem === "npm" ? "pypi" : "npm",
        reason: `Package "${packageName}" publishes to BOTH npm and PyPI — a common credential-theft pattern`,
        riskLevel: "high",
      });
    }

    // Deduplicate matches by targetPackage (keep highest severity)
    const deduped = deduplicateMatches(matches);

    const topRisk = highestRisk(deduped);
    const isRisky = deduped.length > 0;

    return {
      packageName,
      ecosystem,
      isRisky,
      riskLevel: topRisk,
      matches: deduped,
      isKnownTyposquat,
      crossEcosystemFlag,
      analyzedAt: new Date().toISOString(),
    };
  }

  /**
   * Emit a CRITICAL advisory string for a risky result.
   * Callers should feed this into their alert/notification pipeline.
   */
  buildAdvisory(result: NameIntelligenceResult): string {
    const { packageName, ecosystem, riskLevel, matches } = result;
    const lines: string[] = [
      `[BINSHIELD ADVISORY] ${riskLevel.toUpperCase()} — dependency confusion / typosquat risk`,
      `Package: ${ecosystem}/${packageName}`,
      `Risk level: ${riskLevel}`,
      `Matches (${matches.length}):`,
    ];
    for (const m of matches) {
      lines.push(`  • [${m.targetPackage}] ${m.reason} (${m.riskLevel})`);
    }
    return lines.join("\n");
  }

  /**
   * Add new entries to the live typosquat corpus at runtime.
   * Useful for hot-loading updated intelligence without a restart.
   */
  addTyposquats(entries: TyposquatEntry[]): void {
    this.typosquats.push(...entries);
  }

  /**
   * Return the full in-memory typosquat corpus (built-in + extras).
   */
  getCorpus(): TyposquatEntry[] {
    return [...this.typosquats];
  }
}

// ---------------------------------------------------------------------------
// Lockfile parsing + audit-names helpers
// ---------------------------------------------------------------------------

export interface LockfilePackage {
  name: string;
  version: string;
  ecosystem: Ecosystem;
}

export interface AuditNamesResult {
  scanned: number;
  risky: NameIntelligenceResult[];
  clean: number;
  summary: string;
}

/**
 * Parse a package-lock.json (npm lockfile v2/v3) and extract all dependency names.
 */
export function parsePackageLock(content: string): LockfilePackage[] {
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(content) as Record<string, unknown>;
  } catch {
    return [];
  }

  const packages: LockfilePackage[] = [];

  // v2/v3 format: "packages" key
  const pkgs = parsed.packages as Record<string, { version?: string }> | undefined;
  if (pkgs && typeof pkgs === "object") {
    for (const [path, meta] of Object.entries(pkgs)) {
      if (!path || path === "") continue; // skip root
      // path is like "node_modules/lodash" or "node_modules/@scope/pkg"
      const name = path.replace(/^node_modules\//, "").replace(/\/node_modules\//g, "/");
      if (name && meta?.version) {
        packages.push({ name, version: meta.version, ecosystem: "npm" });
      }
    }
  }

  // v1 format: "dependencies" key
  const deps = parsed.dependencies as Record<string, { version?: string }> | undefined;
  if (deps && typeof deps === "object") {
    for (const [name, meta] of Object.entries(deps)) {
      if (meta?.version) {
        packages.push({ name, version: meta.version, ecosystem: "npm" });
      }
    }
  }

  return packages;
}

/**
 * Parse a requirements.txt into LockfilePackage entries (PyPI).
 */
export function parseRequirementsTxt(content: string): LockfilePackage[] {
  const packages: LockfilePackage[] = [];
  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) continue;
    // Handle: package==1.2.3, package>=1.0, package~=2.0, package
    const match = line.match(/^([A-Za-z0-9_.-]+)(?:[=~><!\s].*)?$/);
    if (match?.[1]) {
      const versionMatch = line.match(/[=~><]{1,2}([^\s,;]+)/);
      packages.push({
        name: match[1],
        version: versionMatch?.[1] ?? "unknown",
        ecosystem: "pypi",
      });
    }
  }
  return packages;
}

/**
 * Parse a pnpm-lock.yaml (basic: extract package names from importers/packages sections).
 * We extract names from the "packages" section keys which look like "/lodash@4.17.21".
 */
export function parsePnpmLock(content: string): LockfilePackage[] {
  const packages: LockfilePackage[] = [];
  // Match lines that look like package keys: "/name@version:" or "  /name@version:"
  const re = /^\s*\/?([A-Za-z0-9@/_.-]+)@([^:\s(]+)/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    const name = m[1]?.replace(/^\//, "") ?? "";
    const version = m[2] ?? "unknown";
    if (name && !name.includes("(")) {
      packages.push({ name, version, ecosystem: "npm" });
    }
  }
  return packages;
}

/**
 * Auto-detect lockfile format and parse into packages.
 */
export function parseLockfile(filename: string, content: string): LockfilePackage[] {
  const base = filename.toLowerCase().split("/").pop() ?? filename;
  if (base === "package-lock.json") return parsePackageLock(content);
  if (base === "requirements.txt") return parseRequirementsTxt(content);
  if (base === "pnpm-lock.yaml" || base === "pnpm-lock.yml") return parsePnpmLock(content);
  return [];
}

/**
 * Run audit-names intelligence over a parsed lockfile.
 * Returns all risky results with advisory text.
 */
export function auditLockfileNames(
  packages: LockfilePackage[],
  intelligenceOptions?: PackageNameIntelligenceOptions
): AuditNamesResult {
  const intelligence = new PackageNameIntelligence(intelligenceOptions);
  const risky: NameIntelligenceResult[] = [];

  for (const pkg of packages) {
    const result = intelligence.analyze(pkg.name, pkg.ecosystem);
    if (result.isRisky) {
      risky.push(result);
    }
  }

  const clean = packages.length - risky.length;
  const criticalCount = risky.filter((r) => r.riskLevel === "critical").length;
  const highCount = risky.filter((r) => r.riskLevel === "high").length;

  const summary =
    risky.length === 0
      ? `All ${packages.length} packages passed name-intelligence checks.`
      : `Found ${risky.length} risky package name(s) in ${packages.length} total ` +
        `(${criticalCount} critical, ${highCount} high). ` +
        `Immediate review recommended.`;

  return { scanned: packages.length, risky, clean, summary };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

const RISK_ORDER: Record<ConfusableRiskLevel, number> = {
  low: 1, medium: 2, high: 3, critical: 4,
};

function highestRisk(matches: ConfusableMatch[]): ConfusableRiskLevel {
  if (matches.length === 0) return "low";
  return matches.reduce<ConfusableRiskLevel>((best, m) => {
    return (RISK_ORDER[m.riskLevel] ?? 0) > (RISK_ORDER[best] ?? 0) ? m.riskLevel : best;
  }, "low");
}

function deduplicateMatches(matches: ConfusableMatch[]): ConfusableMatch[] {
  const byTarget = new Map<string, ConfusableMatch>();
  for (const m of matches) {
    const key = `${m.targetEcosystem}:${m.targetPackage}`;
    const existing = byTarget.get(key);
    if (!existing || (RISK_ORDER[m.riskLevel] ?? 0) > (RISK_ORDER[existing.riskLevel] ?? 0)) {
      byTarget.set(key, m);
    }
  }
  return Array.from(byTarget.values());
}

/**
 * Returns true when `candidate` is a scoped/extended derivative of `popular`
 * that is most likely legitimate (e.g. "lodash-es" from "lodash", or
 * "babel-core" from "babel"). We do NOT want to flag intentional forks.
 *
 * Heuristic: candidate starts with popular name followed by a hyphen/slash or
 * popular name ends with '-core'/'-es'/'-next' and candidate is the base.
 */
function isLegitimateExtension(candidate: string, popular: string): boolean {
  const c = candidate.toLowerCase();
  const p = popular.toLowerCase();
  // candidate is an extension: lodash-es, lodash-fp, babel-core, react-dom
  if (c.startsWith(`${p}-`) || c.startsWith(`${p}/`)) return true;
  // popular is an extension of candidate: lodash from lodash-es (reversed)
  if (p.startsWith(`${c}-`) || p.startsWith(`${c}/`)) return true;
  return false;
}
