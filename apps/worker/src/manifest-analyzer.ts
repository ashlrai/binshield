/**
 * Manifest / install-script analyzer.
 *
 * The second BinShield analysis path, running alongside native-binary
 * analysis. It inspects the artifacts that supply-chain worms actually use:
 *
 *  - npm:  package.json lifecycle hooks (preinstall/install/postinstall/
 *          prepare) and the JavaScript they execute.
 *  - PyPI: setup.py / setup.cfg / pyproject.toml — arbitrary Python that
 *          runs at `pip install` time.
 *
 * Heuristic, deterministic, network-free. The AI path
 * (`grok-script-classifier.ts`) layers on top of this floor and reuses the
 * exported `collectScriptSources` so both paths see the same source set.
 */

import { readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";

import type { ManifestAnalysis, ScriptFinding, ScriptThreatSummary } from "@binshield/analysis-types";
import { emptyScriptThreatSummary, SCRIPT_THREAT_KEYS } from "@binshield/analysis-types";
import { scoreManifest } from "@binshield/risk-engine";

import type { ScriptAnalysisInput } from "./types";
import { evaluateScriptPatterns, redactEvidence } from "./threat-patterns";
import { detectTyposquat } from "./typosquat";
import { applyTrustedPackageDemotion } from "./trusted-packages";
import { collectWheelNativeExtensions } from "./package-source";

/** npm lifecycle hooks that execute automatically during `npm install`. */
const AUTO_RUN_HOOKS = ["preinstall", "install", "postinstall", "prepare"];
const ALL_LIFECYCLE_HOOKS = [...AUTO_RUN_HOOKS, "prepublish", "prepublishOnly", "preuninstall", "postuninstall"];

/** System / package-manager commands that a package `bin` should never shadow. */
const SHADOWABLE_COMMANDS = new Set([
  "npm", "npx", "node", "yarn", "pnpm", "git", "sh", "bash", "zsh", "sudo", "python", "python3",
  "pip", "pip3", "curl", "wget", "ssh", "scp", "docker", "kubectl", "make", "cc", "gcc", "clang",
  "env", "ls", "cat", "cp", "mv", "rm", "go", "cargo", "ruby", "perl", "java"
]);

const MAX_FILES = 64;
const MAX_FILE_BYTES = 512 * 1024;
const MAX_WALK_DEPTH = 5;
const SCRIPT_EXTENSIONS = new Set([".js", ".cjs", ".mjs", ".ts", ".jsx", ".tsx"]);
const PYTHON_EXTENSIONS = new Set([".py"]);
const PYPI_BUILD_FILES = ["setup.py", "setup.cfg", "pyproject.toml", "conftest.py"];

export interface ScannedSource {
  /** Display path used in findings, e.g. "package.json#scripts.postinstall" or "scripts/install.js". */
  label: string;
  lifecycleHook?: string;
  content: string;
}

interface RawPackageJson {
  main?: unknown;
  bin?: unknown;
  scripts?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Heuristic analyzer
// ---------------------------------------------------------------------------

export class ManifestAnalyzer {
  readonly name = "heuristic-manifest";

  async analyze(input: ScriptAnalysisInput): Promise<ManifestAnalysis> {
    const sources = await collectScriptSources(input);
    return analyzeFromSources(input, sources);
  }
}

/**
 * Build a deterministic ManifestAnalysis from pre-collected sources. Shared by
 * the heuristic provider and the AI provider (which merges its result on top).
 */
export async function analyzeFromSources(
  input: ScriptAnalysisInput,
  sources: ScannedSource[]
): Promise<ManifestAnalysis> {
  const ecosystem = input.packageRequest.ecosystem;

  const lifecycleHooks: Record<string, string> = {};
  for (const source of sources) {
    if (source.lifecycleHook) {
      lifecycleHooks[source.lifecycleHook] = source.content.slice(0, 2_000);
    }
  }

  const hasInstallScripts =
    ecosystem === "pypi"
      ? sources.some((source) => source.label === "setup.py")
      : AUTO_RUN_HOOKS.some((hook) => Boolean(input.manifest.scripts?.[hook]));

  // Collect Python native extensions from the extracted package tree.
  // This covers both sdist (compiled during install) and wheel (pre-compiled)
  // distributions. For wheels extracted by PyPiWheelPackageSource the
  // packageRoot is the raw unzip directory that may contain .so / .pyd files.
  const pythonExtensionFiles: string[] =
    ecosystem === "pypi" ? await collectWheelNativeExtensions(input.packageRoot) : [];
  const hasPythonBinaryExtension = pythonExtensionFiles.length > 0;

  const threats = emptyScriptThreatSummary();
  const findings: ScriptFinding[] = [];
  const seen = new Set<string>();

  const record = (finding: ScriptFinding): void => {
    const key = `${finding.category}:${finding.filePath}:${finding.title}`;
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    findings.push(finding);
    if ((SCRIPT_THREAT_KEYS as readonly string[]).includes(finding.category)) {
      const signal = threats[finding.category as keyof ScriptThreatSummary];
      signal.detected = true;
      if (signal.details.length < 8) {
        signal.details.push(`${finding.title} (${finding.filePath})`);
      }
    }
  };

  // Pattern-match every collected source.
  for (const source of sources) {
    for (const hit of evaluateScriptPatterns(source.content)) {
      record({
        category: hit.rule.category,
        severity: hit.rule.severity,
        title: hit.rule.title,
        description: hit.rule.description,
        filePath: source.label,
        evidence: hit.evidence,
        lifecycleHook: source.lifecycleHook,
        recommendation: hit.rule.recommendation
      });
    }
  }

  // The mere presence of an install hook is itself a (low) risk signal.
  if (hasInstallScripts) {
    const hookNames =
      ecosystem === "pypi"
        ? ["setup.py"]
        : AUTO_RUN_HOOKS.filter((hook) => Boolean(input.manifest.scripts?.[hook]));
    record({
      category: "installHook",
      severity: "low",
      title: "Package runs install-time scripts",
      description:
        ecosystem === "pypi"
          ? "The package ships a setup.py that executes arbitrary Python during `pip install`."
          : `The package runs ${hookNames.join(", ")} during \`npm install\`, executing code on the installing machine.`,
      filePath: ecosystem === "pypi" ? "setup.py" : "package.json#scripts",
      evidence: hookNames.join(", "),
      recommendation: "Confirm the install scripts only perform expected build steps."
    });
  }

  // Python binary extensions in wheels: pre-compiled native code shipped
  // inside the .whl zip. Treat this as a medium-severity finding so reviewers
  // know that opaque compiled binaries are present — analogous to how
  // node-gyp native addons are surfaced on the npm side.
  if (hasPythonBinaryExtension) {
    record({
      category: "pythonBinaryExtension",
      severity: "medium",
      title: "Wheel contains compiled Python native extensions",
      description: `The wheel ships ${pythonExtensionFiles.length} pre-compiled native extension${pythonExtensionFiles.length === 1 ? "" : "s"} (${pythonExtensionFiles.slice(0, 3).join(", ")}${pythonExtensionFiles.length > 3 ? ", …" : ""}). These are binary blobs that bypass source-code review and can contain arbitrary native code.`,
      filePath: pythonExtensionFiles[0] ?? "wheel",
      evidence: pythonExtensionFiles.slice(0, 5).join(", "),
      recommendation:
        "Verify the wheel was built from the published source tarball. Check PyPI provenance attestations when available, and confirm the binary against a reproducible build."
    });
  }

  // Dependency-confusion: a package `bin` that shadows a system command.
  for (const finding of await detectBinShadowing(input)) {
    record(finding);
  }

  // Typosquatting: package name is suspiciously close to a popular package.
  // Runs on npm packages only (PyPI squatting uses different patterns).
  if (ecosystem === "npm") {
    const typosquatFinding = detectTyposquat(input.manifest.name);
    if (typosquatFinding) {
      record(typosquatFinding);
    }
  }

  // Apply trusted-package demotion: for allowlisted packages, downgrade the
  // benign installHook baseline from "low" → "info". High/critical findings,
  // typosquat hits, and knownMalware are NEVER demoted — see trusted-packages.ts.
  const demotedFindings = applyTrustedPackageDemotion(findings, input.manifest.name);

  const base: ManifestAnalysis = {
    id: `manifest_${input.manifest.name}_${input.manifest.version}`.replace(/[^a-zA-Z0-9_.@/-]/g, "_"),
    ecosystem,
    lifecycleHooks,
    hasInstallScripts,
    analyzedFiles: sources.map((source) => source.label),
    riskScore: 0,
    riskLevel: "none",
    threats,
    findings: demotedFindings,
    knownMalwareAdvisoryIds: [],
    sourceMatchConfidence: ecosystem === "pypi" ? "low" : "medium",
    analyzedAt: new Date().toISOString(),
    hasPythonBinaryExtension: hasPythonBinaryExtension || undefined,
    pythonExtensionFiles: pythonExtensionFiles.length > 0 ? pythonExtensionFiles : undefined
  };

  const scored = scoreManifest(base);
  base.riskScore = scored.riskScore;
  base.riskLevel = scored.riskLevel;
  return base;
}

/**
 * Merge an AI ManifestAnalysis onto the deterministic heuristic floor: the
 * union of findings and threat signals, the AI's explanation/confidence, and a
 * re-scored risk. The heuristic result is never lost if the model misses
 * something — and vice versa.
 */
export function mergeManifestAnalysis(heuristic: ManifestAnalysis, ai: ManifestAnalysis): ManifestAnalysis {
  const findings: ScriptFinding[] = [...heuristic.findings];
  const seen = new Set(findings.map((finding) => `${finding.category}:${finding.filePath}:${finding.title}`));
  for (const finding of ai.findings) {
    const key = `${finding.category}:${finding.filePath}:${finding.title}`;
    if (!seen.has(key)) {
      seen.add(key);
      findings.push(finding);
    }
  }

  const threats = emptyScriptThreatSummary();
  for (const key of Object.keys(threats) as Array<keyof ScriptThreatSummary>) {
    const detected = heuristic.threats[key].detected || ai.threats[key].detected;
    threats[key] = {
      detected,
      details: [...new Set([...heuristic.threats[key].details, ...ai.threats[key].details])].slice(0, 8)
    };
  }

  const merged: ManifestAnalysis = {
    ...heuristic,
    threats,
    findings,
    aiExplanation: ai.aiExplanation ?? heuristic.aiExplanation,
    sourceMatchConfidence: ai.sourceMatchConfidence,
    knownMalwareAdvisoryIds: []
  };

  const scored = scoreManifest(merged);
  merged.riskScore = scored.riskScore;
  merged.riskLevel = scored.riskLevel;
  return merged;
}

// ---------------------------------------------------------------------------
// Source collection (shared by heuristic + AI providers)
// ---------------------------------------------------------------------------

/** Collect install-relevant source: lifecycle hooks plus the scripts they reach. */
export async function collectScriptSources(input: ScriptAnalysisInput): Promise<ScannedSource[]> {
  return input.packageRequest.ecosystem === "pypi"
    ? collectPythonSources(input)
    : collectNpmSources(input);
}

async function collectNpmSources(input: ScriptAnalysisInput): Promise<ScannedSource[]> {
  const sources: ScannedSource[] = [];
  const scripts = input.manifest.scripts ?? {};

  // 1. Lifecycle hook bodies — the highest-signal location.
  for (const hook of ALL_LIFECYCLE_HOOKS) {
    const body = scripts[hook];
    if (typeof body === "string" && body.trim().length > 0) {
      sources.push({ label: `package.json#scripts.${hook}`, lifecycleHook: hook, content: body });
    }
  }

  // 2. Seed files: those referenced by hooks, plus main/bin entries.
  const raw = await readRawPackageJson(input.packageRoot);
  const seeds = new Set<string>();
  for (const hook of ALL_LIFECYCLE_HOOKS) {
    const body = scripts[hook];
    if (typeof body === "string") {
      for (const ref of extractFileReferences(body)) {
        seeds.add(ref);
      }
    }
  }
  for (const entry of collectStringValues(raw.main)) {
    seeds.add(entry);
  }
  for (const entry of collectStringValues(raw.bin)) {
    seeds.add(entry);
  }

  // 3. Any install-named script anywhere in the package tree.
  for (const file of await walkFiles(input.packageRoot, SCRIPT_EXTENSIONS)) {
    if (/(?:^|[/\\])(?:pre|post)?install[^/\\]*$|setup\.[cm]?js$|gyp[-_]?build/i.test(file)) {
      seeds.add(path.relative(input.packageRoot, file));
    }
  }

  // 4. BFS over seed files, following shallow relative requires/imports.
  await scanFileGraph(input.packageRoot, seeds, sources, SCRIPT_EXTENSIONS);
  return sources;
}

async function collectPythonSources(input: ScriptAnalysisInput): Promise<ScannedSource[]> {
  const sources: ScannedSource[] = [];

  for (const file of PYPI_BUILD_FILES) {
    const content = await readFileCapped(path.join(input.packageRoot, file));
    if (content !== null) {
      sources.push({ label: file, content });
    }
  }

  const seeds = new Set<string>();
  for (const source of sources) {
    for (const ref of extractFileReferences(source.content)) {
      if (PYTHON_EXTENSIONS.has(path.extname(ref).toLowerCase())) {
        seeds.add(ref);
      }
    }
  }
  for (const file of await walkFiles(input.packageRoot, PYTHON_EXTENSIONS)) {
    if (/(?:^|[/\\])(?:install|setup|_build|build)[^/\\]*\.py$/i.test(file)) {
      seeds.add(path.relative(input.packageRoot, file));
    }
  }

  await scanFileGraph(input.packageRoot, seeds, sources, PYTHON_EXTENSIONS);
  return sources;
}

/** Breadth-first scan of `seeds`, following one-hop relative imports, bounded by MAX_FILES. */
async function scanFileGraph(
  root: string,
  seeds: Set<string>,
  sources: ScannedSource[],
  extensions: Set<string>
): Promise<void> {
  const queue: string[] = [...seeds];
  const visited = new Set<string>();

  while (queue.length > 0 && sources.length < MAX_FILES) {
    const ref = queue.shift();
    if (ref === undefined) {
      break;
    }
    const resolved = await resolveInsideRoot(root, ref, extensions);
    if (!resolved || visited.has(resolved)) {
      continue;
    }
    visited.add(resolved);

    const content = await readFileCapped(resolved);
    if (content === null) {
      continue;
    }
    sources.push({ label: path.relative(root, resolved), content });

    const fromDir = path.relative(root, path.dirname(resolved));
    for (const importRef of extractRelativeImports(content)) {
      queue.push(path.join(fromDir, importRef));
    }
  }
}

// ---------------------------------------------------------------------------
// Bin shadowing
// ---------------------------------------------------------------------------

async function detectBinShadowing(input: ScriptAnalysisInput): Promise<ScriptFinding[]> {
  if (input.packageRequest.ecosystem === "pypi") {
    return [];
  }

  const findings: ScriptFinding[] = [];
  const commandNames: string[] = [];
  const bin = (await readRawPackageJson(input.packageRoot)).bin;

  if (typeof bin === "string") {
    commandNames.push(input.manifest.name.replace(/^@[^/]+\//, ""));
  } else if (bin && typeof bin === "object") {
    commandNames.push(...Object.keys(bin as Record<string, unknown>));
  }

  for (const command of commandNames) {
    if (SHADOWABLE_COMMANDS.has(command.toLowerCase())) {
      findings.push({
        category: "dependencyConfusion",
        severity: "high",
        title: "Package binary shadows a system command",
        description: `The package installs a \`${command}\` executable, which can shadow the real \`${command}\` on PATH and hijack subsequent commands.`,
        filePath: "package.json#bin",
        evidence: redactEvidence(`bin.${command}`),
        recommendation: `Do not install packages that register a \`${command}\` binary unless that is explicitly expected.`
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// File helpers
// ---------------------------------------------------------------------------

async function readRawPackageJson(packageRoot: string): Promise<RawPackageJson> {
  try {
    const content = await readFile(path.join(packageRoot, "package.json"), "utf8");
    return JSON.parse(content) as RawPackageJson;
  } catch {
    return {};
  }
}

async function readFileCapped(filePath: string): Promise<string | null> {
  try {
    const info = await stat(filePath);
    if (!info.isFile() || info.size > MAX_FILE_BYTES) {
      return null;
    }
    return await readFile(filePath, "utf8");
  } catch {
    return null;
  }
}

/** Collect every string value from a package.json field that may be a string or a record. */
function collectStringValues(value: unknown): string[] {
  if (typeof value === "string") {
    return [value];
  }
  if (value && typeof value === "object") {
    return Object.values(value as Record<string, unknown>).filter((entry): entry is string => typeof entry === "string");
  }
  return [];
}

/** Extract file paths named inside a shell command / script body. */
function extractFileReferences(text: string): string[] {
  const refs = new Set<string>();
  const pattern = /[\w.@/\\-]+\.(?:c?js|mjs|jsx?|tsx?|py|sh)\b/gi;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(text)) !== null) {
    refs.add(match[0].replace(/\\/g, "/"));
  }
  return [...refs];
}

/** Extract relative require()/import specifiers from JS/Python source. */
function extractRelativeImports(text: string): string[] {
  const refs = new Set<string>();
  const patterns = [
    /require\s*\(\s*['"](\.[^'"]+)['"]\s*\)/g,
    /import\s[^'"]*['"](\.[^'"]+)['"]/g,
    /from\s+['"](\.[^'"]+)['"]/g
  ];
  for (const pattern of patterns) {
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(text)) !== null) {
      refs.add(match[1]);
    }
  }
  return [...refs];
}

/** Resolve a reference to an absolute path that must stay inside `root`. */
async function resolveInsideRoot(root: string, ref: string, extensions: Set<string>): Promise<string | null> {
  const cleaned = ref.replace(/^['"]|['"]$/g, "").trim();
  if (!cleaned) {
    return null;
  }

  const candidates = [cleaned];
  if (!path.extname(cleaned)) {
    for (const ext of extensions) {
      candidates.push(`${cleaned}${ext}`);
      candidates.push(path.join(cleaned, `index${ext}`));
    }
  }

  for (const candidate of candidates) {
    const resolved = path.resolve(root, candidate);
    const relative = path.relative(root, resolved);
    if (relative.startsWith("..") || path.isAbsolute(relative)) {
      continue;
    }
    if (!extensions.has(path.extname(resolved).toLowerCase())) {
      continue;
    }
    try {
      const info = await stat(resolved);
      if (info.isFile()) {
        return resolved;
      }
    } catch {
      // try next candidate
    }
  }

  return null;
}

/** Recursively list files with the given extensions, skipping node_modules/.git, bounded by MAX_FILES. */
async function walkFiles(root: string, extensions: Set<string>): Promise<string[]> {
  const out: string[] = [];

  async function recurse(dir: string, depth: number): Promise<void> {
    if (depth > MAX_WALK_DEPTH || out.length >= MAX_FILES) {
      return;
    }
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (out.length >= MAX_FILES) {
        return;
      }
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === "node_modules" || entry.name === ".git" || entry.name === ".bin") {
          continue;
        }
        await recurse(full, depth + 1);
      } else if (entry.isFile() && extensions.has(path.extname(entry.name).toLowerCase())) {
        out.push(full);
      }
    }
  }

  await recurse(root, 0);
  return out;
}
