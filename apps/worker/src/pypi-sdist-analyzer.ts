/**
 * PyPI Source Distribution Deep Analyzer
 *
 * Performs deeper static analysis of PyPI source distributions beyond the
 * basic manifest scan. Analyzes:
 *
 *  - setup.py / setup.cfg / pyproject.toml / conftest.py for build configuration
 *  - Cython source files (.pyx / .pxd) for system call and FFI usage
 *  - Build system type detection (setuptools / poetry / pdm / flit / hatch)
 *  - Shell command execution patterns in build configs
 *  - Dynamic code generation / eval in build configs
 *  - Pre/post install hooks that invoke external scripts
 *
 * Results are returned as structured `PypiBuildAnalysis` which feeds into
 * `ManifestAnalysis.buildSystemType` and `ManifestAnalysis.pythonBuildThreatDetails`.
 */

import { readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";

import type { BuildSystemType, PythonBuildThreatDetails } from "@binshield/analysis-types";

// ---------------------------------------------------------------------------
// Public result types
// ---------------------------------------------------------------------------

export interface PypiBuildAnalysis {
  /** Build backend detected from pyproject.toml / setup.cfg / setup.py. */
  buildSystemType: BuildSystemType;
  /** Detailed threat inventory (hooks, Cython files, suspicious patterns). */
  threatDetails: PythonBuildThreatDetails;
  /** All build configuration files that were examined. */
  analyzedFiles: string[];
}

export interface CythonFileAnalysis {
  /** Relative path to the .pyx or .pxd file. */
  filePath: string;
  /** Whether the file calls system-level functions (os.system, subprocess, ctypes). */
  hasSystemCalls: boolean;
  /** Whether the file uses ctypes or cffi FFI. */
  hasFfiUsage: boolean;
  /** Suspicious snippets found (truncated for display). */
  suspiciousSnippets: string[];
}

// ---------------------------------------------------------------------------
// Internal constants
// ---------------------------------------------------------------------------

const MAX_FILE_BYTES = 512 * 1024;
const MAX_WALK_DEPTH = 6;
const MAX_CYTHON_FILES = 32;

/** Build config files we actively parse for hooks and patterns. */
const BUILD_CONFIG_FILES = ["setup.py", "setup.cfg", "pyproject.toml", "conftest.py"];

/** Cython source extensions. */
const CYTHON_EXTENSIONS = new Set([".pyx", ".pxd"]);

// ---------------------------------------------------------------------------
// Build-system detection patterns
// ---------------------------------------------------------------------------

interface BuildSystemPattern {
  system: BuildSystemType;
  /** Test against pyproject.toml content. */
  pyprojectPattern?: RegExp;
  /** Test against setup.py content. */
  setupPyPattern?: RegExp;
  /** Test against setup.cfg content. */
  setupCfgPattern?: RegExp;
}

const BUILD_SYSTEM_PATTERNS: BuildSystemPattern[] = [
  {
    system: "poetry",
    pyprojectPattern: /build-backend\s*=\s*["']poetry(?:\.core)?\.masonry\.api["']/
  },
  {
    system: "pdm",
    pyprojectPattern: /build-backend\s*=\s*["']pdm\.(?:pep517\.)?api["']/
  },
  {
    system: "flit",
    pyprojectPattern: /build-backend\s*=\s*["']flit(?:_core)?\.buildapi["']/
  },
  {
    system: "hatch",
    pyprojectPattern: /build-backend\s*=\s*["']hatchling\.build["']/
  },
  {
    system: "setuptools",
    pyprojectPattern: /build-backend\s*=\s*["']setuptools\._?vendor\.wheel|setuptools\.build_meta["']/,
    setupPyPattern: /from\s+setuptools\s+import|import\s+setuptools/,
    setupCfgPattern: /\[metadata\]|\[options\]/
  }
];

// ---------------------------------------------------------------------------
// Shell command execution patterns in build configs
// ---------------------------------------------------------------------------

const SHELL_EXECUTION_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
  {
    pattern: /subprocess\s*\.\s*(?:run|call|check_call|check_output|Popen)\s*\(/,
    description: "subprocess invocation in build config"
  },
  {
    pattern: /os\s*\.\s*system\s*\(/,
    description: "os.system() call in build config"
  },
  {
    pattern: /os\s*\.\s*(?:popen|execv?[ep]?[l]?[pe]?)\s*\(/,
    description: "os process execution in build config"
  },
  {
    pattern: /shell\s*=\s*True/,
    description: "shell=True flag in subprocess call"
  },
  {
    pattern: /commands\s*\.\s*(?:getoutput|getstatus|getstatusoutput)\s*\(/,
    description: "commands module usage (deprecated shell execution)"
  }
];

// ---------------------------------------------------------------------------
// Dynamic code generation / eval patterns
// ---------------------------------------------------------------------------

const EVAL_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
  {
    pattern: /\beval\s*\(/,
    description: "eval() in build config"
  },
  {
    pattern: /\bexec\s*\(/,
    description: "exec() in build config"
  },
  {
    pattern: /\bcompile\s*\(\s*(?:open|read|fetch|request)/,
    description: "compile() on dynamic source in build config"
  },
  {
    pattern: /importlib\s*\.\s*import_module\s*\(\s*(?:os|subprocess|ctypes)/,
    description: "dynamic import of sensitive module in build config"
  },
  {
    pattern: /__import__\s*\(\s*['"](?:os|subprocess|ctypes|socket)/,
    description: "__import__ of sensitive module in build config"
  }
];

// ---------------------------------------------------------------------------
// Pre/post install hook patterns
// ---------------------------------------------------------------------------

const HOOK_PATTERNS: Array<{ pattern: RegExp; hookName: string }> = [
  {
    pattern: /cmdclass\s*=\s*\{[^}]*['"](?:install|develop|build_ext|build_clib|sdist|bdist)['"]/,
    hookName: "cmdclass override"
  },
  {
    pattern: /class\s+\w+\s*\(\s*install\s*\)\s*:/,
    hookName: "custom install class"
  },
  {
    pattern: /class\s+\w+\s*\(\s*develop\s*\)\s*:/,
    hookName: "custom develop class"
  },
  {
    pattern: /class\s+\w+\s*\(\s*build_ext\s*\)\s*:/,
    hookName: "custom build_ext class"
  },
  {
    pattern: /def\s+run\s*\(self\)[^:]*:.*?(?:subprocess|os\.system|exec|eval)/s,
    hookName: "run() method with shell execution"
  },
  {
    pattern: /setup_requires\s*=\s*\[/,
    hookName: "setup_requires (runs code pre-install)"
  },
  {
    pattern: /\[\s*tool\.setuptools\.cmdclass\s*\]/,
    hookName: "pyproject cmdclass override"
  }
];

// ---------------------------------------------------------------------------
// Cython-specific suspicious patterns
// ---------------------------------------------------------------------------

const CYTHON_SUSPICIOUS_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
  {
    pattern: /libc\.stdlib\s+cimport\s+(?:system|popen|exec)/,
    description: "Cython: cimport of system/popen/exec from libc"
  },
  {
    pattern: /from\s+libc\s*\.\s*stdlib\s+cimport/,
    description: "Cython: cimport from libc.stdlib (can access system calls)"
  },
  {
    pattern: /ctypes\s*\.\s*(?:CDLL|WinDLL|cdll|windll)\s*\(/,
    description: "Cython: ctypes dynamic library loading"
  },
  {
    pattern: /cdef\s+extern\s+from\s+["'][^"']*\.h["']/,
    description: "Cython: extern C header import (FFI)"
  },
  {
    pattern: /cdef\s+(?:int|char\s*\*|void\s*\*)\s+\w+\s*\(/,
    description: "Cython: C function declaration (low-level FFI)"
  },
  {
    pattern: /subprocess|os\.system|os\.popen/,
    description: "Cython: subprocess/os.system usage"
  },
  {
    pattern: /cffi|ffi\.cdef|ffi\.dlopen/,
    description: "Cython: cffi/ffi usage"
  },
  {
    pattern: /socket\.(?:connect|bind|listen|sendto)\s*\(/,
    description: "Cython: network socket usage"
  }
];

// ---------------------------------------------------------------------------
// File reading helpers
// ---------------------------------------------------------------------------

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

async function walkCythonFiles(root: string): Promise<string[]> {
  const found: string[] = [];

  async function recurse(dir: string, depth: number): Promise<void> {
    if (depth > MAX_WALK_DEPTH || found.length >= MAX_CYTHON_FILES) return;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (found.length >= MAX_CYTHON_FILES) break;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === "node_modules" || entry.name === ".git" || entry.name.startsWith("__pycache__")) {
          continue;
        }
        await recurse(full, depth + 1);
      } else if (entry.isFile() && CYTHON_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
        found.push(path.relative(root, full));
      }
    }
  }

  await recurse(root, 0);
  return found;
}

// ---------------------------------------------------------------------------
// Build system detection
// ---------------------------------------------------------------------------

function detectBuildSystem(
  pyprojectContent: string | null,
  setupPyContent: string | null,
  setupCfgContent: string | null
): BuildSystemType {
  for (const bp of BUILD_SYSTEM_PATTERNS) {
    if (pyprojectContent && bp.pyprojectPattern?.test(pyprojectContent)) {
      return bp.system;
    }
    if (setupPyContent && bp.setupPyPattern?.test(setupPyContent)) {
      return bp.system;
    }
    if (setupCfgContent && bp.setupCfgPattern?.test(setupCfgContent)) {
      return bp.system;
    }
  }

  // If pyproject.toml exists but no recognized backend, it's still "other"
  if (pyprojectContent && pyprojectContent.includes("[build-system]")) {
    return "other";
  }

  // setup.py without setuptools import is still likely setuptools
  if (setupPyContent) {
    return "setuptools";
  }

  // setup.cfg alone
  if (setupCfgContent) {
    return "setuptools";
  }

  return "other";
}

// ---------------------------------------------------------------------------
// Pattern scanning helpers
// ---------------------------------------------------------------------------

function scanForPatterns<T extends { pattern: RegExp; description: string }>(
  content: string,
  patterns: T[]
): string[] {
  const found: string[] = [];
  for (const { pattern, description } of patterns) {
    if (pattern.test(content)) {
      found.push(description);
    }
  }
  return found;
}

function extractEvidence(content: string, pattern: RegExp, maxLen = 120): string | null {
  const match = pattern.exec(content);
  if (!match) return null;
  const start = Math.max(0, match.index - 20);
  const end = Math.min(content.length, match.index + match[0].length + 40);
  const snippet = content.slice(start, end).replace(/\s+/g, " ").trim();
  return snippet.length > maxLen ? snippet.slice(0, maxLen) + "…" : snippet;
}

function detectHooks(content: string, filePath: string): string[] {
  const hooks: string[] = [];
  for (const { pattern, hookName } of HOOK_PATTERNS) {
    if (pattern.test(content)) {
      hooks.push(`${hookName} (${filePath})`);
    }
  }
  return hooks;
}

// ---------------------------------------------------------------------------
// Cython file analysis
// ---------------------------------------------------------------------------

export async function analyzeCythonFile(
  packageRoot: string,
  relPath: string
): Promise<CythonFileAnalysis> {
  const absPath = path.join(packageRoot, relPath);
  const content = await readFileCapped(absPath);

  if (!content) {
    return { filePath: relPath, hasSystemCalls: false, hasFfiUsage: false, suspiciousSnippets: [] };
  }

  const snippets: string[] = [];

  for (const { pattern, description } of CYTHON_SUSPICIOUS_PATTERNS) {
    const evidence = extractEvidence(content, pattern);
    if (evidence) {
      snippets.push(`${description}: ${evidence}`);
    }
  }

  const hasSystemCalls = CYTHON_SUSPICIOUS_PATTERNS
    .filter((p) => p.description.includes("system") || p.description.includes("subprocess") || p.description.includes("popen") || p.description.includes("exec"))
    .some((p) => p.pattern.test(content));

  const hasFfiUsage = CYTHON_SUSPICIOUS_PATTERNS
    .filter((p) => p.description.includes("FFI") || p.description.includes("ffi") || p.description.includes("ctypes") || p.description.includes("extern"))
    .some((p) => p.pattern.test(content));

  return { filePath: relPath, hasSystemCalls, hasFfiUsage, suspiciousSnippets: snippets };
}

// ---------------------------------------------------------------------------
// Main analyzer
// ---------------------------------------------------------------------------

/**
 * Perform a deep analysis of a PyPI source distribution's build system.
 *
 * @param packageRoot  Absolute path to the extracted sdist root directory.
 * @returns Structured build analysis including build system type, hooks, and
 *          Cython extension inventory.
 */
export async function analyzePypiBuildSystem(packageRoot: string): Promise<PypiBuildAnalysis> {
  const analyzedFiles: string[] = [];

  // Read all build configuration files
  const pyprojectContent = await readFileCapped(path.join(packageRoot, "pyproject.toml"));
  if (pyprojectContent !== null) analyzedFiles.push("pyproject.toml");

  const setupPyContent = await readFileCapped(path.join(packageRoot, "setup.py"));
  if (setupPyContent !== null) analyzedFiles.push("setup.py");

  const setupCfgContent = await readFileCapped(path.join(packageRoot, "setup.cfg"));
  if (setupCfgContent !== null) analyzedFiles.push("setup.cfg");

  const conftestContent = await readFileCapped(path.join(packageRoot, "conftest.py"));
  if (conftestContent !== null) analyzedFiles.push("conftest.py");

  // Detect build system
  const buildSystemType = detectBuildSystem(pyprojectContent, setupPyContent, setupCfgContent);

  // Walk Cython files
  const rawCythonFiles = await walkCythonFiles(packageRoot);

  // Collect hooks, suspicious patterns across all build configs
  const detectedHooks: string[] = [];
  const suspiciousPatterns: string[] = [];

  const buildConfigs: Array<[string, string]> = [];
  if (setupPyContent) buildConfigs.push(["setup.py", setupPyContent]);
  if (setupCfgContent) buildConfigs.push(["setup.cfg", setupCfgContent]);
  if (pyprojectContent) buildConfigs.push(["pyproject.toml", pyprojectContent]);
  if (conftestContent) buildConfigs.push(["conftest.py", conftestContent]);

  for (const [filePath, content] of buildConfigs) {
    // Hook detection
    detectedHooks.push(...detectHooks(content, filePath));

    // Shell execution patterns
    for (const { pattern, description } of SHELL_EXECUTION_PATTERNS) {
      const evidence = extractEvidence(content, pattern);
      if (evidence) {
        suspiciousPatterns.push(`${description} in ${filePath}: ${evidence}`);
      }
    }

    // Eval / dynamic code generation patterns
    for (const { pattern, description } of EVAL_PATTERNS) {
      const evidence = extractEvidence(content, pattern);
      if (evidence) {
        suspiciousPatterns.push(`${description} in ${filePath}: ${evidence}`);
      }
    }

    // ext_modules — indicates C/Cython extensions are compiled at install time
    if (/ext_modules\s*=/.test(content)) {
      detectedHooks.push(`ext_modules declaration in ${filePath} (compiles native code at install time)`);
    }

    // External script invocations
    if (/open\s*\(\s*(?:os\.path\.join|__file__)[^)]*\)\s*(?:\.read\(\)|as\s+f)/.test(content)) {
      suspiciousPatterns.push(`file read at build time in ${filePath}: reading local files during setup`);
    }

    // Network access in setup
    if (/(?:urllib|requests|http\.client|httpx)\s*\./.test(content)) {
      suspiciousPatterns.push(`network access in ${filePath}: HTTP calls during build/install`);
    }
  }

  // Deduplicate
  const uniqueHooks = [...new Set(detectedHooks)];
  const uniquePatterns = [...new Set(suspiciousPatterns)];

  return {
    buildSystemType,
    threatDetails: {
      detectedHooks: uniqueHooks,
      cythonFiles: rawCythonFiles,
      suspiciousPatterns: uniquePatterns
    },
    analyzedFiles
  };
}

/**
 * Analyze Cython files found in a package tree for system calls, FFI usage,
 * and other suspicious native interop patterns.
 *
 * @param packageRoot  Absolute path to the extracted package root.
 * @param cythonFiles  Relative paths of .pyx / .pxd files (from analyzePypiBuildSystem).
 * @returns Per-file analysis results.
 */
export async function analyzeCythonFiles(
  packageRoot: string,
  cythonFiles: string[]
): Promise<CythonFileAnalysis[]> {
  const results: CythonFileAnalysis[] = [];
  for (const relPath of cythonFiles) {
    results.push(await analyzeCythonFile(packageRoot, relPath));
  }
  return results;
}
