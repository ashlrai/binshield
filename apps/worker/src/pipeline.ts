import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";

import type { ManifestAnalysis, PackageAnalysis } from "@binshield/analysis-types";
import { AnalyticsCollector } from "@binshield/analytics-collector";
import { AnalyzerRegistry, getSharedMatchingEngine } from "@binshield/malware-engines";
import type { OsvMatchResult } from "@binshield/malware-engines";
import { aggregatePackageRiskWithManifest, summarizePackage, scoreBinary } from "@binshield/risk-engine";
import { SupplyChainHealthAnalyzer, toHealthFinding } from "@binshield/supply-chain-health";

import { buildCacheKey, InMemoryAnalysisCache } from "./cache";
import { FileSystemBinaryExtractor } from "./extractor";
import { InMemoryJobStore } from "./job-store";
import {
  createDefaultDecompilerProvider,
  createDefaultClassifierProvider,
  createDefaultScriptAnalyzerProvider
} from "./providers";
import {
  InstallPackageSource,
  LocalDirectoryPackageSource,
  PyPiPackageSource,
  RegistryPackageSource,
  createDefaultPackageSource
} from "./package-source";
import type {
  AcquiredPackage,
  AnalysisOutcome,
  AnalysisServiceBundle,
  ClassifiedArtifact,
  DecompiledArtifact,
  FingerprintedArtifact,
  PackageManifest,
  ScriptAnalysisInput,
  WorkerScanRequest
} from "./types";

function defaultDemoPackageRoot(): string {
  return path.resolve(new URL("../fixtures/sample-package", import.meta.url).pathname);
}

function collapsePackageConfidence(values: Array<"low" | "medium" | "high">): "low" | "medium" | "high" {
  if (values.length === 0) {
    return "low";
  }
  if (values.every((value) => value === "high")) {
    return "high";
  }
  if (values.some((value) => value === "low")) {
    return "low";
  }
  return "medium";
}

function createDefaultBundle(demoPackageRoot = defaultDemoPackageRoot()): AnalysisServiceBundle {
  return {
    acquisition: createDefaultPackageSource(demoPackageRoot),
    extraction: new FileSystemBinaryExtractor(),
    decompiler: createDefaultDecompilerProvider(),
    classifier: createDefaultClassifierProvider(),
    scriptAnalyzer: createDefaultScriptAnalyzerProvider(),
    cache: new InMemoryAnalysisCache(),
    jobs: new InMemoryJobStore()
  };
}

async function loadManifest(packageRoot: string): Promise<PackageManifest> {
  const content = await readFile(path.join(packageRoot, "package.json"), "utf8");
  const raw = JSON.parse(content) as Partial<PackageManifest> & {
    name?: string;
    version?: string;
    scripts?: Record<string, string>;
    dependencies?: Record<string, string>;
    optionalDependencies?: Record<string, string>;
  };

  return {
    name: raw.name ?? "unknown-package",
    version: raw.version ?? "0.0.0",
    scripts: raw.scripts ?? {},
    dependencies: raw.dependencies ?? {},
    optionalDependencies: raw.optionalDependencies ?? {}
  };
}

/**
 * Stable hash of the install-script analysis, mixed into the cache key so a
 * malicious script change invalidates a cached result even when the package's
 * native binaries are byte-for-byte unchanged.
 */
function manifestFingerprint(analysis: ManifestAnalysis): string {
  const stable = JSON.stringify({
    hooks: analysis.lifecycleHooks,
    files: [...analysis.analyzedFiles].sort(),
    findings: analysis.findings
      .map((finding) => `${finding.category}|${finding.filePath}|${finding.title}|${finding.evidence}`)
      .sort(),
    malware: [...analysis.knownMalwareAdvisoryIds].sort()
  });
  return createHash("sha256").update(stable).digest("hex").slice(0, 16);
}

function buildPackageSummary(packageAnalysis: PackageAnalysis): string {
  const manifestFindings = packageAnalysis.manifestAnalysis?.findings.length ?? 0;
  if (packageAnalysis.binaryCount === 0 && manifestFindings === 0) {
    return `${packageAnalysis.packageName}@${packageAnalysis.version} has no native binaries and no notable install-script behavior.`;
  }

  return summarizePackage(packageAnalysis);
}

function toAnalysisPackage(
  request: WorkerScanRequest,
  manifest: PackageManifest,
  classifiedArtifacts: Array<{
    fingerprint: FingerprintedArtifact;
    decompiled: { pseudoSource: string; imports: string[]; strings: string[]; functionCount: number; callTargets: string[]; confidence: number };
    classified: ClassifiedArtifact;
    malwareDetectionResults?: import("@binshield/analysis-types").MalwareDetectionResult[];
  }>,
  manifestAnalysis: ManifestAnalysis,
  supplyChainHealth?: import("@binshield/analysis-types").SupplyChainHealthResult
): PackageAnalysis {
  const binaries = classifiedArtifacts.map(({ fingerprint, decompiled, classified, malwareDetectionResults }) => {
    const scored = scoreBinary({
      behaviors: classified.behaviors,
      findings: classified.findings,
      importCount: decompiled.imports.length,
      functionCount: decompiled.functionCount
    });

    return {
      id: `${request.packageName}_${fingerprint.sha256.slice(0, 12)}`,
      filename: fingerprint.filename,
      architecture: fingerprint.architecture,
      format: fingerprint.format,
      fileSize: fingerprint.fileSize,
      functionCount: decompiled.functionCount,
      importCount: decompiled.imports.length,
      riskScore: scored.riskScore,
      riskLevel: scored.riskLevel,
      decompiledPreview: decompiled.pseudoSource,
      aiExplanation: classified.explanation,
      imports: decompiled.imports,
      strings: decompiled.strings,
      behaviors: classified.behaviors,
      findings: classified.findings,
      ...(malwareDetectionResults !== undefined ? { malwareDetectionResults } : {})
    };
  });

  const confidence = collapsePackageConfidence(classifiedArtifacts.map(({ classified }) => classified.sourceMatchConfidence));
  const packageAnalysis: PackageAnalysis = {
    id: `${request.packageName}_${request.version}`,
    ecosystem: request.ecosystem,
    packageName: manifest.name || request.packageName,
    version: manifest.version || request.version,
    status: "complete",
    riskScore: 0,
    riskLevel: "none",
    summary: "",
    sourceMatchConfidence: confidence,
    binaryCount: binaries.length,
    totalBinarySize: binaries.reduce((total, binary) => total + binary.fileSize, 0),
    aiModel: "binshield-worker",
    createdAt: new Date().toISOString(),
    binaries,
    manifestAnalysis,
    ...(supplyChainHealth !== undefined ? { supplyChainHealth } : {})
  };

  const aggregate = aggregatePackageRiskWithManifest(binaries, manifestAnalysis);
  packageAnalysis.riskScore = aggregate.riskScore;
  packageAnalysis.riskLevel = aggregate.riskLevel;
  packageAnalysis.summary = buildPackageSummary(packageAnalysis);
  return packageAnalysis;
}

function createAcquisitionForRequest(request: WorkerScanRequest, acquisition: AnalysisServiceBundle["acquisition"]) {
  if (request.packageRoot) {
    return new LocalDirectoryPackageSource(request.packageRoot);
  }

  if (request.ecosystem === "pypi") {
    return new PyPiPackageSource();
  }

  if (request.packageSource === "install") {
    return new InstallPackageSource();
  }

  if (request.packageSource === "registry" || process.env.BINSHIELD_PACKAGE_SOURCE === "registry") {
    return new RegistryPackageSource();
  }

  return acquisition;
}

// Module-level analytics collector for the worker process.
// Demo mode is auto-detected from BINSHIELD_DEMO env var; no Supabase
// credentials are needed when running locally.
const workerAnalytics = new AnalyticsCollector({
  supabaseUrl: process.env.SUPABASE_URL,
  supabaseServiceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY
});

export class WorkerRuntime {
  constructor(private readonly services: AnalysisServiceBundle = createDefaultBundle()) {}

  submit(request: WorkerScanRequest) {
    const cacheKey = buildCacheKey(request, [request.packageRoot ?? request.packageSource ?? "pending"]);
    return this.services.jobs.submit(request, cacheKey);
  }

  async process(jobId: string): Promise<AnalysisOutcome> {
    const submitted = this.services.jobs.start(jobId);
    const request = submitted.request;
    const pipelineStart = Date.now();
    const packageSource = createAcquisitionForRequest(request, this.services.acquisition);

    const acquired = await packageSource.acquire(request);
    const scriptInput: ScriptAnalysisInput = {
      packageRequest: request,
      packageRoot: acquired.packageRoot,
      manifest: acquired.manifest,
      buildSystemType: acquired.buildSystemType,
      pythonBuildThreatDetails: acquired.pythonBuildThreatDetails
    };
    // OSV malware feed cross-reference — runs before AI classification so that
    // known-worm packages are flagged immediately without waiting for the full
    // binary analysis pipeline.  The MatchingEngine is in-memory so this is
    // synchronous and <5ms.  Results are attached to the manifest analysis via
    // the knownMalwareAdvisoryIds / knownMalwareMatches fields.
    const osvEcosystem = request.ecosystem === "pypi" ? "PyPI" : "npm";
    const osvMatchResult: OsvMatchResult = getSharedMatchingEngine().match(
      request.packageName,
      request.version,
      osvEcosystem
    );

    if (osvMatchResult.matched) {
      console.log(
        `[BinShield] OSV malware match (${osvMatchResult.matchType}): ` +
          `${request.packageName}@${request.version} — ` +
          osvMatchResult.findings.map((f) => f.advisoryId).join(", ")
      );
    }

    // Install-script analysis runs concurrently with binary discovery — it is
    // independent of the binaries and feeds the cache key below.
    const [artifacts, manifestAnalysis] = await Promise.all([
      this.services.extraction.discover(acquired.packageRoot),
      this.services.scriptAnalyzer.analyze(scriptInput)
    ]);

    // Merge OSV match findings into the manifest analysis so they appear in
    // the knownMalwareAdvisoryIds list and affect risk scoring downstream.
    if (osvMatchResult.matched && osvMatchResult.findings.length > 0) {
      const existingIds = new Set(manifestAnalysis.knownMalwareAdvisoryIds);
      for (const finding of osvMatchResult.findings) {
        if (!existingIds.has(finding.advisoryId)) {
          manifestAnalysis.knownMalwareAdvisoryIds.push(finding.advisoryId);
          existingIds.add(finding.advisoryId);
        }
      }
      // Attach structured match objects for provenance (advisory ID + link)
      if (!manifestAnalysis.knownMalwareMatches) {
        manifestAnalysis.knownMalwareMatches = [];
      }
      const existingMatchIds = new Set(
        manifestAnalysis.knownMalwareMatches.map((m) => m.advisoryId)
      );
      for (const finding of osvMatchResult.findings) {
        if (!existingMatchIds.has(finding.advisoryId)) {
          manifestAnalysis.knownMalwareMatches.push({
            advisoryId: finding.advisoryId,
            source: "osv",
            summary: finding.summary,
            url: finding.advisoryUrl,
          });
          existingMatchIds.add(finding.advisoryId);
        }
      }
    }
    const artifactHashes = artifacts.map((artifact) => artifact.sha256);
    const cacheKey = buildCacheKey(request, [
      ...artifactHashes,
      `manifest:${manifestFingerprint(manifestAnalysis)}`
    ]);

    const cached = !request.forceReanalyze ? this.services.cache.get(cacheKey) : undefined;
    if (cached) {
      const completed = this.services.jobs.cache(jobId, cached.analysis, artifactHashes, cacheKey);
      workerAnalytics.scanCompleted({
        ecosystem: request.ecosystem,
        packageName: request.packageName,
        version: request.version,
        binaryCount: cached.analysis.binaryCount,
        durationMs: Date.now() - pipelineStart,
        riskLevel: cached.analysis.riskLevel as "none" | "low" | "medium" | "high" | "critical",
        riskScore: cached.analysis.riskScore,
        cached: true
      });
      return {
        job: completed,
        analysis: cached.analysis,
        artifacts
      };
    }

    const classifiedArtifacts: Array<{
      fingerprint: FingerprintedArtifact;
      decompiled: DecompiledArtifact;
      classified: ClassifiedArtifact;
      malwareDetectionResults?: import("@binshield/analysis-types").MalwareDetectionResult[];
    }> = [];

    // Create the malware-engines registry once per process call so all
    // artifacts share the same instance.
    const malwareRegistry = AnalyzerRegistry.createDefault();

    for (const fingerprint of artifacts) {
      const binaryBuffer = Buffer.from(fingerprint.bytes);

      // Stage 1: decompile the binary (classifier depends on its output).
      const decompiled = await this.services.decompiler.decompile({
        packageRequest: request,
        packageRoot: acquired.packageRoot,
        artifact: fingerprint
      });

      // Stage 2: run classifier and malware-engines registry in parallel.
      // The registry works directly on raw bytes and is independent of
      // decompiled output, so these two can safely run concurrently.
      const [classified, malwareRun] = await Promise.all([
        this.services.classifier.classify({
          packageRequest: request,
          packageRoot: acquired.packageRoot,
          artifact: fingerprint,
          decompiled
        }),
        malwareRegistry.runAll(binaryBuffer)
      ]);

      const malwareDetectionResults: import("@binshield/analysis-types").MalwareDetectionResult[] =
        malwareRun.results.map((r) => ({
          analyzerName: r.analyzerName,
          analyzerVersion: r.analyzerVersion,
          detected: r.detected,
          signals: r.signals,
          confidence: r.confidence
        }));

      classifiedArtifacts.push({
        fingerprint,
        decompiled,
        classified,
        malwareDetectionResults
      });
    }

    // Supply-chain health analysis — runs after binary classification since it
    // only needs registry metadata (already present in acquired.manifest) and
    // the dependency graph from the manifest.  Runs best-effort: failures are
    // caught so they never block the main analysis pipeline.
    let supplyChainHealth: import("@binshield/analysis-types").SupplyChainHealthResult | undefined;
    try {
      const schAnalyzer = new SupplyChainHealthAnalyzer();
      const directDeps = Object.keys(acquired.manifest.dependencies ?? {});
      const depGraph: Record<string, string[]> = {};
      for (const dep of directDeps) {
        depGraph[dep] = [];
      }
      const registryMeta =
        request.ecosystem === "pypi"
          ? SupplyChainHealthAnalyzer.buildPypiMetadata({
              info: {
                name: acquired.manifest.name,
                version: acquired.manifest.version,
                license: null,
                requires_dist: directDeps,
                author: null,
                maintainer: null,
              },
              releases: {},
            })
          : SupplyChainHealthAnalyzer.buildNpmMetadata({
              name: acquired.manifest.name,
              versions: {
                [acquired.manifest.version]: {
                  dependencies: acquired.manifest.dependencies ?? {},
                  license: undefined,
                },
              },
              maintainers: [],
            });
      supplyChainHealth = schAnalyzer.analyze(
        registryMeta,
        acquired.manifest.version,
        depGraph,
        directDeps
      ) as unknown as import("@binshield/analysis-types").SupplyChainHealthResult;
    } catch (err) {
      console.warn(
        "[BinShield] supply-chain health analysis failed (non-fatal):",
        err instanceof Error ? err.message : err
      );
    }

    const analysis = toAnalysisPackage(request, acquired.manifest, classifiedArtifacts, manifestAnalysis, supplyChainHealth);
    this.services.cache.set({
      cacheKey,
      artifactHashes,
      analysis,
      createdAt: new Date().toISOString()
    });

    const completed = this.services.jobs.complete(jobId, analysis, artifactHashes, cacheKey);

    // Emit scan_completed analytics event (fire-and-forget, never throws)
    try {
      workerAnalytics.scanCompleted({
        ecosystem: request.ecosystem,
        packageName: request.packageName,
        version: request.version,
        binaryCount: analysis.binaryCount,
        durationMs: Date.now() - pipelineStart,
        riskLevel: analysis.riskLevel as "none" | "low" | "medium" | "high" | "critical",
        riskScore: analysis.riskScore,
        cached: false
      });
    } catch {
      // analytics must never block the pipeline
    }

    return {
      job: completed,
      analysis,
      artifacts
    };
  }

  async run(request: WorkerScanRequest): Promise<AnalysisOutcome> {
    const job = this.submit(request);
    return this.process(job.id);
  }

  async analyze(request: WorkerScanRequest): Promise<PackageAnalysis> {
    const outcome = await this.run(request);
    return outcome.analysis;
  }

  async resolvePackage(request: WorkerScanRequest): Promise<AcquiredPackage> {
    const source = createAcquisitionForRequest(request, this.services.acquisition);
    return source.acquire(request);
  }

  getJob(jobId: string) {
    return this.services.jobs.get(jobId);
  }

  listJobs() {
    return this.services.jobs.list();
  }

  jobEvents(jobId: string) {
    return this.services.jobs.events(jobId);
  }
}

export class AnalysisPipeline {
  constructor(private readonly runtime = new WorkerRuntime()) {}

  async analyze(request: WorkerScanRequest): Promise<PackageAnalysis> {
    return this.runtime.analyze(request);
  }

  submit(request: WorkerScanRequest) {
    return this.runtime.submit(request);
  }

  async process(jobId: string): Promise<AnalysisOutcome> {
    return this.runtime.process(jobId);
  }

  async run(request: WorkerScanRequest): Promise<AnalysisOutcome> {
    return this.runtime.run(request);
  }

  getJob(jobId: string) {
    return this.runtime.getJob(jobId);
  }

  listJobs() {
    return this.runtime.listJobs();
  }
}
