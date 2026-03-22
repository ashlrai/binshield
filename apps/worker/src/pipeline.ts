import { readFile } from "node:fs/promises";
import path from "node:path";

import type { PackageAnalysis } from "@binshield/analysis-types";
import { aggregatePackageRisk, summarizePackage, scoreBinary } from "@binshield/risk-engine";

import { buildCacheKey, InMemoryAnalysisCache } from "./cache";
import { FileSystemBinaryExtractor } from "./extractor";
import { InMemoryJobStore } from "./job-store";
import {
  createDefaultDecompilerProvider,
  createDefaultClassifierProvider
} from "./providers";
import { LocalDirectoryPackageSource, RegistryPackageSource, createDefaultPackageSource } from "./package-source";
import type {
  AcquiredPackage,
  AnalysisOutcome,
  AnalysisServiceBundle,
  ClassifiedArtifact,
  DecompiledArtifact,
  FingerprintedArtifact,
  PackageManifest,
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

function buildPackageSummary(packageAnalysis: PackageAnalysis): string {
  if (packageAnalysis.binaryCount === 0) {
    return `${packageAnalysis.packageName}@${packageAnalysis.version} has no native binaries in the scanned package tree.`;
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
  }>
): PackageAnalysis {
  const binaries = classifiedArtifacts.map(({ fingerprint, decompiled, classified }) => {
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
      findings: classified.findings
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
    binaries
  };

  const aggregate = aggregatePackageRisk(binaries);
  packageAnalysis.riskScore = aggregate.riskScore;
  packageAnalysis.riskLevel = aggregate.riskLevel;
  packageAnalysis.summary = buildPackageSummary(packageAnalysis);
  return packageAnalysis;
}

function createAcquisitionForRequest(request: WorkerScanRequest, acquisition: AnalysisServiceBundle["acquisition"]) {
  if (request.packageRoot) {
    return new LocalDirectoryPackageSource(request.packageRoot);
  }

  if (request.packageSource === "registry" || process.env.BINSHIELD_PACKAGE_SOURCE === "registry") {
    return new RegistryPackageSource();
  }

  return acquisition;
}

export class WorkerRuntime {
  constructor(private readonly services: AnalysisServiceBundle = createDefaultBundle()) {}

  submit(request: WorkerScanRequest) {
    const cacheKey = buildCacheKey(request, [request.packageRoot ?? request.packageSource ?? "pending"]);
    return this.services.jobs.submit(request, cacheKey);
  }

  async process(jobId: string): Promise<AnalysisOutcome> {
    const submitted = this.services.jobs.start(jobId);
    const request = submitted.request;
    const packageSource = createAcquisitionForRequest(request, this.services.acquisition);

    const acquired = await packageSource.acquire(request);
    const artifacts = await this.services.extraction.discover(acquired.packageRoot);
    const artifactHashes = artifacts.map((artifact) => artifact.sha256);
    const cacheKey = buildCacheKey(request, artifactHashes);

    const cached = !request.forceReanalyze ? this.services.cache.get(cacheKey) : undefined;
    if (cached) {
      const completed = this.services.jobs.cache(jobId, cached.analysis, artifactHashes, cacheKey);
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
    }> = [];

    for (const fingerprint of artifacts) {
      const decompiled = await this.services.decompiler.decompile({
        packageRequest: request,
        packageRoot: acquired.packageRoot,
        artifact: fingerprint
      });

      const classified = await this.services.classifier.classify({
        packageRequest: request,
        packageRoot: acquired.packageRoot,
        artifact: fingerprint,
        decompiled
      });

      classifiedArtifacts.push({ fingerprint, decompiled, classified });
    }

    const analysis = toAnalysisPackage(request, acquired.manifest, classifiedArtifacts);
    this.services.cache.set({
      cacheKey,
      artifactHashes,
      analysis,
      createdAt: new Date().toISOString()
    });

    const completed = this.services.jobs.complete(jobId, analysis, artifactHashes, cacheKey);
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
