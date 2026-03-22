import { execFile } from "node:child_process";
import { mkdir, writeFile, readFile, unlink, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, basename } from "node:path";
import { randomUUID } from "node:crypto";

import type {
  DecompiledArtifact,
  DecompilerProvider,
  FingerprintedArtifact,
  WorkerScanRequest,
} from "./types";

/** Configuration for the Ghidra Docker decompiler provider. */
export interface GhidraProviderOptions {
  /** Docker image name. Defaults to "binshield/ghidra-worker:latest". */
  image?: string;
  /** Maximum analysis time in milliseconds. Defaults to 5 minutes. */
  timeoutMs?: number;
  /** Extra Docker run flags (e.g. ["--network", "none"]). */
  dockerFlags?: string[];
  /** Path to the docker executable. Defaults to "docker". */
  dockerBin?: string;
  /** Memory limit for the Docker container. Defaults to "4g". */
  memoryLimit?: string;
  /** CPU limit for the Docker container. Defaults to "2.0". */
  cpuLimit?: string;
}

const DEFAULT_IMAGE = "binshield/ghidra-worker:latest";
const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes
const DEFAULT_MEMORY_LIMIT = "4g";
const DEFAULT_CPU_LIMIT = "2.0";

/**
 * Decompiler provider that runs Ghidra headless analysis inside a Docker
 * container. The provider writes the binary artifact to a temp directory,
 * bind-mounts it into a fresh container, and parses the JSON result produced
 * by the Ghidra postScript.
 */
export class GhidraDockerDecompilerProvider implements DecompilerProvider {
  readonly name = "ghidra-docker";

  private readonly image: string;
  private readonly timeoutMs: number;
  private readonly dockerFlags: string[];
  private readonly dockerBin: string;
  private readonly memoryLimit: string;
  private readonly cpuLimit: string;

  constructor(options: GhidraProviderOptions = {}) {
    this.image = options.image ?? process.env.BINSHIELD_GHIDRA_IMAGE ?? DEFAULT_IMAGE;
    this.timeoutMs = options.timeoutMs ?? toIntEnv("BINSHIELD_GHIDRA_TIMEOUT_MS", DEFAULT_TIMEOUT_MS);
    this.dockerFlags = options.dockerFlags ?? [];
    this.dockerBin = options.dockerBin ?? "docker";
    this.memoryLimit = options.memoryLimit ?? DEFAULT_MEMORY_LIMIT;
    this.cpuLimit = options.cpuLimit ?? DEFAULT_CPU_LIMIT;
  }

  async decompile(input: {
    packageRequest: WorkerScanRequest;
    packageRoot: string;
    artifact: FingerprintedArtifact;
  }): Promise<DecompiledArtifact> {
    const runId = randomUUID().slice(0, 12);
    const workDir = join(tmpdir(), `binshield-ghidra-${runId}`);
    const inputDir = join(workDir, "input");
    const outputDir = join(workDir, "output");

    await mkdir(inputDir, { recursive: true });
    await mkdir(outputDir, { recursive: true });

    const binaryFilename = sanitizeFilename(input.artifact.filename);
    const binaryPath = join(inputDir, binaryFilename);
    const outputPath = join(outputDir, "result.json");

    try {
      // Write the binary bytes to the temp input directory
      await writeFile(binaryPath, input.artifact.bytes);

      // Build docker run arguments
      const containerInputPath = `/work/input/${binaryFilename}`;
      const containerOutputPath = "/work/output/result.json";

      const args = buildDockerArgs({
        dockerFlags: this.dockerFlags,
        image: this.image,
        inputDir,
        outputDir,
        memoryLimit: this.memoryLimit,
        cpuLimit: this.cpuLimit,
        containerInputPath,
        containerOutputPath,
        runId,
      });

      // Execute docker run
      await this.runDocker(args);

      // Parse the JSON output
      const rawOutput = await readFile(outputPath, "utf-8");
      const parsed = parseGhidraOutput(rawOutput, input.artifact);

      return parsed;
    } finally {
      // Clean up temp files unconditionally
      await rm(workDir, { recursive: true, force: true }).catch(() => {
        // Swallow cleanup errors -- they should not mask analysis failures
      });
    }
  }

  private runDocker(args: string[]): Promise<string> {
    return new Promise((resolve, reject) => {
      const child = execFile(
        this.dockerBin,
        args,
        {
          maxBuffer: 50 * 1024 * 1024, // 50 MB -- Ghidra can be chatty
          timeout: this.timeoutMs,
          env: { ...process.env },
        },
        (error, stdout, stderr) => {
          if (error) {
            const message = [
              `Ghidra Docker analysis failed: ${error.message}`,
              stderr ? `stderr: ${stderr.slice(0, 2000)}` : "",
            ]
              .filter(Boolean)
              .join("\n");
            reject(new Error(message));
            return;
          }
          resolve(stdout);
        },
      );

      // If the process is killed by timeout, make sure we surface it
      child.on("error", (err) => {
        reject(new Error(`Failed to spawn Docker process: ${err.message}`));
      });
    });
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function toIntEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const parsed = parseInt(raw, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function sanitizeFilename(filename: string): string {
  // Strip path separators and dangerous characters, keep extension
  return basename(filename).replace(/[^a-zA-Z0-9._-]/g, "_") || "binary";
}

function buildDockerArgs(opts: {
  dockerFlags: string[];
  image: string;
  inputDir: string;
  outputDir: string;
  memoryLimit: string;
  cpuLimit: string;
  containerInputPath: string;
  containerOutputPath: string;
  runId: string;
}): string[] {
  return [
    "run",
    "--rm",
    "--name", `binshield-ghidra-${opts.runId}`,
    "--memory", opts.memoryLimit,
    "--cpus", opts.cpuLimit,
    "--network", "none", // no network access for security
    "-v", `${opts.inputDir}:/work/input:ro`,
    "-v", `${opts.outputDir}:/work/output`,
    ...opts.dockerFlags,
    opts.image,
    opts.containerInputPath,
    opts.containerOutputPath,
  ];
}

function parseGhidraOutput(
  raw: string,
  artifact: FingerprintedArtifact,
): DecompiledArtifact {
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    throw new Error(
      `Failed to parse Ghidra JSON output (${raw.length} bytes). ` +
        `First 500 chars: ${raw.slice(0, 500)}`,
    );
  }

  const pseudoSource =
    typeof parsed.pseudoSource === "string" && parsed.pseudoSource.length > 0
      ? parsed.pseudoSource
      : "// Ghidra produced no decompiled output";

  const imports = toStringArray(parsed.imports);
  const strings =
    toStringArray(parsed.strings).length > 0
      ? toStringArray(parsed.strings)
      : artifact.interestingStrings;

  const functionCount =
    typeof parsed.functionCount === "number" && parsed.functionCount >= 0
      ? parsed.functionCount
      : 0;

  const callTargets = toStringArray(parsed.callTargets);

  const confidence =
    typeof parsed.confidence === "number" &&
    parsed.confidence >= 0 &&
    parsed.confidence <= 1
      ? parsed.confidence
      : 0.7;

  return {
    pseudoSource,
    imports,
    strings,
    functionCount,
    callTargets,
    confidence,
  };
}

function toStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string");
}
