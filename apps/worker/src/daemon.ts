import { aggregatePackageRiskWithManifest } from "@binshield/risk-engine";

import type { QueuedJob, SupabaseWorkerConfig } from "./supabase-store";
import { SupabaseWorkerStore } from "./supabase-store";
import { WorkerRuntime } from "./pipeline";
import { lookupKnownMalware } from "./malware-feed";
import {
  createLiveClassifierProvider,
  createLiveDecompilerProvider,
  createLiveScriptAnalyzerProvider
} from "./providers";
import { runAlertLoop } from "./alert-loop";
import { YaraScanner } from "./yara-scanner";
import type { WorkerScanRequest } from "./types";

export interface DaemonConfig extends SupabaseWorkerConfig {
  /** Milliseconds between poll cycles. Default 5000. */
  pollIntervalMs: number;
  /** Maximum number of jobs processed concurrently. Default 2. */
  maxConcurrent: number;
  /** Resend API key for email alerts. Empty string disables alerts. */
  sendgridApiKey: string;
  /** From address for alert emails. */
  fromEmail: string;
}

function log(message: string) {
  console.log(`[BinShield Worker] ${message}`);
}

function logError(message: string, error?: unknown) {
  const detail =
    error instanceof Error ? error.message : error !== undefined ? String(error) : "";
  console.error(`[BinShield Worker] ${message}${detail ? `: ${detail}` : ""}`);
}

/**
 * Long-running daemon that polls Supabase for queued analysis jobs,
 * processes them through the worker pipeline, and persists results.
 */
export class WorkerDaemon {
  private readonly store: SupabaseWorkerStore;
  private readonly runtime: WorkerRuntime;
  private readonly config: DaemonConfig;
  private readonly yara = new YaraScanner();

  private timer: ReturnType<typeof setInterval> | null = null;
  private activeJobs = 0;
  private stopping = false;

  constructor(config: DaemonConfig) {
    this.config = config;
    this.store = new SupabaseWorkerStore({
      supabaseUrl: config.supabaseUrl,
      supabaseServiceRoleKey: config.supabaseServiceRoleKey,
    });
    this.runtime = new WorkerRuntime();
  }

  /** Start the polling loop. Resolves once the first poll cycle fires. */
  async start(): Promise<void> {
    log("Starting daemon mode");
    log(`Polling interval: ${this.config.pollIntervalMs}ms`);
    log(`Max concurrent: ${this.config.maxConcurrent}`);
    log(`Supabase: ${this.config.supabaseUrl}`);

    // Upgrade to live providers (Ghidra Docker + Grok AI) if available
    try {
      const liveDecompiler = await createLiveDecompilerProvider();
      const liveClassifier = await createLiveClassifierProvider();
      const liveScriptAnalyzer = await createLiveScriptAnalyzerProvider();
      const services = (
        this.runtime as unknown as {
          services: { decompiler: unknown; classifier: unknown; scriptAnalyzer: unknown };
        }
      ).services;
      services.decompiler = liveDecompiler;
      services.classifier = liveClassifier;
      services.scriptAnalyzer = liveScriptAnalyzer;
      log("Live providers loaded (Ghidra Docker + Grok AI + install-script analysis)");
    } catch {
      log("Using default providers (heuristic fallback)");
    }

    // Wire up graceful shutdown
    const onSignal = () => {
      this.stop();
    };
    process.on("SIGTERM", onSignal);
    process.on("SIGINT", onSignal);

    // Run an initial poll immediately, then schedule the interval
    await this.poll();

    this.timer = setInterval(() => {
      void this.poll();
    }, this.config.pollIntervalMs);
  }

  /** Signal the daemon to stop. In-flight jobs will finish, but no new jobs are claimed. */
  stop(): void {
    if (this.stopping) {
      return;
    }
    this.stopping = true;
    log("Shutting down (in-flight jobs will finish)...");

    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  // ---------------------------------------------------------------------------
  // Internal
  // ---------------------------------------------------------------------------

  private async poll(): Promise<void> {
    if (this.stopping) {
      return;
    }

    const available = this.config.maxConcurrent - this.activeJobs;
    if (available <= 0) {
      return;
    }

    try {
      const queued = await this.store.pollQueuedJobs(available);
      for (const job of queued) {
        if (this.stopping) {
          break;
        }

        const claimed = await this.store.claimJob(job.id);
        if (!claimed) {
          // Another worker grabbed it first — skip
          continue;
        }

        this.activeJobs++;
        // Fire-and-forget: processJob handles its own error reporting
        void this.processJob(job).finally(() => {
          this.activeJobs--;
        });
      }
    } catch (error) {
      logError("Poll cycle failed", error);
    }
  }

  private async processJob(job: QueuedJob): Promise<void> {
    log(`Job ${job.id}: starting ${job.ecosystem}/${job.packageName}@${job.version}`);

    const request: WorkerScanRequest = {
      ecosystem: job.ecosystem,
      packageName: job.packageName,
      version: job.version,
      packageSource: "install",
    };

    try {
      const outcome = await this.runtime.run(request);

      // Post-process: run YARA scanning on discovered artifacts (fire-and-forget enrichment)
      for (const artifact of outcome.artifacts) {
        try {
          const yaraResult = await this.yara.scan(artifact);
          if (yaraResult.findings.length > 0) {
            // Merge YARA findings into the matching binary analysis
            const binary = outcome.analysis.binaries.find((b) => b.filename === artifact.filename);
            if (binary) {
              for (const finding of yaraResult.findings) {
                if (!binary.findings.some((f) => f.title === finding.title)) {
                  binary.findings.push(finding);
                }
              }
            }
          }
        } catch {
          // YARA scan failure is non-fatal — continue with base analysis
        }
      }

      // Cross-reference against the known-malware feed. A confirmed match
      // forces a critical verdict regardless of heuristic/AI analysis.
      const manifest = outcome.analysis.manifestAnalysis;
      if (manifest) {
        try {
          const malware = await lookupKnownMalware(job.ecosystem, job.packageName, job.version);
          if (malware.advisoryIds.length > 0) {
            manifest.knownMalwareAdvisoryIds = malware.advisoryIds;
            manifest.knownMalwareMatches = malware.matches;
            manifest.riskScore = 100;
            manifest.riskLevel = "critical";
            for (const match of malware.matches) {
              if (!manifest.findings.some((finding) => finding.evidence === match.advisoryId)) {
                manifest.findings.push({
                  category: "knownMalware",
                  severity: "critical",
                  title: `Known-malicious package (${match.advisoryId})`,
                  description: match.summary,
                  filePath: `${job.packageName}@${job.version}`,
                  evidence: match.advisoryId,
                  recommendation:
                    "This package is on a public malware advisory. Remove it immediately and rotate any exposed credentials."
                });
              }
            }
            const merged = aggregatePackageRiskWithManifest(outcome.analysis.binaries, manifest);
            outcome.analysis.riskScore = merged.riskScore;
            outcome.analysis.riskLevel = merged.riskLevel;
            log(`Job ${job.id}: matched ${malware.advisoryIds.length} known-malware advisory(ies)`);
          }
        } catch (malwareError) {
          logError(`Job ${job.id}: malware feed lookup failed`, malwareError);
        }
      }

      const analysisId = await this.store.persistAnalysis(outcome.analysis);
      await this.store.completeJob(job.id, analysisId);

      // Fire-and-forget: run the proactive alert loop (matches the package
      // against watchlists + scanned lockfiles, notifies affected orgs).
      // Never blocks job completion.
      runAlertLoop(
        {
          supabaseUrl: this.config.supabaseUrl,
          supabaseServiceRoleKey: this.config.supabaseServiceRoleKey,
          sendgridApiKey: this.config.sendgridApiKey,
          fromEmail: this.config.fromEmail,
        },
        { ecosystem: job.ecosystem, packageName: job.packageName, version: job.version },
        outcome.analysis,
      ).catch((alertError) => {
        logError(`Job ${job.id}: alert loop failed`, alertError);
      });

      log(
        `Job ${job.id}: completed (risk=${outcome.analysis.riskLevel}, binaries=${outcome.analysis.binaryCount})`,
      );
    } catch (error) {
      const message =
        error instanceof Error ? error.message : String(error);
      logError(`Job ${job.id}: failed`, error);
      await this.store.failJob(job.id, message).catch((failError) => {
        logError(`Job ${job.id}: could not mark as failed`, failError);
      });
    }
  }
}
