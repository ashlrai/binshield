import type { PackageAnalysis, Ecosystem } from "@binshield/analysis-types";

export interface SupabaseWorkerConfig {
  supabaseUrl: string;
  supabaseServiceRoleKey: string;
}

/** A queued job as read from the analysis_jobs table. */
export interface QueuedJob {
  id: string;
  orgId: string | null;
  ecosystem: Ecosystem;
  packageName: string;
  version: string;
  requestedAt: string;
}

interface AnalysisJobRow {
  id: string;
  org_id: string | null;
  ecosystem: Ecosystem;
  package_name: string;
  version: string;
  status: string;
  error: string | null;
  requested_at: string;
  completed_at: string | null;
}

interface PackageRow {
  id: string;
  ecosystem: Ecosystem;
  name: string;
  latest_analyzed_version: string | null;
  total_versions_analyzed: number;
}

/**
 * Supabase persistence layer for the BinShield worker daemon.
 *
 * Uses the PostgREST API with the service-role key so every call
 * bypasses RLS.
 */
export class SupabaseWorkerStore {
  private readonly baseUrl: string;
  private readonly serviceRoleKey: string;

  constructor(config: SupabaseWorkerConfig) {
    this.baseUrl = config.supabaseUrl.replace(/\/$/, "");
    this.serviceRoleKey = config.supabaseServiceRoleKey;
  }

  // ---------------------------------------------------------------------------
  // Low-level helpers (mirrors the pattern in apps/api/src/lib/repository.ts)
  // ---------------------------------------------------------------------------

  private headers(extra: Record<string, string> = {}): Record<string, string> {
    return {
      apikey: this.serviceRoleKey,
      authorization: `Bearer ${this.serviceRoleKey}`,
      "content-type": "application/json",
      ...extra,
    };
  }

  private async request<T>(
    path: string,
    init: RequestInit = {},
  ): Promise<T> {
    const response = await fetch(`${this.baseUrl}/rest/v1${path}`, {
      ...init,
      headers: {
        ...this.headers(),
        ...(init.headers as Record<string, string> | undefined),
      },
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(
        `Supabase request failed (${response.status}): ${text}`,
      );
    }

    if (response.status === 204) {
      return undefined as T;
    }

    return (await response.json()) as T;
  }

  // ---------------------------------------------------------------------------
  // Job queue operations
  // ---------------------------------------------------------------------------

  /** Fetch queued jobs ordered by requested_at ASC. */
  async pollQueuedJobs(limit = 10): Promise<QueuedJob[]> {
    const rows = await this.request<AnalysisJobRow[]>(
      `/analysis_jobs?status=eq.queued&order=requested_at.asc&limit=${limit}`,
      { method: "GET" },
    );

    return rows.map((row) => ({
      id: row.id,
      orgId: row.org_id,
      ecosystem: row.ecosystem,
      packageName: row.package_name,
      version: row.version,
      requestedAt: row.requested_at,
    }));
  }

  /**
   * Atomically claim a queued job by setting status to 'analyzing'.
   *
   * The WHERE clause includes `status=eq.queued` so that concurrent workers
   * cannot double-claim the same job. PostgREST returns an empty array when
   * the row was already claimed by another worker.
   */
  async claimJob(jobId: string): Promise<boolean> {
    const rows = await this.request<AnalysisJobRow[]>(
      `/analysis_jobs?id=eq.${jobId}&status=eq.queued&select=id`,
      {
        method: "PATCH",
        headers: { Prefer: "return=representation" },
        body: JSON.stringify({ status: "analyzing" }),
      },
    );

    return rows.length > 0;
  }

  /**
   * Persist a completed analysis into the packages, analyses, and binaries
   * tables.
   *
   * Returns the id of the newly-created analysis row.
   */
  async persistAnalysis(analysis: PackageAnalysis): Promise<string> {
    // 1. Upsert package row (ecosystem + name is unique)
    const packageRows = await this.request<PackageRow[]>(
      `/packages?select=id,total_versions_analyzed&ecosystem=eq.${analysis.ecosystem}&name=eq.${encodeURIComponent(analysis.packageName)}`,
      { method: "GET" },
    );

    let packageId: string;
    let previousVersionCount: number;

    if (packageRows.length > 0) {
      packageId = packageRows[0].id;
      previousVersionCount = packageRows[0].total_versions_analyzed;
    } else {
      // Insert new package
      const [created] = await this.request<PackageRow[]>(
        `/packages?select=id,total_versions_analyzed`,
        {
          method: "POST",
          headers: { Prefer: "return=representation" },
          body: JSON.stringify({
            ecosystem: analysis.ecosystem,
            name: analysis.packageName,
            latest_analyzed_version: analysis.version,
            total_versions_analyzed: 0,
          }),
        },
      );
      packageId = created.id;
      previousVersionCount = 0;
    }

    // 2. Insert analysis row
    const [analysisRow] = await this.request<Array<{ id: string }>>(
      `/analyses?select=id`,
      {
        method: "POST",
        headers: { Prefer: "return=representation" },
        body: JSON.stringify({
          package_id: packageId,
          version: analysis.version,
          status: analysis.status,
          risk_score: analysis.riskScore,
          risk_level: analysis.riskLevel,
          summary: analysis.summary,
          source_match_confidence: analysis.sourceMatchConfidence,
          behaviors: aggregateBehaviors(analysis),
          findings: aggregateFindings(analysis),
          binary_count: analysis.binaryCount,
          total_binary_size: analysis.totalBinarySize,
          ai_model: analysis.aiModel,
          manifest_analysis: analysis.manifestAnalysis ?? null,
          script_findings: analysis.manifestAnalysis?.findings ?? [],
        }),
      },
    );

    const analysisId = analysisRow.id;

    // 3. Insert binary rows (one per binary)
    if (analysis.binaries.length > 0) {
      const binaryRows = analysis.binaries.map((binary) => ({
        analysis_id: analysisId,
        filename: binary.filename,
        architecture: binary.architecture,
        format: binary.format,
        file_size: binary.fileSize,
        function_count: binary.functionCount,
        import_count: binary.importCount,
        risk_score: binary.riskScore,
        risk_level: binary.riskLevel,
        ai_explanation: binary.aiExplanation,
        decompiled_preview: binary.decompiledPreview,
        imports: binary.imports,
        strings: binary.strings,
        behaviors: binary.behaviors,
        findings: binary.findings,
      }));

      await this.request<unknown>(
        `/binaries`,
        {
          method: "POST",
          headers: { Prefer: "return=minimal" },
          body: JSON.stringify(binaryRows),
        },
      );
    }

    // 4. Update package metadata
    await this.request<unknown>(
      `/packages?id=eq.${packageId}`,
      {
        method: "PATCH",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify({
          latest_analyzed_version: analysis.version,
          total_versions_analyzed: previousVersionCount + 1,
        }),
      },
    );

    return analysisId;
  }

  /** Mark a job as successfully completed. */
  async completeJob(jobId: string, analysisId: string): Promise<void> {
    await this.request<unknown>(
      `/analysis_jobs?id=eq.${jobId}`,
      {
        method: "PATCH",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify({
          status: "complete",
          completed_at: new Date().toISOString(),
        }),
      },
    );
  }

  /** Mark a job as failed with an error message. */
  async failJob(jobId: string, error: string): Promise<void> {
    await this.request<unknown>(
      `/analysis_jobs?id=eq.${jobId}`,
      {
        method: "PATCH",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify({
          status: "failed",
          error: error.slice(0, 2000), // Truncate long error messages
          completed_at: new Date().toISOString(),
        }),
      },
    );
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a top-level behavior summary for the analysis row by merging all
 * binary-level behaviors. If *any* binary has a behavior detected, the
 * package-level value is detected.
 */
function aggregateBehaviors(analysis: PackageAnalysis) {
  if (analysis.binaries.length === 0) {
    return {};
  }

  const merged: Record<string, { detected: boolean; details: string[] }> = {};

  for (const binary of analysis.binaries) {
    for (const [key, value] of Object.entries(binary.behaviors)) {
      const typed = value as { detected: boolean; details: string[] };
      if (!merged[key]) {
        merged[key] = { detected: false, details: [] };
      }
      if (typed.detected) {
        merged[key].detected = true;
        merged[key].details.push(
          ...typed.details.filter((d) => !merged[key].details.includes(d)),
        );
      }
    }
  }

  return merged;
}

/** Flatten all binary-level findings into a single array for the analysis row. */
function aggregateFindings(analysis: PackageAnalysis) {
  return analysis.binaries.flatMap((binary) => binary.findings);
}
