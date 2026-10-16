/**
 * Proxy re-export for the PyPI Wheel Provenance Attestation engine.
 *
 * The canonical implementation lives in the worker package at
 * `apps/worker/src/pypi-wheel-provenance-attestator.ts`.  This file
 * provides a self-contained copy of the public API surface so the API
 * app can consume it without a cross-package TypeScript compilation
 * dependency on the worker.
 *
 * Only the types and the primary `verifyWheelProvenanceAttestation`
 * function are re-exported here — internal helpers stay in the worker.
 */

import crypto from "node:crypto";

// ---------------------------------------------------------------------------
// Shared types (mirrored from worker module for API compilation)
// ---------------------------------------------------------------------------

export interface WheelProvenanceFinding {
  type:
    | "provenance_verified"
    | "attestation_signature_valid"
    | "build_timestamp_anomaly"
    | "repackaging_fraud_suspected"
    | "missing_provenance"
    | "slsa_level_insufficient"
    | "trusted_publisher_unverified"
    | "builder_reputation_low";
  severity: "info" | "low" | "medium" | "high" | "critical";
  title: string;
  description: string;
  evidence: Record<string, unknown>;
  recommendation: string;
}

export interface WheelProvenanceAttestationResult {
  packageName: string;
  version: string;
  wheelFilename: string | null;
  provenance_verified: boolean;
  attestation_signature_valid: boolean | null;
  build_timestamp_anomaly: boolean | null;
  repackaging_fraud_suspected: boolean;
  riskScore: number;
  riskLevel: "none" | "low" | "medium" | "high" | "critical";
  trustedPublisher: boolean | null;
  publicBuildLogs: boolean | null;
  slsaLevel: 0 | 1 | 2 | 3 | null;
  findings: WheelProvenanceFinding[];
  verifiedAt: string;
}

export interface WheelProvenanceAttestatorOptions {
  githubToken?: string;
  skipTimestampCheck?: boolean;
  skipBuildLogCheck?: boolean;
  _pypiMetadataOverride?: PyPiJsonResponse | null;
  _wheelFileListOverride?: string[];
}

// ---------------------------------------------------------------------------
// Internal PyPI API shape
// ---------------------------------------------------------------------------

interface PyPiUrlEntry {
  filename: string;
  packagetype: string;
  url: string;
  digests: { sha256?: string };
  upload_time_iso_8601?: string;
  provenance?: PyPiProvenancePayload;
}

interface PyPiProvenancePayload {
  attestation_bundles?: Array<{
    publisher?: {
      kind?: string;
      repository?: string;
      workflow?: string;
    };
    attestations?: Array<{
      version?: number;
      verification_material?: {
        tlog_entries?: Array<{ log_index?: number; integrated_time?: number }>;
        certificate?: string;
      };
      envelope?: { statement?: string; signature?: string };
    }>;
  }>;
}

interface PyPiJsonResponse {
  info: {
    name: string;
    version: string;
    home_page?: string | null;
    project_urls?: Record<string, string> | null;
    requires_dist?: string[] | null;
    classifiers?: string[];
    author?: string | null;
    maintainer?: string | null;
  };
  urls: PyPiUrlEntry[];
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const BUILD_TIMESTAMP_ANOMALY_WINDOW_SECONDS = 7 * 24 * 3600;
const BUILD_BEFORE_COMMIT_THRESHOLD_SECONDS = 300;
const NATIVE_BINARY_EXTENSIONS = new Set([".so", ".pyd", ".dylib"]);
const PURE_PYTHON_ABI_PATTERNS = [
  /^.+-py3-none-any\.whl$/i,
  /^.+-py2\.py3-none-any\.whl$/i,
  /^.+-py[23]\d*-none-any\.whl$/i,
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function fetchPyPiMetadata(
  packageName: string,
  version: string
): Promise<PyPiJsonResponse | null> {
  const url = `https://pypi.org/pypi/${encodeURIComponent(packageName)}/${encodeURIComponent(version)}/json`;
  try {
    const resp = await fetch(url, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(10_000),
    });
    if (!resp.ok) return null;
    return (await resp.json()) as PyPiJsonResponse;
  } catch {
    return null;
  }
}

function isPurePythonWheelFilename(filename: string): boolean {
  return PURE_PYTHON_ABI_PATTERNS.some((re) => re.test(filename));
}

function detectNativeBinariesInFilelist(filenames: string[]): string[] {
  return filenames.filter((f) => {
    const lower = f.toLowerCase();
    for (const ext of NATIVE_BINARY_EXTENSIONS) {
      if (lower.endsWith(ext) || lower.includes(`${ext}.`)) return true;
    }
    return false;
  });
}

function extractRepositoryUrl(info: PyPiJsonResponse["info"]): string | null {
  const candidates = [
    info.project_urls?.["Source"],
    info.project_urls?.["Source Code"],
    info.project_urls?.["Repository"],
    info.project_urls?.["GitHub"],
    info.project_urls?.["Homepage"],
    info.home_page,
  ];
  for (const url of candidates) {
    if (url && /github\.com|gitlab\.com|bitbucket\.org/i.test(url)) return url;
  }
  return null;
}

interface AttestationAnalysis {
  hasAttestation: boolean;
  signatureValid: boolean | null;
  slsaLevel: 0 | 1 | 2 | 3 | null;
  trustedPublisher: boolean | null;
  repositoryUrl: string | null;
  tlogEntries: number;
}

function analyzeAttestation(urlEntry: PyPiUrlEntry): AttestationAnalysis {
  const provenance = urlEntry.provenance;
  if (!provenance?.attestation_bundles || provenance.attestation_bundles.length === 0) {
    return { hasAttestation: false, signatureValid: null, slsaLevel: 0, trustedPublisher: null, repositoryUrl: null, tlogEntries: 0 };
  }
  let signatureValid: boolean | null = null;
  let tlogEntries = 0;
  let repositoryUrl: string | null = null;
  let trustedPublisher = false;
  for (const bundle of provenance.attestation_bundles) {
    if (bundle.publisher) {
      repositoryUrl = bundle.publisher.repository ?? null;
      if (bundle.publisher.kind === "GitHub" || bundle.publisher.kind === "GitLab" || bundle.publisher.workflow) {
        trustedPublisher = true;
      }
    }
    for (const att of bundle.attestations ?? []) {
      const sig = att.envelope?.signature;
      if (sig !== undefined) signatureValid = typeof sig === "string" && sig.length > 0;
      tlogEntries += att.verification_material?.tlog_entries?.length ?? 0;
    }
  }
  let slsaLevel: 0 | 1 | 2 | 3;
  if (!signatureValid) slsaLevel = 0;
  else if (tlogEntries === 0) slsaLevel = 1;
  else if (!trustedPublisher) slsaLevel = 2;
  else slsaLevel = 3;
  return { hasAttestation: true, signatureValid, slsaLevel, trustedPublisher, repositoryUrl, tlogEntries };
}

async function checkBuildTimestampAnomaly(opts: {
  uploadTime: string;
  repositoryUrl: string;
  version: string;
  githubToken?: string;
}): Promise<{ anomalyDetected: boolean; reason: string; uploadTimestamp: Date | null; nearestCommitTimestamp: Date | null; gapSeconds: number | null; commitSha: string | null }> {
  const uploadTimestamp = new Date(opts.uploadTime);
  if (isNaN(uploadTimestamp.getTime())) return { anomalyDetected: false, reason: "invalid upload timestamp", uploadTimestamp: null, nearestCommitTimestamp: null, gapSeconds: null, commitSha: null };
  const ghMatch = opts.repositoryUrl.match(/github\.com[/:]([^/]+)\/([^/#?]+?)(?:\.git)?(?:[/#?].*)?$/i);
  if (!ghMatch) return { anomalyDetected: false, reason: "repository is not a GitHub repo; cross-reference skipped", uploadTimestamp, nearestCommitTimestamp: null, gapSeconds: null, commitSha: null };
  const [, owner, repo] = ghMatch;
  const versionTags = [`v${opts.version}`, opts.version, `release/${opts.version}`, `release/v${opts.version}`];
  const headers: Record<string, string> = { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" };
  if (opts.githubToken) headers["Authorization"] = `Bearer ${opts.githubToken}`;
  for (const tag of versionTags) {
    try {
      const resp = await fetch(`https://api.github.com/repos/${owner}/${repo}/commits?sha=${encodeURIComponent(tag)}&per_page=1`, { headers, signal: AbortSignal.timeout(8_000) });
      if (!resp.ok) continue;
      const commits = (await resp.json()) as Array<{ sha: string; commit: { author?: { date?: string }; committer?: { date?: string } } }>;
      if (!commits.length) continue;
      const commit = commits[0]!;
      const commitDateStr = commit.commit.committer?.date ?? commit.commit.author?.date;
      if (!commitDateStr) continue;
      const commitTimestamp = new Date(commitDateStr);
      if (isNaN(commitTimestamp.getTime())) continue;
      const gapSeconds = Math.round((uploadTimestamp.getTime() - commitTimestamp.getTime()) / 1000);
      const uploadedBeforeCommit = gapSeconds < -BUILD_BEFORE_COMMIT_THRESHOLD_SECONDS;
      const uploadedTooLongAfterCommit = gapSeconds > BUILD_TIMESTAMP_ANOMALY_WINDOW_SECONDS;
      const anomalyDetected = uploadedBeforeCommit || uploadedTooLongAfterCommit;
      const reason = uploadedBeforeCommit
        ? `wheel upload is ${Math.abs(gapSeconds)}s BEFORE commit ${commit.sha.slice(0, 8)} — impossible for a legitimate CI build`
        : uploadedTooLongAfterCommit
          ? `wheel upload is ${gapSeconds}s after commit ${commit.sha.slice(0, 8)} — gap exceeds ${BUILD_TIMESTAMP_ANOMALY_WINDOW_SECONDS / 3600}h threshold`
          : `upload ${gapSeconds}s after commit ${commit.sha.slice(0, 8)} — within normal build window`;
      return { anomalyDetected, reason, uploadTimestamp, nearestCommitTimestamp: commitTimestamp, gapSeconds, commitSha: commit.sha };
    } catch { continue; }
  }
  return { anomalyDetected: false, reason: "no matching tag found in GitHub commit history; check skipped", uploadTimestamp, nearestCommitTimestamp: null, gapSeconds: null, commitSha: null };
}

function scoreBuilderReputation(opts: {
  trustedPublisher: boolean | null;
  tlogEntries: number;
  publicBuildLogs: boolean | null;
  hasAttestation: boolean;
  repositoryUrl: string | null;
  slsaLevel: 0 | 1 | 2 | 3 | null;
}): { score: number; level: "none" | "low" | "medium" | "high" | "critical" } {
  let score = 30;
  if (opts.trustedPublisher === true) score -= 20;
  if (opts.tlogEntries > 0) score -= 15;
  if (opts.publicBuildLogs === true) score -= 10;
  if (!opts.hasAttestation) score += 15;
  if (!opts.repositoryUrl) score += 20;
  if (opts.slsaLevel !== null && opts.slsaLevel <= 1) score += 10;
  const clamped = Math.max(0, Math.min(100, score));
  let level: "none" | "low" | "medium" | "high" | "critical";
  if (clamped <= 10) level = "none";
  else if (clamped <= 30) level = "low";
  else if (clamped <= 55) level = "medium";
  else if (clamped <= 75) level = "high";
  else level = "critical";
  return { score: clamped, level };
}

async function checkPublicBuildLogs(repositoryUrl: string | null, githubToken?: string): Promise<boolean | null> {
  if (!repositoryUrl) return null;
  const ghMatch = repositoryUrl.match(/github\.com[/:]([^/]+)\/([^/#?]+?)(?:\.git)?(?:[/#?].*)?$/i);
  if (!ghMatch) return null;
  const [, owner, repo] = ghMatch;
  const headers: Record<string, string> = { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" };
  if (githubToken) headers["Authorization"] = `Bearer ${githubToken}`;
  try {
    const resp = await fetch(`https://api.github.com/repos/${owner}/${repo}/actions/workflows?per_page=1`, { headers, signal: AbortSignal.timeout(6_000) });
    if (!resp.ok) return null;
    const data = (await resp.json()) as { total_count?: number };
    return (data.total_count ?? 0) > 0;
  } catch { return null; }
}

// ---------------------------------------------------------------------------
// Primary export
// ---------------------------------------------------------------------------

/**
 * Perform deep wheel provenance + attestation verification for a PyPI package.
 * This is the API-side proxy of the canonical worker implementation.
 */
export async function verifyWheelProvenanceAttestation(
  packageName: string,
  version: string,
  opts: WheelProvenanceAttestatorOptions = {}
): Promise<WheelProvenanceAttestationResult> {
  const findings: WheelProvenanceFinding[] = [];
  const verifiedAt = new Date().toISOString();

  const metadata: PyPiJsonResponse | null =
    opts._pypiMetadataOverride !== undefined
      ? opts._pypiMetadataOverride
      : await fetchPyPiMetadata(packageName, version);

  if (!metadata) {
    findings.push({
      type: "missing_provenance",
      severity: "medium",
      title: `PyPI metadata unavailable: ${packageName}@${version}`,
      description: `Could not fetch PyPI JSON metadata for ${packageName}@${version}. Provenance verification requires access to the PyPI API.`,
      evidence: { packageName, version },
      recommendation: "Ensure network connectivity to pypi.org and retry.",
    });
    return { packageName, version, wheelFilename: null, provenance_verified: false, attestation_signature_valid: null, build_timestamp_anomaly: null, repackaging_fraud_suspected: false, riskScore: 70, riskLevel: "high", trustedPublisher: null, publicBuildLogs: null, slsaLevel: null, findings, verifiedAt };
  }

  const wheelEntry = metadata.urls.find((u) => u.packagetype === "bdist_wheel") ?? null;
  const wheelFilename = wheelEntry?.filename ?? null;
  const repositoryUrl = extractRepositoryUrl(metadata.info);
  const attestation = wheelEntry ? analyzeAttestation(wheelEntry) : { hasAttestation: false, signatureValid: null, slsaLevel: 0 as const, trustedPublisher: null, repositoryUrl, tlogEntries: 0 };
  const effectiveRepoUrl = attestation.repositoryUrl ?? repositoryUrl;

  // Attestation findings
  if (attestation.hasAttestation && attestation.signatureValid === true) {
    findings.push({ type: "provenance_verified", severity: "info", title: `Wheel provenance verified (SLSA level ${attestation.slsaLevel}): ${wheelFilename ?? "unknown"}`, description: `The wheel '${wheelFilename}' for ${packageName}@${version} has a valid PEP 740 attestation. SLSA level ${attestation.slsaLevel} inferred.`, evidence: { wheelFilename, slsaLevel: attestation.slsaLevel, packageName, version }, recommendation: "No action required — provenance is verified." });
  } else if (attestation.hasAttestation && attestation.signatureValid === false) {
    findings.push({ type: "attestation_signature_valid", severity: "high", title: `Attestation present but signature invalid: ${wheelFilename ?? "unknown"}`, description: `PyPI reports a PEP 740 attestation bundle for '${wheelFilename}' but the signature envelope is empty or malformed.`, evidence: { wheelFilename, signatureValid: false }, recommendation: "Verify the package's Sigstore attestation independently using the cosign CLI." });
  } else {
    findings.push({ type: "missing_provenance", severity: "medium", title: `No PEP 740 provenance attestation: ${packageName}@${version}`, description: `The package '${packageName}@${version}' does not have a PEP 740 attestation on PyPI.`, evidence: { packageName, version, wheelFilename }, recommendation: "Prefer packages with PEP 740 attestations." });
  }

  // SLSA level finding
  const sl = attestation.slsaLevel;
  if (sl !== null && sl < 2) {
    findings.push({ type: "slsa_level_insufficient", severity: sl === 0 ? "medium" : "low", title: `Low SLSA provenance level (${sl}): ${wheelFilename ?? "unknown"}`, description: `Inferred SLSA provenance level ${sl}. ${sl === 0 ? "Level 0 means no provenance data." : "Level 1 means self-asserted provenance without transparency log verification."}`, evidence: { slsaLevel: sl, wheelFilename }, recommendation: sl === 0 ? "No attestation found." : "Attestation is self-asserted. Require SLSA ≥ 2 for production use." });
  }

  // Trusted publisher finding
  if (!attestation.trustedPublisher && !attestation.hasAttestation) {
    findings.push({ type: "trusted_publisher_unverified", severity: "low", title: `Trusted publisher not configured: ${packageName}@${version}`, description: `The package does not use a PyPI Trusted Publisher (OIDC-based GitHub Actions or GitLab CI).`, evidence: { packageName, version, trustedPublisher: false }, recommendation: "This is informational. Prefer packages using Trusted Publishers." });
  }

  // Build timestamp anomaly
  let buildTimestampAnomaly: boolean | null = null;
  if (!opts.skipTimestampCheck && wheelEntry?.upload_time_iso_8601 && effectiveRepoUrl) {
    const tsCheck = await checkBuildTimestampAnomaly({ uploadTime: wheelEntry.upload_time_iso_8601, repositoryUrl: effectiveRepoUrl, version, githubToken: opts.githubToken });
    buildTimestampAnomaly = tsCheck.anomalyDetected;
    if (tsCheck.anomalyDetected) {
      findings.push({ type: "build_timestamp_anomaly", severity: "high", title: `Build timestamp anomaly detected${wheelFilename ? `: ${wheelFilename}` : ""}`, description: `A suspicious timing gap was detected between the wheel upload time and the nearest git commit. ${tsCheck.reason}.`, evidence: { uploadTimestamp: tsCheck.uploadTimestamp?.toISOString() ?? null, nearestCommitTimestamp: tsCheck.nearestCommitTimestamp?.toISOString() ?? null, gapSeconds: tsCheck.gapSeconds, commitSha: tsCheck.commitSha, reason: tsCheck.reason, wheelFilename }, recommendation: "Inspect the git tag and compare the wheel contents against a locally-built version from the tagged commit." });
    }
  }

  // Repackaging fraud
  let repackagingFraudSuspected = false;
  if (wheelFilename) {
    const fileList = opts._wheelFileListOverride ?? [];
    const purePython = PURE_PYTHON_ABI_PATTERNS.some((re) => re.test(wheelFilename));
    const natives = detectNativeBinariesInFilelist(fileList);
    repackagingFraudSuspected = purePython && natives.length > 0;
    if (repackagingFraudSuspected) {
      findings.push({ type: "repackaging_fraud_suspected", severity: "critical", title: `Repackaging fraud: pure-Python wheel contains native binaries — ${wheelFilename}`, description: `The wheel '${wheelFilename}' is tagged as pure-Python but contains ${natives.length} native binary file(s): ${natives.slice(0, 5).join(", ")}.`, evidence: { wheelFilename, nativeBinariesFound: natives, claimedPurePython: true, packageName, version }, recommendation: "Do not install this package. Report immediately to PyPI security at security@python.org." });
    }
  }

  // Builder reputation
  let publicBuildLogs: boolean | null = null;
  if (!opts.skipBuildLogCheck && effectiveRepoUrl) {
    publicBuildLogs = await checkPublicBuildLogs(effectiveRepoUrl, opts.githubToken);
  }
  const reputation = scoreBuilderReputation({ trustedPublisher: attestation.trustedPublisher, tlogEntries: attestation.tlogEntries, publicBuildLogs, hasAttestation: attestation.hasAttestation, repositoryUrl: effectiveRepoUrl, slsaLevel: attestation.slsaLevel });
  if (!attestation.hasAttestation && reputation.score > 40) {
    findings.push({ type: "builder_reputation_low", severity: reputation.level === "critical" ? "critical" : reputation.level === "high" ? "high" : "medium", title: `Low builder reputation score (${reputation.score}/100): ${packageName}@${version}`, description: `The wheel lacks provenance attestation and has a builder reputation score of ${reputation.score}/100 (${reputation.level} risk).`, evidence: { reputationScore: reputation.score, riskLevel: reputation.level, packageName, version }, recommendation: "Prefer packages with PyPI Trusted Publisher configuration and public CI/CD workflows." });
  }

  const provenanceVerified = attestation.hasAttestation && attestation.signatureValid === true && (attestation.slsaLevel ?? 0) >= 1 && !repackagingFraudSuspected && buildTimestampAnomaly !== true;

  let finalRiskScore = reputation.score;
  if (repackagingFraudSuspected) finalRiskScore = Math.max(finalRiskScore, 95);
  if (buildTimestampAnomaly === true) finalRiskScore = Math.max(finalRiskScore, 80);
  if (attestation.signatureValid === false) finalRiskScore = Math.max(finalRiskScore, 75);
  if (provenanceVerified) finalRiskScore = Math.min(finalRiskScore, 10);

  return { packageName, version, wheelFilename, provenance_verified: provenanceVerified, attestation_signature_valid: attestation.signatureValid, build_timestamp_anomaly: buildTimestampAnomaly, repackaging_fraud_suspected: repackagingFraudSuspected, riskScore: finalRiskScore, riskLevel: reputation.level, trustedPublisher: attestation.trustedPublisher, publicBuildLogs, slsaLevel: attestation.slsaLevel, findings, verifiedAt };
}

/**
 * Compute a stable SHA-256 fingerprint of a WheelProvenanceAttestationResult.
 */
export function hashProvenanceResult(result: WheelProvenanceAttestationResult): string {
  const stable = JSON.stringify({ packageName: result.packageName, version: result.version, wheelFilename: result.wheelFilename, provenance_verified: result.provenance_verified, attestation_signature_valid: result.attestation_signature_valid, build_timestamp_anomaly: result.build_timestamp_anomaly, repackaging_fraud_suspected: result.repackaging_fraud_suspected, slsaLevel: result.slsaLevel, findingTypes: result.findings.map((f) => f.type).sort() });
  return crypto.createHash("sha256").update(stable).digest("hex").slice(0, 16);
}
