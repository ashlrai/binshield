/**
 * Tests for pypi-wheel-provenance-attestator.ts
 *
 * Covers:
 *   1.  isPurePythonWheelFilename — filename ABI tag detection
 *   2.  detectNativeBinariesInFilelist — .so/.pyd/.dylib detection
 *   3.  analyzeAttestation — PEP 740 attestation structure parsing
 *   4.  checkBuildTimestampAnomaly — GH API timestamp cross-reference (mocked)
 *   5.  detectRepackagingFraud — pure-Python wheel + native binary detection
 *   6.  scoreBuilderReputation — composite risk scoring
 *   7.  hashProvenanceResult — stable result fingerprint
 *   8.  verifyWheelProvenanceAttestation — full integration
 *       a. valid attestation → provenance_verified=true
 *       b. missing attestation → provenance_verified=false, missing_provenance finding
 *       c. invalid signature → attestation_signature_valid=false
 *       d. timestamp anomaly → build_timestamp_anomaly=true
 *       e. forged wheel (pure-Python claim + .so) → repackaging_fraud_suspected=true
 *       f. PyPI metadata unavailable → graceful degradation
 *       g. SLSA level inference
 *       h. builder reputation finding threshold
 *       i. no repository URL → timestamp check skipped
 *       j. trusted publisher → lower risk score
 */

import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";

import {
  isPurePythonWheelFilename,
  detectNativeBinariesInFilelist,
  analyzeAttestation,
  checkBuildTimestampAnomaly,
  detectRepackagingFraud,
  scoreBuilderReputation,
  hashProvenanceResult,
  verifyWheelProvenanceAttestation,
  type WheelProvenanceAttestationResult,
} from "./pypi-wheel-provenance-attestator";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeMinimalMetadata(overrides: Record<string, unknown> = {}) {
  return {
    info: {
      name: "mypkg",
      version: "1.0.0",
      home_page: null,
      project_urls: null,
      requires_dist: null,
      classifiers: [],
      author: null,
      maintainer: null,
    },
    urls: [],
    vulnerabilities: [],
    ...overrides,
  };
}

function makeUrlEntry(overrides: Record<string, unknown> = {}) {
  return {
    filename: "mypkg-1.0.0-cp311-cp311-linux_x86_64.whl",
    packagetype: "bdist_wheel",
    url: "https://files.pythonhosted.org/mypkg.whl",
    digests: { sha256: "a".repeat(64) },
    upload_time_iso_8601: "2024-03-15T10:00:00Z",
    ...overrides,
  };
}

function makeAttestedUrlEntry() {
  return makeUrlEntry({
    provenance: {
      attestation_bundles: [
        {
          publisher: {
            kind: "GitHub",
            repository: "https://github.com/example/mypkg",
            workflow: ".github/workflows/release.yml",
          },
          attestations: [
            {
              version: 1,
              verification_material: {
                tlog_entries: [
                  { log_index: 12345, integrated_time: 1710489600 },
                ],
                certificate: "base64cert",
              },
              envelope: {
                statement: "base64statement",
                signature: "base64signature",
              },
            },
          ],
        },
      ],
    },
  });
}

// ---------------------------------------------------------------------------
// 1. isPurePythonWheelFilename
// ---------------------------------------------------------------------------

describe("isPurePythonWheelFilename — ABI tag detection", () => {
  it("detects py3-none-any wheels as pure Python", () => {
    expect(isPurePythonWheelFilename("requests-2.31.0-py3-none-any.whl")).toBe(true);
  });

  it("detects py2.py3-none-any wheels as pure Python", () => {
    expect(isPurePythonWheelFilename("six-1.16.0-py2.py3-none-any.whl")).toBe(true);
  });

  it("returns false for cp311 ABI wheels (native)", () => {
    expect(isPurePythonWheelFilename("cryptography-41.0.0-cp311-cp311-linux_x86_64.whl")).toBe(false);
  });

  it("returns false for abi3 wheels (stable ABI)", () => {
    expect(isPurePythonWheelFilename("mypackage-1.0.0-cp38-abi3-manylinux_2_17_x86_64.whl")).toBe(false);
  });

  it("is case-insensitive", () => {
    expect(isPurePythonWheelFilename("MYPKG-1.0-PY3-NONE-ANY.WHL")).toBe(true);
  });

  it("returns false for platform-specific wheels even without cp tag", () => {
    expect(isPurePythonWheelFilename("mypackage-1.0.0-pp39-pypy39_pp73-win_amd64.whl")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 2. detectNativeBinariesInFilelist
// ---------------------------------------------------------------------------

describe("detectNativeBinariesInFilelist — native binary detection", () => {
  it("detects .so files", () => {
    const files = ["mypkg/__init__.py", "mypkg/_core.so", "README.txt"];
    const result = detectNativeBinariesInFilelist(files);
    expect(result).toContain("mypkg/_core.so");
    expect(result).not.toContain("mypkg/__init__.py");
  });

  it("detects .pyd files (Windows extension)", () => {
    const files = ["mypkg/_core.pyd", "mypkg/__init__.py"];
    const result = detectNativeBinariesInFilelist(files);
    expect(result).toContain("mypkg/_core.pyd");
  });

  it("detects .dylib files (macOS)", () => {
    const files = ["lib/_core.dylib", "mypkg/__init__.py"];
    const result = detectNativeBinariesInFilelist(files);
    expect(result).toContain("lib/_core.dylib");
  });

  it("detects cpython-tagged .so files", () => {
    const files = ["mypkg/_core.cpython-311-x86_64-linux-gnu.so"];
    const result = detectNativeBinariesInFilelist(files);
    expect(result).toHaveLength(1);
  });

  it("returns empty array for pure-Python file list", () => {
    const files = ["mypkg/__init__.py", "mypkg/utils.py", "mypkg-1.0.dist-info/WHEEL"];
    const result = detectNativeBinariesInFilelist(files);
    expect(result).toHaveLength(0);
  });

  it("handles empty file list", () => {
    expect(detectNativeBinariesInFilelist([])).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// 3. analyzeAttestation
// ---------------------------------------------------------------------------

describe("analyzeAttestation — PEP 740 attestation parsing", () => {
  it("returns hasAttestation=false when no provenance field", () => {
    const entry = makeUrlEntry();
    const result = analyzeAttestation(entry);
    expect(result.hasAttestation).toBe(false);
    expect(result.signatureValid).toBeNull();
    expect(result.slsaLevel).toBe(0);
    expect(result.trustedPublisher).toBeNull();
  });

  it("returns hasAttestation=false for empty attestation_bundles array", () => {
    const entry = makeUrlEntry({ provenance: { attestation_bundles: [] } });
    const result = analyzeAttestation(entry);
    expect(result.hasAttestation).toBe(false);
  });

  it("returns signatureValid=true for non-empty signature", () => {
    const result = analyzeAttestation(makeAttestedUrlEntry());
    expect(result.hasAttestation).toBe(true);
    expect(result.signatureValid).toBe(true);
  });

  it("returns signatureValid=false for empty signature string", () => {
    const entry = makeUrlEntry({
      provenance: {
        attestation_bundles: [{
          attestations: [{ envelope: { statement: "stmt", signature: "" } }],
        }],
      },
    });
    const result = analyzeAttestation(entry);
    expect(result.hasAttestation).toBe(true);
    expect(result.signatureValid).toBe(false);
  });

  it("infers SLSA level 3 for trusted publisher + tlog entries", () => {
    const result = analyzeAttestation(makeAttestedUrlEntry());
    expect(result.slsaLevel).toBe(3);
    expect(result.trustedPublisher).toBe(true);
    expect(result.tlogEntries).toBeGreaterThan(0);
  });

  it("infers SLSA level 2 for tlog entries without trusted publisher", () => {
    const entry = makeUrlEntry({
      provenance: {
        attestation_bundles: [{
          // No publisher field
          attestations: [{
            verification_material: {
              tlog_entries: [{ log_index: 1 }],
            },
            envelope: { signature: "sig" },
          }],
        }],
      },
    });
    const result = analyzeAttestation(entry);
    expect(result.slsaLevel).toBe(2);
    expect(result.trustedPublisher).toBe(false);
  });

  it("infers SLSA level 1 for valid signature but no tlog entries", () => {
    const entry = makeUrlEntry({
      provenance: {
        attestation_bundles: [{
          publisher: { kind: "GitHub", repository: "https://github.com/owner/repo", workflow: "release.yml" },
          attestations: [{
            // No verification_material
            envelope: { signature: "somesig" },
          }],
        }],
      },
    });
    const result = analyzeAttestation(entry);
    expect(result.slsaLevel).toBe(1);
  });

  it("infers SLSA level 0 for invalid/empty signature", () => {
    const entry = makeUrlEntry({
      provenance: {
        attestation_bundles: [{
          publisher: { kind: "GitHub" },
          attestations: [{ envelope: { signature: "" } }],
        }],
      },
    });
    const result = analyzeAttestation(entry);
    expect(result.slsaLevel).toBe(0);
  });

  it("extracts repository URL from publisher", () => {
    const result = analyzeAttestation(makeAttestedUrlEntry());
    expect(result.repositoryUrl).toBe("https://github.com/example/mypkg");
  });
});

// ---------------------------------------------------------------------------
// 4. checkBuildTimestampAnomaly
// ---------------------------------------------------------------------------

describe("checkBuildTimestampAnomaly — GH API timestamp cross-reference", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns anomalyDetected=false when upload is within normal window after commit", async () => {
    const commitDate = new Date("2024-03-15T08:00:00Z");
    const uploadDate = new Date("2024-03-15T10:00:00Z"); // 2h after commit — normal

    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => [{
        sha: "abc123def456",
        commit: { committer: { date: commitDate.toISOString() } },
      }],
    }));

    const result = await checkBuildTimestampAnomaly({
      uploadTime: uploadDate.toISOString(),
      repositoryUrl: "https://github.com/example/mypkg",
      version: "1.0.0",
    });

    expect(result.anomalyDetected).toBe(false);
    expect(result.gapSeconds).toBeGreaterThan(0);
    expect(result.gapSeconds).toBeLessThan(7 * 24 * 3600);
  });

  it("detects anomaly when upload is more than 7 days after commit", async () => {
    const commitDate = new Date("2024-03-01T08:00:00Z");
    const uploadDate = new Date("2024-03-15T10:00:00Z"); // 14 days after — suspicious

    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => [{
        sha: "deadbeef1234",
        commit: { committer: { date: commitDate.toISOString() } },
      }],
    }));

    const result = await checkBuildTimestampAnomaly({
      uploadTime: uploadDate.toISOString(),
      repositoryUrl: "https://github.com/example/mypkg",
      version: "1.0.0",
    });

    expect(result.anomalyDetected).toBe(true);
    expect(result.reason).toMatch(/gap|threshold/i);
  });

  it("detects anomaly when wheel upload is before commit (impossible for legitimate build)", async () => {
    const commitDate = new Date("2024-03-16T12:00:00Z");
    const uploadDate = new Date("2024-03-15T10:00:00Z"); // 1 day BEFORE commit

    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => [{
        sha: "feedcafe5678",
        commit: { committer: { date: commitDate.toISOString() } },
      }],
    }));

    const result = await checkBuildTimestampAnomaly({
      uploadTime: uploadDate.toISOString(),
      repositoryUrl: "https://github.com/example/mypkg",
      version: "1.0.0",
    });

    expect(result.anomalyDetected).toBe(true);
    expect(result.reason).toMatch(/before|impossible/i);
  });

  it("returns anomalyDetected=false for non-GitHub repos", async () => {
    const result = await checkBuildTimestampAnomaly({
      uploadTime: new Date().toISOString(),
      repositoryUrl: "https://gitlab.com/owner/repo",
      version: "1.0.0",
    });

    expect(result.anomalyDetected).toBe(false);
    expect(result.reason).toMatch(/not a github/i);
  });

  it("returns anomalyDetected=false when GitHub API returns no commits", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => [],
    }));

    const result = await checkBuildTimestampAnomaly({
      uploadTime: new Date().toISOString(),
      repositoryUrl: "https://github.com/example/mypkg",
      version: "99.99.99",
    });

    expect(result.anomalyDetected).toBe(false);
    expect(result.reason).toMatch(/no matching tag|skipped/i);
  });

  it("returns anomalyDetected=false on network error", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network error")));

    const result = await checkBuildTimestampAnomaly({
      uploadTime: new Date().toISOString(),
      repositoryUrl: "https://github.com/example/mypkg",
      version: "1.0.0",
    });

    expect(result.anomalyDetected).toBe(false);
  });

  it("returns anomalyDetected=false for invalid upload timestamp", async () => {
    const result = await checkBuildTimestampAnomaly({
      uploadTime: "not-a-date",
      repositoryUrl: "https://github.com/example/mypkg",
      version: "1.0.0",
    });

    expect(result.anomalyDetected).toBe(false);
    expect(result.reason).toMatch(/invalid/i);
  });

  it("uses Authorization header when githubToken is provided", async () => {
    const capturedHeaders: Record<string, string>[] = [];
    vi.stubGlobal("fetch", vi.fn().mockImplementation((_url: unknown, opts: { headers?: Record<string, string> }) => {
      if (opts?.headers) capturedHeaders.push(opts.headers);
      return Promise.resolve({ ok: false, status: 404 });
    }));

    await checkBuildTimestampAnomaly({
      uploadTime: new Date().toISOString(),
      repositoryUrl: "https://github.com/example/mypkg",
      version: "1.0.0",
      githubToken: "ghp_testtoken",
    });

    expect(capturedHeaders.some((h) => h["Authorization"]?.includes("ghp_testtoken"))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 5. detectRepackagingFraud
// ---------------------------------------------------------------------------

describe("detectRepackagingFraud — pure-Python claim + native binary detection", () => {
  it("detects fraud when pure-Python wheel contains .so files", () => {
    const result = detectRepackagingFraud(
      "mypkg-1.0.0-py3-none-any.whl",
      ["mypkg/__init__.py", "mypkg/_backdoor.so"]
    );
    expect(result.fraudSuspected).toBe(true);
    expect(result.claimedPurePython).toBe(true);
    expect(result.nativeBinariesFound).toContain("mypkg/_backdoor.so");
  });

  it("detects fraud when pure-Python wheel contains .pyd files", () => {
    const result = detectRepackagingFraud(
      "mypkg-1.0.0-py3-none-any.whl",
      ["mypkg/__init__.py", "mypkg/_core.pyd"]
    );
    expect(result.fraudSuspected).toBe(true);
    expect(result.nativeBinariesFound).toHaveLength(1);
  });

  it("returns fraudSuspected=false for expected native wheel with .so files", () => {
    const result = detectRepackagingFraud(
      "cryptography-41.0.0-cp311-cp311-linux_x86_64.whl",
      ["cryptography/__init__.py", "cryptography/_openssl.so"]
    );
    expect(result.fraudSuspected).toBe(false);
    expect(result.claimedPurePython).toBe(false);
    expect(result.nativeBinariesFound).toHaveLength(1);
  });

  it("returns fraudSuspected=false for pure-Python wheel with no native files", () => {
    const result = detectRepackagingFraud(
      "requests-2.31.0-py3-none-any.whl",
      ["requests/__init__.py", "requests/utils.py"]
    );
    expect(result.fraudSuspected).toBe(false);
    expect(result.nativeBinariesFound).toHaveLength(0);
  });

  it("detects multiple native binaries", () => {
    const result = detectRepackagingFraud(
      "mypkg-1.0.0-py3-none-any.whl",
      ["mypkg/_a.so", "mypkg/_b.pyd", "mypkg/_c.dylib", "mypkg/__init__.py"]
    );
    expect(result.fraudSuspected).toBe(true);
    expect(result.nativeBinariesFound).toHaveLength(3);
  });

  it("includes evidence string in result", () => {
    const result = detectRepackagingFraud(
      "mypkg-1.0.0-py3-none-any.whl",
      ["mypkg/_secret.so"]
    );
    expect(result.evidence).toMatch(/pure-Python/i);
    expect(result.evidence).toMatch(/_secret\.so/);
  });

  it("evidence describes no fraud correctly", () => {
    const result = detectRepackagingFraud(
      "mypkg-1.0.0-py3-none-any.whl",
      ["mypkg/__init__.py"]
    );
    expect(result.evidence).toMatch(/no native/i);
  });
});

// ---------------------------------------------------------------------------
// 6. scoreBuilderReputation
// ---------------------------------------------------------------------------

describe("scoreBuilderReputation — composite risk scoring", () => {
  it("gives low risk for trusted publisher + tlog + public logs", () => {
    const result = scoreBuilderReputation({
      trustedPublisher: true,
      tlogEntries: 5,
      publicBuildLogs: true,
      hasAttestation: true,
      repositoryUrl: "https://github.com/owner/repo",
      slsaLevel: 3,
    });
    expect(result.score).toBeLessThanOrEqual(30);
    expect(result.level).toMatch(/none|low/);
  });

  it("gives high risk for no attestation, no repo, no trusted publisher", () => {
    const result = scoreBuilderReputation({
      trustedPublisher: false,
      tlogEntries: 0,
      publicBuildLogs: false,
      hasAttestation: false,
      repositoryUrl: null,
      slsaLevel: 0,
    });
    expect(result.score).toBeGreaterThan(50);
    expect(result.level).toMatch(/high|critical/);
  });

  it("returns score in 0–100 range", () => {
    const result = scoreBuilderReputation({
      trustedPublisher: false,
      tlogEntries: 0,
      publicBuildLogs: null,
      hasAttestation: false,
      repositoryUrl: null,
      slsaLevel: null,
    });
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(100);
  });

  it("reduces score for trusted publisher", () => {
    const withoutTP = scoreBuilderReputation({
      trustedPublisher: false,
      tlogEntries: 0,
      publicBuildLogs: null,
      hasAttestation: false,
      repositoryUrl: "https://github.com/a/b",
      slsaLevel: 0,
    });
    const withTP = scoreBuilderReputation({
      trustedPublisher: true,
      tlogEntries: 0,
      publicBuildLogs: null,
      hasAttestation: false,
      repositoryUrl: "https://github.com/a/b",
      slsaLevel: 0,
    });
    expect(withTP.score).toBeLessThan(withoutTP.score);
  });

  it("reduces score for tlog entries", () => {
    const without = scoreBuilderReputation({
      trustedPublisher: false,
      tlogEntries: 0,
      publicBuildLogs: null,
      hasAttestation: true,
      repositoryUrl: "https://github.com/a/b",
      slsaLevel: 1,
    });
    const with_ = scoreBuilderReputation({
      trustedPublisher: false,
      tlogEntries: 3,
      publicBuildLogs: null,
      hasAttestation: true,
      repositoryUrl: "https://github.com/a/b",
      slsaLevel: 1,
    });
    expect(with_.score).toBeLessThan(without.score);
  });
});

// ---------------------------------------------------------------------------
// 7. hashProvenanceResult
// ---------------------------------------------------------------------------

describe("hashProvenanceResult — stable fingerprint", () => {
  const baseResult: WheelProvenanceAttestationResult = {
    packageName: "mypkg",
    version: "1.0.0",
    wheelFilename: "mypkg-1.0.0-py3-none-any.whl",
    provenance_verified: true,
    attestation_signature_valid: true,
    build_timestamp_anomaly: false,
    repackaging_fraud_suspected: false,
    riskScore: 5,
    riskLevel: "low",
    trustedPublisher: true,
    publicBuildLogs: true,
    slsaLevel: 3,
    findings: [],
    verifiedAt: "2024-03-15T10:00:00.000Z",
  };

  it("returns a 16-char hex string", () => {
    const hash = hashProvenanceResult(baseResult);
    expect(hash).toMatch(/^[0-9a-f]{16}$/);
  });

  it("is stable across calls with same input", () => {
    const hash1 = hashProvenanceResult(baseResult);
    const hash2 = hashProvenanceResult(baseResult);
    expect(hash1).toBe(hash2);
  });

  it("changes when provenance_verified changes", () => {
    const hash1 = hashProvenanceResult(baseResult);
    const hash2 = hashProvenanceResult({ ...baseResult, provenance_verified: false });
    expect(hash1).not.toBe(hash2);
  });

  it("does NOT change when only verifiedAt changes (temporal field excluded)", () => {
    const hash1 = hashProvenanceResult(baseResult);
    const hash2 = hashProvenanceResult({ ...baseResult, verifiedAt: "2025-01-01T00:00:00.000Z" });
    expect(hash1).toBe(hash2);
  });

  it("changes when repackaging_fraud_suspected changes", () => {
    const hash1 = hashProvenanceResult(baseResult);
    const hash2 = hashProvenanceResult({ ...baseResult, repackaging_fraud_suspected: true });
    expect(hash1).not.toBe(hash2);
  });
});

// ---------------------------------------------------------------------------
// 8. verifyWheelProvenanceAttestation — full integration
// ---------------------------------------------------------------------------

describe("verifyWheelProvenanceAttestation — full integration", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  // -------------------------------------------------------------------------
  // 8a. Valid attestation → provenance_verified=true
  // -------------------------------------------------------------------------

  it("8a: sets provenance_verified=true for fully attested wheel", async () => {
    const metadata = makeMinimalMetadata({
      info: {
        name: "mypkg",
        version: "1.0.0",
        project_urls: { Source: "https://github.com/example/mypkg" },
        requires_dist: null,
        home_page: null,
        classifiers: [],
        author: null,
        maintainer: null,
      },
      urls: [makeAttestedUrlEntry()],
    });

    const result = await verifyWheelProvenanceAttestation("mypkg", "1.0.0", {
      _pypiMetadataOverride: metadata,
      skipTimestampCheck: true,
      skipBuildLogCheck: true,
    });

    expect(result.provenance_verified).toBe(true);
    expect(result.attestation_signature_valid).toBe(true);
    expect(result.slsaLevel).toBe(3);
    expect(result.trustedPublisher).toBe(true);
    expect(result.findings.some((f) => f.type === "provenance_verified")).toBe(true);
    expect(result.riskScore).toBeLessThanOrEqual(10);
  });

  // -------------------------------------------------------------------------
  // 8b. Missing attestation → provenance_verified=false, missing_provenance finding
  // -------------------------------------------------------------------------

  it("8b: sets provenance_verified=false and emits missing_provenance for package with no attestation", async () => {
    const metadata = makeMinimalMetadata({
      urls: [makeUrlEntry()],
    });

    const result = await verifyWheelProvenanceAttestation("mypkg", "1.0.0", {
      _pypiMetadataOverride: metadata,
      skipTimestampCheck: true,
      skipBuildLogCheck: true,
    });

    expect(result.provenance_verified).toBe(false);
    expect(result.attestation_signature_valid).toBeNull();
    expect(result.slsaLevel).toBe(0);
    expect(result.findings.some((f) => f.type === "missing_provenance")).toBe(true);
  });

  // -------------------------------------------------------------------------
  // 8c. Invalid signature → attestation_signature_valid=false
  // -------------------------------------------------------------------------

  it("8c: emits attestation_signature_valid finding for empty signature", async () => {
    const metadata = makeMinimalMetadata({
      urls: [makeUrlEntry({
        provenance: {
          attestation_bundles: [{
            publisher: { kind: "GitHub" },
            attestations: [{ envelope: { statement: "stmt", signature: "" } }],
          }],
        },
      })],
    });

    const result = await verifyWheelProvenanceAttestation("mypkg", "1.0.0", {
      _pypiMetadataOverride: metadata,
      skipTimestampCheck: true,
      skipBuildLogCheck: true,
    });

    expect(result.attestation_signature_valid).toBe(false);
    expect(result.provenance_verified).toBe(false);
    expect(result.findings.some((f) => f.type === "attestation_signature_valid")).toBe(true);
    const sigFinding = result.findings.find((f) => f.type === "attestation_signature_valid");
    expect(sigFinding?.severity).toBe("high");
  });

  // -------------------------------------------------------------------------
  // 8d. Timestamp anomaly → build_timestamp_anomaly=true
  // -------------------------------------------------------------------------

  it("8d: detects build_timestamp_anomaly and emits finding", async () => {
    const metadata = makeMinimalMetadata({
      info: {
        name: "mypkg",
        version: "1.0.0",
        project_urls: { Source: "https://github.com/example/mypkg" },
        requires_dist: null,
        home_page: null,
        classifiers: [],
        author: null,
        maintainer: null,
      },
      urls: [makeUrlEntry({
        // Upload 14 days after commit — anomalous
        upload_time_iso_8601: "2024-03-15T10:00:00Z",
      })],
    });

    // Mock GH API to return a commit 14 days before upload
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => [{
        sha: "deadbeef1234abcd",
        commit: { committer: { date: "2024-03-01T10:00:00Z" } },
      }],
    }));

    const result = await verifyWheelProvenanceAttestation("mypkg", "1.0.0", {
      _pypiMetadataOverride: metadata,
      skipBuildLogCheck: true,
    });

    expect(result.build_timestamp_anomaly).toBe(true);
    expect(result.findings.some((f) => f.type === "build_timestamp_anomaly")).toBe(true);
    const anomalyFinding = result.findings.find((f) => f.type === "build_timestamp_anomaly");
    expect(anomalyFinding?.severity).toBe("high");
  });

  // -------------------------------------------------------------------------
  // 8e. Forged wheel (pure-Python claim + .so) → repackaging_fraud_suspected=true
  // -------------------------------------------------------------------------

  it("8e: detects repackaging_fraud_suspected for pure-Python wheel with native files", async () => {
    const metadata = makeMinimalMetadata({
      urls: [makeUrlEntry({ filename: "mypkg-1.0.0-py3-none-any.whl" })],
    });

    const result = await verifyWheelProvenanceAttestation("mypkg", "1.0.0", {
      _pypiMetadataOverride: metadata,
      _wheelFileListOverride: [
        "mypkg/__init__.py",
        "mypkg/_backdoor.so",
        "mypkg/_stealer.pyd",
      ],
      skipTimestampCheck: true,
      skipBuildLogCheck: true,
    });

    expect(result.repackaging_fraud_suspected).toBe(true);
    expect(result.provenance_verified).toBe(false);
    const fraudFinding = result.findings.find((f) => f.type === "repackaging_fraud_suspected");
    expect(fraudFinding).toBeDefined();
    expect(fraudFinding?.severity).toBe("critical");
    expect(result.riskScore).toBeGreaterThanOrEqual(95);
  });

  // -------------------------------------------------------------------------
  // 8f. PyPI metadata unavailable → graceful degradation
  // -------------------------------------------------------------------------

  it("8f: degrades gracefully when PyPI metadata is unavailable", async () => {
    const result = await verifyWheelProvenanceAttestation("nonexistent-pkg-xyz", "99.0.0", {
      _pypiMetadataOverride: null,
      skipTimestampCheck: true,
      skipBuildLogCheck: true,
    });

    expect(result.provenance_verified).toBe(false);
    expect(result.wheelFilename).toBeNull();
    expect(result.riskScore).toBeGreaterThanOrEqual(60);
    expect(result.findings.some((f) => f.type === "missing_provenance")).toBe(true);
    // Must not throw
  });

  // -------------------------------------------------------------------------
  // 8g. SLSA level inference
  // -------------------------------------------------------------------------

  it("8g: emits slsa_level_insufficient finding for level-0 package", async () => {
    const metadata = makeMinimalMetadata({
      urls: [makeUrlEntry()], // no provenance
    });

    const result = await verifyWheelProvenanceAttestation("mypkg", "1.0.0", {
      _pypiMetadataOverride: metadata,
      skipTimestampCheck: true,
      skipBuildLogCheck: true,
    });

    expect(result.slsaLevel).toBe(0);
    expect(result.findings.some((f) => f.type === "slsa_level_insufficient")).toBe(true);
    const slsaFinding = result.findings.find((f) => f.type === "slsa_level_insufficient");
    expect(slsaFinding?.severity).toBe("medium"); // level 0 → medium
  });

  it("8g: emits low-severity slsa_level_insufficient for level-1", async () => {
    const metadata = makeMinimalMetadata({
      urls: [makeUrlEntry({
        provenance: {
          attestation_bundles: [{
            publisher: { kind: "GitHub", workflow: "release.yml" },
            attestations: [{ envelope: { signature: "sig" } }], // no tlog
          }],
        },
      })],
    });

    const result = await verifyWheelProvenanceAttestation("mypkg", "1.0.0", {
      _pypiMetadataOverride: metadata,
      skipTimestampCheck: true,
      skipBuildLogCheck: true,
    });

    expect(result.slsaLevel).toBe(1);
    const slsaFinding = result.findings.find((f) => f.type === "slsa_level_insufficient");
    expect(slsaFinding?.severity).toBe("low"); // level 1 → low
  });

  it("8g: does NOT emit slsa_level_insufficient for level 2 or 3", async () => {
    const result = await verifyWheelProvenanceAttestation("mypkg", "1.0.0", {
      _pypiMetadataOverride: makeMinimalMetadata({ urls: [makeAttestedUrlEntry()] }),
      skipTimestampCheck: true,
      skipBuildLogCheck: true,
    });

    expect(result.slsaLevel).toBeGreaterThanOrEqual(2);
    expect(result.findings.some((f) => f.type === "slsa_level_insufficient")).toBe(false);
  });

  // -------------------------------------------------------------------------
  // 8h. Builder reputation finding threshold
  // -------------------------------------------------------------------------

  it("8h: emits builder_reputation_low for high-risk wheel without attestation", async () => {
    const metadata = makeMinimalMetadata({
      urls: [makeUrlEntry()], // no attestation, no repo
    });

    const result = await verifyWheelProvenanceAttestation("mypkg", "1.0.0", {
      _pypiMetadataOverride: metadata,
      skipTimestampCheck: true,
      skipBuildLogCheck: true,
    });

    // No attestation + no repo = high reputation score
    const repFinding = result.findings.find((f) => f.type === "builder_reputation_low");
    expect(repFinding).toBeDefined();
  });

  it("8h: does NOT emit builder_reputation_low when attestation is valid", async () => {
    const result = await verifyWheelProvenanceAttestation("mypkg", "1.0.0", {
      _pypiMetadataOverride: makeMinimalMetadata({ urls: [makeAttestedUrlEntry()] }),
      skipTimestampCheck: true,
      skipBuildLogCheck: true,
    });

    expect(result.findings.some((f) => f.type === "builder_reputation_low")).toBe(false);
  });

  // -------------------------------------------------------------------------
  // 8i. No repository URL → timestamp check skipped gracefully
  // -------------------------------------------------------------------------

  it("8i: sets build_timestamp_anomaly=null when no repository URL found", async () => {
    const metadata = makeMinimalMetadata({
      urls: [makeUrlEntry()], // no project_urls
    });

    const result = await verifyWheelProvenanceAttestation("mypkg", "1.0.0", {
      _pypiMetadataOverride: metadata,
      skipBuildLogCheck: true,
      // skipTimestampCheck NOT set — let it run, but no repo URL so it should skip
    });

    // No repo URL → timestamp check cannot run → null
    expect(result.build_timestamp_anomaly).toBeNull();
  });

  // -------------------------------------------------------------------------
  // 8j. Trusted publisher → lower risk score
  // -------------------------------------------------------------------------

  it("8j: fully attested package has risk score ≤ 10", async () => {
    const result = await verifyWheelProvenanceAttestation("mypkg", "1.0.0", {
      _pypiMetadataOverride: makeMinimalMetadata({ urls: [makeAttestedUrlEntry()] }),
      skipTimestampCheck: true,
      skipBuildLogCheck: true,
    });

    expect(result.trustedPublisher).toBe(true);
    expect(result.riskScore).toBeLessThanOrEqual(10);
    expect(result.riskLevel).toMatch(/none|low/);
  });

  // -------------------------------------------------------------------------
  // Extra: result shape validation
  // -------------------------------------------------------------------------

  it("always sets verifiedAt to a valid ISO-8601 timestamp", async () => {
    const result = await verifyWheelProvenanceAttestation("mypkg", "1.0.0", {
      _pypiMetadataOverride: makeMinimalMetadata({ urls: [makeUrlEntry()] }),
      skipTimestampCheck: true,
      skipBuildLogCheck: true,
    });

    expect(() => new Date(result.verifiedAt)).not.toThrow();
    expect(new Date(result.verifiedAt).toISOString()).toBe(result.verifiedAt);
  });

  it("all findings have required fields", async () => {
    const result = await verifyWheelProvenanceAttestation("mypkg", "1.0.0", {
      _pypiMetadataOverride: makeMinimalMetadata({ urls: [makeUrlEntry()] }),
      skipTimestampCheck: true,
      skipBuildLogCheck: true,
    });

    for (const f of result.findings) {
      expect(f.type).toBeTruthy();
      expect(f.severity).toMatch(/^(info|low|medium|high|critical)$/);
      expect(f.title).toBeTruthy();
      expect(f.description).toBeTruthy();
      expect(typeof f.evidence).toBe("object");
      expect(f.recommendation).toBeTruthy();
    }
  });

  it("repackaging_fraud boosted riskScore overrides low reputation score", async () => {
    const metadata = makeMinimalMetadata({
      urls: [makeAttestedUrlEntry()], // normally good attestation
    });

    // But force a pure-Python-claiming wheel with native binaries
    const fraudEntry = { ...makeAttestedUrlEntry(), filename: "mypkg-1.0.0-py3-none-any.whl" };
    const metadataWithFraud = makeMinimalMetadata({
      urls: [fraudEntry],
    });

    const result = await verifyWheelProvenanceAttestation("mypkg", "1.0.0", {
      _pypiMetadataOverride: metadataWithFraud,
      _wheelFileListOverride: ["mypkg/_injected.so"],
      skipTimestampCheck: true,
      skipBuildLogCheck: true,
    });

    expect(result.repackaging_fraud_suspected).toBe(true);
    expect(result.riskScore).toBeGreaterThanOrEqual(95);
  });

  it("hashProvenanceResult changes when findings change", async () => {
    const baseResult = await verifyWheelProvenanceAttestation("mypkg", "1.0.0", {
      _pypiMetadataOverride: makeMinimalMetadata({ urls: [makeUrlEntry()] }),
      skipTimestampCheck: true,
      skipBuildLogCheck: true,
    });

    const fraudResult = await verifyWheelProvenanceAttestation("mypkg", "1.0.0", {
      _pypiMetadataOverride: makeMinimalMetadata({
        urls: [makeUrlEntry({ filename: "mypkg-1.0.0-py3-none-any.whl" })],
      }),
      _wheelFileListOverride: ["mypkg/_injected.so"],
      skipTimestampCheck: true,
      skipBuildLogCheck: true,
    });

    expect(hashProvenanceResult(baseResult)).not.toBe(hashProvenanceResult(fraudResult));
  });
});
