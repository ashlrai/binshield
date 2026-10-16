import path from "node:path";

import { describe, expect, it } from "vitest";

import { AnalysisPipeline, WorkerRuntime } from "./pipeline";
import { AnalyzerRegistry } from "./malware-analyzer.js";
import { BehaviorCorrelationAnalyzer } from "./analyzers/behavior-correlation-analyzer.js";
import type { FingerprintedArtifact } from "./types.js";

describe("analysis pipeline", () => {
  it("analyzes the fixture package and caches the result", async () => {
    const packageRoot = path.resolve(new URL("../fixtures/sample-package", import.meta.url).pathname);
    const pipeline = new AnalysisPipeline();

    const first = await pipeline.run({
      ecosystem: "npm",
      packageName: "binshield-fixture-addon",
      version: "1.0.0",
      packageRoot
    });

    expect(first.job.status).toBe("complete");
    expect(first.analysis.binaryCount).toBe(2);
    expect(first.analysis.riskLevel).toBe("critical");
    expect(first.analysis.summary).toContain("binshield-fixture-addon");

    const second = await pipeline.run({
      ecosystem: "npm",
      packageName: "binshield-fixture-addon",
      version: "1.0.0",
      packageRoot
    });

    expect(second.job.fromCache).toBe(true);
    expect(second.analysis.summary).toBe(first.analysis.summary);
  });

  it("supports direct runtime access for queue state", async () => {
    const packageRoot = path.resolve(new URL("../fixtures/sample-package", import.meta.url).pathname);
    const runtime = new WorkerRuntime();
    const job = runtime.submit({
      ecosystem: "npm",
      packageName: "binshield-fixture-addon",
      version: "1.0.0",
      packageRoot
    });

    const outcome = await runtime.process(job.id);
    expect(outcome.job.status).toBe("complete");
    expect(runtime.getJob(job.id)?.status).toBe("complete");
    expect(runtime.jobEvents(job.id)).toHaveLength(3);
  });
});

// ---------------------------------------------------------------------------
// Behavior Correlation Analyzer integration tests
// ---------------------------------------------------------------------------

/** Build a minimal FingerprintedArtifact for testing. */
function makeArtifact(
  overrides: { strings?: string[]; interestingStrings?: string[]; filename?: string }
): FingerprintedArtifact {
  return {
    filename: overrides.filename ?? "test.node",
    absolutePath: "/tmp/test.node",
    relativePath: "test.node",
    fileSize: 1024,
    sha256: "deadbeef",
    format: "ELF",
    architecture: "x86_64",
    kind: "native-addon",
    bytes: new Uint8Array(0),
    strings: overrides.strings ?? [],
    interestingStrings: overrides.interestingStrings ?? []
  };
}

describe("BehaviorCorrelationAnalyzer — unit", () => {
  it("is registered in AnalyzerRegistry.createDefault()", async () => {
    const registry = await AnalyzerRegistry.createDefault();
    expect(registry.registeredNames()).toContain("behavior-correlation");
  });

  it("returns analyzer name and semver version", () => {
    const analyzer = new BehaviorCorrelationAnalyzer();
    expect(analyzer.name()).toBe("behavior-correlation");
    expect(analyzer.version()).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it("returns detected:false and low confidence for a benign binary", async () => {
    const analyzer = new BehaviorCorrelationAnalyzer();
    const artifact = makeArtifact({
      strings: ["libvips", "cairo_surface_create", "/tmp/render.png"],
      interestingStrings: []
    });
    const result = await analyzer.analyze(artifact);
    expect(result.findings).toHaveLength(0);
    expect(result.confidence).toBeLessThan(0.7);
  });

  // ── Profile 1: Exfiltration + C2 ────────────────────────────────────────

  describe("profile: Exfiltration + C2 (credential-stealing + network beacon)", () => {
    it("detects credential-stealing APIs combined with network exfil strings", async () => {
      const analyzer = new BehaviorCorrelationAnalyzer();
      const artifact = makeArtifact({
        strings: [
          // credential-stealing API
          "CryptUnprotectData",
          "LsaOpenPolicy",
          // network beacon / exfil
          "discord.com/api/webhooks/123456/exfil-token",
          "WSAStartup"
        ],
        interestingStrings: []
      });

      const result = await analyzer.analyze(artifact);
      expect(result.findings.length).toBeGreaterThan(0);

      const exfilFinding = result.findings.find((f) => f.title.includes("CORR_ExfilC2"));
      expect(exfilFinding).toBeDefined();
      expect(exfilFinding!.severity).toBe("critical");
      expect(exfilFinding!.description).toMatch(/exfiltration.*c2|credential.*network/i);
      expect(result.behaviorSignals.dataExfiltration?.detected).toBe(true);
      expect(result.confidence).toBeGreaterThan(0.7);
    });

    it("does NOT fire when only credential APIs are present (no network beacon)", async () => {
      const analyzer = new BehaviorCorrelationAnalyzer();
      const artifact = makeArtifact({
        strings: ["CryptUnprotectData", "LsaOpenPolicy"],
        interestingStrings: []
      });
      const result = await analyzer.analyze(artifact);
      const exfilFinding = result.findings.find((f) => f.title.includes("CORR_ExfilC2"));
      expect(exfilFinding).toBeUndefined();
    });

    it("does NOT fire when only network strings are present (no credential APIs)", async () => {
      const analyzer = new BehaviorCorrelationAnalyzer();
      const artifact = makeArtifact({
        strings: ["WSAStartup", "connect(sockfd", "send("],
        interestingStrings: []
      });
      const result = await analyzer.analyze(artifact);
      const exfilFinding = result.findings.find((f) => f.title.includes("CORR_ExfilC2"));
      expect(exfilFinding).toBeUndefined();
    });
  });

  // ── Profile 2: Persistence + Wiper ──────────────────────────────────────

  describe("profile: Persistence + Wiper (registry persistence + file deletion)", () => {
    it("detects registry persistence APIs combined with file deletion/wiper patterns", async () => {
      const analyzer = new BehaviorCorrelationAnalyzer();
      const artifact = makeArtifact({
        strings: [
          // persistence
          "RegSetValueEx",
          "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
          // wiper
          "vssadmin delete shadows",
          "DeleteFileW"
        ],
        interestingStrings: []
      });

      const result = await analyzer.analyze(artifact);
      const wipeFinding = result.findings.find((f) => f.title.includes("CORR_PersistWiper"));
      expect(wipeFinding).toBeDefined();
      expect(wipeFinding!.severity).toBe("critical");
      expect(wipeFinding!.description).toMatch(/persistence.*wiper|wiper.*persistence/i);
      expect(result.behaviorSignals.filesystem?.detected).toBe(true);
    });

    it("detects POSIX crontab persistence combined with rm -rf wiper", async () => {
      const analyzer = new BehaviorCorrelationAnalyzer();
      const artifact = makeArtifact({
        strings: [
          "crontab -l",
          "rc.local",
          "rm -rf /home",
          "unlink(path)"
        ],
        interestingStrings: []
      });

      const result = await analyzer.analyze(artifact);
      const wipeFinding = result.findings.find((f) => f.title.includes("CORR_PersistWiper"));
      expect(wipeFinding).toBeDefined();
    });
  });

  // ── Profile 3: Injection + Process Spawn ────────────────────────────────

  describe("profile: Injection + Process Spawn (process injection + process creation)", () => {
    it("detects WriteProcessMemory combined with CreateProcess — classic hollowing", async () => {
      const analyzer = new BehaviorCorrelationAnalyzer();
      const artifact = makeArtifact({
        strings: [
          "WriteProcessMemory",
          "VirtualAllocEx",
          "CreateRemoteThread",
          "CreateProcess",
          "cmd.exe"
        ],
        interestingStrings: []
      });

      const result = await analyzer.analyze(artifact);
      const injectFinding = result.findings.find((f) => f.title.includes("CORR_InjectSpawn"));
      expect(injectFinding).toBeDefined();
      expect(injectFinding!.severity).toBe("critical");
      expect(injectFinding!.description).toMatch(/injection.*process.*spawn|process.*injection/i);
      expect(result.behaviorSignals.process?.detected).toBe(true);
    });

    it("detects ptrace (POSIX injection) combined with fork+execve (process spawn)", async () => {
      const analyzer = new BehaviorCorrelationAnalyzer();
      const artifact = makeArtifact({
        strings: [
          "ptrace(PTRACE_ATTACH",
          "process_vm_writev",
          "fork()",
          "execve('/bin/sh')"
        ],
        interestingStrings: []
      });

      const result = await analyzer.analyze(artifact);
      const injectFinding = result.findings.find((f) => f.title.includes("CORR_InjectSpawn"));
      expect(injectFinding).toBeDefined();
    });

    it("emits process behavior signal when injection+spawn profile fires", async () => {
      const analyzer = new BehaviorCorrelationAnalyzer();
      const artifact = makeArtifact({
        strings: [
          "NtCreateThreadEx",
          "WriteProcessMemory",
          "ShellExecute",
          "powershell"
        ],
        interestingStrings: []
      });
      const result = await analyzer.analyze(artifact);
      const injectFinding = result.findings.find((f) => f.title.includes("CORR_InjectSpawn"));
      if (injectFinding) {
        expect(result.behaviorSignals.process?.detected).toBe(true);
      }
    });
  });

  // ── Profile 4: Crypto Stealing ───────────────────────────────────────────

  describe("profile: Crypto Stealing (wallet addresses + crypto library imports)", () => {
    it("detects Bitcoin wallet address combined with libcrypto import", async () => {
      const analyzer = new BehaviorCorrelationAnalyzer();
      const artifact = makeArtifact({
        strings: [
          // Bitcoin address (valid P2PKH)
          "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf",
          // Crypto library
          "libcrypto.so.1.1",
          "BCryptOpenAlgorithmProvider"
        ],
        interestingStrings: []
      });

      const result = await analyzer.analyze(artifact);
      const cryptoFinding = result.findings.find((f) => f.title.includes("CORR_CryptoStealing"));
      expect(cryptoFinding).toBeDefined();
      expect(cryptoFinding!.severity).toBe("high");
      expect(cryptoFinding!.description).toMatch(/crypto.*stealing|wallet.*crypto/i);
      expect(result.behaviorSignals.crypto?.detected).toBe(true);
    });

    it("detects Ethereum address combined with web3 library reference", async () => {
      const analyzer = new BehaviorCorrelationAnalyzer();
      const artifact = makeArtifact({
        strings: [
          "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
          "web3.eth.getBalance",
          "ethers.provider"
        ],
        interestingStrings: []
      });

      const result = await analyzer.analyze(artifact);
      const cryptoFinding = result.findings.find((f) => f.title.includes("CORR_CryptoStealing"));
      expect(cryptoFinding).toBeDefined();
    });

    it("detects wallet.dat combined with CryptDecrypt — wallet-file decryption", async () => {
      const analyzer = new BehaviorCorrelationAnalyzer();
      const artifact = makeArtifact({
        strings: [
          "wallet.dat",
          "mnemonic phrase",
          "CryptDecrypt",
          "openssl"
        ],
        interestingStrings: []
      });
      const result = await analyzer.analyze(artifact);
      const cryptoFinding = result.findings.find((f) => f.title.includes("CORR_CryptoStealing"));
      expect(cryptoFinding).toBeDefined();
    });
  });

  // ── Multi-profile correlation ────────────────────────────────────────────

  describe("multi-profile coordinated attack (all profiles active)", () => {
    it("detects multiple coordinated profiles simultaneously", async () => {
      const analyzer = new BehaviorCorrelationAnalyzer();
      const artifact = makeArtifact({
        strings: [
          // Exfil + C2
          "CryptUnprotectData",
          "LsaOpenPolicy",
          "discord.com/api/webhooks/000/exfil",
          // Persistence + Wiper
          "RegSetValueEx",
          "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
          "vssadmin delete shadows",
          "DeleteFileW",
          // Injection + Spawn
          "WriteProcessMemory",
          "CreateRemoteThread",
          "CreateProcess",
          // Crypto Stealing
          "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf",
          "libcrypto.so"
        ],
        interestingStrings: []
      });

      const result = await analyzer.analyze(artifact);

      // All four profiles should fire
      const profileIds = result.findings.map((f) => f.title);
      expect(profileIds.some((t) => t.includes("CORR_ExfilC2"))).toBe(true);
      expect(profileIds.some((t) => t.includes("CORR_PersistWiper"))).toBe(true);
      expect(profileIds.some((t) => t.includes("CORR_InjectSpawn"))).toBe(true);
      expect(profileIds.some((t) => t.includes("CORR_CryptoStealing"))).toBe(true);

      // All findings should have high/critical severity
      for (const f of result.findings) {
        expect(["high", "critical"]).toContain(f.severity);
      }

      // Confidence should be at maximum (1.0) — all groups matched
      expect(result.confidence).toBeGreaterThanOrEqual(0.9);

      // Metadata should list all matched profile IDs
      const meta = result.metadata as { matchedProfileIds: string[] };
      expect(meta.matchedProfileIds).toContain("CORR_ExfilC2");
      expect(meta.matchedProfileIds).toContain("CORR_PersistWiper");
      expect(meta.matchedProfileIds).toContain("CORR_InjectSpawn");
      expect(meta.matchedProfileIds).toContain("CORR_CryptoStealing");
    });
  });

  // ── AnalyzerRegistry integration ─────────────────────────────────────────

  describe("AnalyzerRegistry integration — behavior-correlation runs in merged scan", () => {
    it("includes behavior-correlation version in analyzerVersions", async () => {
      const registry = await AnalyzerRegistry.createDefault();
      const artifact = makeArtifact({
        strings: [
          "WriteProcessMemory",
          "CreateRemoteThread",
          "CreateProcess",
          "powershell"
        ],
        interestingStrings: []
      });

      const merged = await registry.analyze(artifact);
      expect(merged.analyzerVersions["behavior-correlation"]).toBeDefined();
      expect(merged.analyzerVersions["behavior-correlation"]).toMatch(/^\d+\.\d+\.\d+$/);
    });

    it("filter to behavior-correlation only — only that analyzer's version recorded", async () => {
      const registry = await AnalyzerRegistry.createDefault();
      const artifact = makeArtifact({ strings: [], interestingStrings: [] });

      const result = await registry.analyze(artifact, ["behavior-correlation"]);
      expect(Object.keys(result.analyzerVersions)).toContain("behavior-correlation");
      expect(Object.keys(result.analyzerVersions)).not.toContain("yara");
      expect(Object.keys(result.analyzerVersions)).not.toContain("heuristic");
      expect(Object.keys(result.analyzerVersions)).not.toContain("string-sig");
    });

    it("behavior-correlation findings are in analyzerResults for coordinated binary", async () => {
      const registry = await AnalyzerRegistry.createDefault();
      const artifact = makeArtifact({
        strings: [
          // Injection + Spawn (full profile)
          "WriteProcessMemory",
          "VirtualAllocEx",
          "CreateRemoteThread",
          "CreateProcess",
          "cmd.exe",
          // Exfil + C2 (full profile)
          "LsaOpenPolicy",
          "CryptUnprotectData",
          "discord.com/api/webhooks/999/exfil"
        ],
        interestingStrings: []
      });

      const merged = await registry.analyze(artifact);
      const corrResult = merged.analyzerResults.find(
        (r) => r.analyzerName === "behavior-correlation"
      );
      expect(corrResult).toBeDefined();
      expect(corrResult!.findings.length).toBeGreaterThan(0);

      const injectFinding = corrResult!.findings.find((f) =>
        f.title.includes("CORR_InjectSpawn")
      );
      expect(injectFinding).toBeDefined();

      const exfilFinding = corrResult!.findings.find((f) =>
        f.title.includes("CORR_ExfilC2")
      );
      expect(exfilFinding).toBeDefined();
    });
  });
});
