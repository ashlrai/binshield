/**
 * Manifest Install-Script Behavior Correlation Engine
 *
 * Detects coordinated attack patterns across npm package.json hooks and PyPI
 * setup.py by correlating individual threat signals into named attack profiles
 * (e.g. env-exfil, reverse-shell-with-wiper, dependency-confusion-cascade).
 *
 * Matching rules:
 *   - >= 2 signals from the profile's threatSignals list must be present.
 *   - Combined confidence (mean of per-signal confidences) >= profile.confidenceFloor.
 *
 * Each matched profile emits a CRITICAL or HIGH ScriptFinding in the output.
 */

import type {
  AttackProfile,
  BehaviorCorrelationResult,
  FindingSeverity,
  ScriptFinding,
  ScriptThreatCategory,
  ScriptThreatSummary,
} from "@binshield/analysis-types";

export type { AttackProfile, BehaviorCorrelationResult };

// ---------------------------------------------------------------------------
// Canonical attack profiles (8–12 profiles)
// ---------------------------------------------------------------------------

/**
 * Canonical library of attack profiles. Each profile describes a multi-signal
 * coordinated attack pattern seen in real npm / PyPI supply-chain incidents.
 */
export const ATTACK_PROFILES: AttackProfile[] = [
  {
    id: "env-exfil",
    name: "Environment Variable Theft + Network Exfiltration",
    threatSignals: ["environmentTheft", "remoteCodeExecution"],
    confidenceFloor: 0.75,
    description:
      "The package harvests environment variables (API tokens, credentials, secrets) " +
      "and transmits them to a remote endpoint during installation. This is the most " +
      "common pattern in npm supply-chain credential-theft attacks.",
  },
  {
    id: "reverse-shell-with-wiper",
    name: "Reverse Shell + Disk Wiper",
    threatSignals: ["reverseShell", "wiper"],
    confidenceFloor: 0.75,
    description:
      "The package opens a reverse shell to a remote host AND executes filesystem " +
      "wiper commands. Combined, these signals indicate a destructive RAT (Remote " +
      "Access Trojan) payload designed to establish persistence then erase evidence.",
  },
  {
    id: "dependency-confusion-cascade",
    name: "Dependency Confusion + Script Injection Cascade",
    threatSignals: ["dependencyConfusion", "scriptInjection"],
    confidenceFloor: 0.75,
    description:
      "The package exploits dependency confusion to substitute a private internal " +
      "package and then injects malicious script payloads via lifecycle hooks. " +
      "Commonly used to pivot from a CI/CD environment into production.",
  },
  {
    id: "c2-beacon-setup",
    name: "C2 Beacon / Persistent Callback Setup",
    threatSignals: ["installHook", "remoteCodeExecution"],
    confidenceFloor: 0.75,
    description:
      "The install hook establishes a persistent callback mechanism to a command-and-" +
      "control (C2) server. The combination of an automatic install trigger with " +
      "remote code execution indicates the package is designed to beacon home after " +
      "every `npm install`.",
  },
  {
    id: "persistence-chain",
    name: "Persistence Chain (Cron / RC File Implant)",
    threatSignals: ["scriptInjection", "reverseShell"],
    confidenceFloor: 0.75,
    description:
      "The package attempts to establish persistent access by combining script " +
      "injection (e.g. writing to .bashrc, cron jobs, or shell profiles) with a " +
      "reverse shell payload. This creates a survivable implant that re-activates " +
      "after reboots.",
  },
  {
    id: "wiper-only-attack",
    name: "Destructive Wiper Attack",
    threatSignals: ["wiper", "remoteCodeExecution"],
    confidenceFloor: 0.75,
    description:
      "The package triggers destructive disk-wipe commands from a remotely fetched " +
      "payload. Seen in politically motivated supply-chain sabotage attacks targeting " +
      "developer workstations and CI servers.",
  },
  {
    id: "full-exfil-chain",
    name: "Full Credential Exfiltration Chain",
    threatSignals: ["environmentTheft", "scriptInjection", "remoteCodeExecution"],
    confidenceFloor: 0.75,
    description:
      "A three-stage credential theft chain: environment variables are harvested " +
      "via injected scripts and sent to a remote C2. Represents the most complete " +
      "form of credential exfiltration, combining access, staging, and transmission.",
  },
  {
    id: "env-exfil-with-persistence",
    name: "Env-Var Theft with Persistence Implant",
    threatSignals: ["environmentTheft", "scriptInjection"],
    confidenceFloor: 0.75,
    description:
      "The package steals environment variables AND writes persistent script " +
      "implants (shell profile modifications, cron entries). This indicates a " +
      "long-term access operation rather than a one-shot theft.",
  },
  {
    id: "reverse-shell-env-harvest",
    name: "Reverse Shell with Credential Harvest",
    threatSignals: ["reverseShell", "environmentTheft"],
    confidenceFloor: 0.75,
    description:
      "The package opens an interactive reverse shell to a remote attacker while " +
      "simultaneously harvesting credentials from the environment. The reverse shell " +
      "gives the attacker live access; the env theft pre-stages exfiltrated secrets.",
  },
  {
    id: "rce-dependency-confusion",
    name: "RCE via Dependency Confusion",
    threatSignals: ["dependencyConfusion", "remoteCodeExecution"],
    confidenceFloor: 0.75,
    description:
      "A dependency confusion substitution attack whose payload executes remote " +
      "code. The confused package name tricks internal tooling into installing an " +
      "attacker-controlled package that immediately contacts a remote host.",
  },
  {
    id: "hook-exfil-wiper",
    name: "Install Hook → Exfiltration → Wipe",
    threatSignals: ["installHook", "environmentTheft", "wiper"],
    confidenceFloor: 0.75,
    description:
      "A full three-phase attack: an install hook triggers credential harvesting " +
      "followed by a disk wipe to destroy forensic evidence. Designed to steal " +
      "secrets silently and cover its tracks in a single install event.",
  },
  {
    id: "rce-reverse-shell-chain",
    name: "Remote Code Execution + Reverse Shell Chain",
    threatSignals: ["remoteCodeExecution", "reverseShell"],
    confidenceFloor: 0.75,
    description:
      "The package chains remote code execution (fetching a remote stage-2 payload) " +
      "with a reverse shell, providing both scriptable control and interactive " +
      "terminal access to the attacker.",
  },
];

// ---------------------------------------------------------------------------
// Per-signal confidence weights
// ---------------------------------------------------------------------------

/**
 * Base confidence contribution for each detected threat category.
 * Higher values reflect stronger signal specificity — a reverse shell detection
 * is almost always malicious, whereas an installHook alone may be benign.
 */
const SIGNAL_CONFIDENCE: Record<ScriptThreatCategory, number> = {
  reverseShell: 0.95,
  wiper: 0.95,
  remoteCodeExecution: 0.90,
  environmentTheft: 0.85,
  scriptInjection: 0.80,
  dependencyConfusion: 0.80,
  installHook: 0.50,
  obfuscation: 0.70,
  knownMalware: 0.99,
  pythonBinaryExtension: 0.40,
  setupToolsHookExecution: 0.45,
  cythonBinaryExtension: 0.40,
  wheelNativeBinary: 0.45,
  pypi_binary_repackaging: 0.85,
  crossEcosystemConfusion: 0.80,
};

// ---------------------------------------------------------------------------
// Input type — accepts ScriptThreatSummary + raw findings
// ---------------------------------------------------------------------------

export interface CorrelatorInput {
  /** Threat signal summary from the manifest analyzer. */
  threats: ScriptThreatSummary;
  /** Raw per-finding list for detail extraction. */
  findings: ScriptFinding[];
}

// ---------------------------------------------------------------------------
// Core correlator class
// ---------------------------------------------------------------------------

/**
 * ManifestBehaviorCorrelator — accepts a ScriptThreatSummary and raw findings,
 * matches detected signals against canonical attack profiles, and returns
 * BehaviorCorrelationResult objects plus CRITICAL/HIGH ScriptFindings.
 */
export class ManifestBehaviorCorrelator {
  private readonly profiles: AttackProfile[];

  constructor(profiles: AttackProfile[] = ATTACK_PROFILES) {
    this.profiles = profiles;
  }

  /**
   * Run correlation against the provided threat summary and findings.
   *
   * Returns:
   *  - `correlations`: one BehaviorCorrelationResult per matched profile
   *  - `findings`: CRITICAL/HIGH ScriptFindings, one per matched profile
   */
  correlate(input: CorrelatorInput): {
    correlations: BehaviorCorrelationResult[];
    findings: ScriptFinding[];
  } {
    const correlations: BehaviorCorrelationResult[] = [];
    const findings: ScriptFinding[] = [];

    for (const profile of this.profiles) {
      const result = this.matchProfile(profile, input);
      if (result) {
        correlations.push(result);
        findings.push(this.toFinding(result, profile));
      }
    }

    return { correlations, findings };
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  private matchProfile(
    profile: AttackProfile,
    input: CorrelatorInput
  ): BehaviorCorrelationResult | null {
    // 1. Determine which profile signals are actually detected.
    const matchedSignals = profile.threatSignals.filter((signal) =>
      this.isSignalDetected(signal, input)
    );

    // 2. Require at least 2 signals to be present.
    if (matchedSignals.length < 2) {
      return null;
    }

    // 3. Compute combined confidence: mean of per-signal confidences,
    //    further weighted by the proportion of required signals matched.
    const meanSignalConfidence =
      matchedSignals.reduce((sum, s) => sum + SIGNAL_CONFIDENCE[s], 0) /
      matchedSignals.length;

    const coverageRatio = matchedSignals.length / profile.threatSignals.length;

    // Combined confidence = mean signal confidence * coverage ratio.
    // For profiles where ALL signals are matched, coverageRatio = 1.0 so the
    // score equals the pure mean confidence.  Partial matches are penalised.
    const aggregatedConfidence = parseFloat(
      (meanSignalConfidence * coverageRatio).toFixed(4)
    );

    // 4. Apply the confidence floor.
    if (aggregatedConfidence < profile.confidenceFloor) {
      return null;
    }

    return {
      profileId: profile.id,
      profileName: profile.name,
      matchedThreatIds: matchedSignals,
      aggregatedConfidence,
      description: profile.description,
    };
  }

  private isSignalDetected(
    category: ScriptThreatCategory,
    input: CorrelatorInput
  ): boolean {
    // Check the ScriptThreatSummary for the seven summary-level keys.
    const summaryKey = category as keyof ScriptThreatSummary;
    if (summaryKey in input.threats) {
      return input.threats[summaryKey].detected;
    }
    // For categories not in the summary (obfuscation, knownMalware, etc.),
    // fall back to checking the raw findings list.
    return input.findings.some((f) => f.category === category);
  }

  private toFinding(
    result: BehaviorCorrelationResult,
    profile: AttackProfile
  ): ScriptFinding {
    const severity: FindingSeverity =
      result.aggregatedConfidence >= 0.85 ? "critical" : "high";

    return {
      category: "scriptInjection", // closest ScriptThreatCategory for taxonomy placement
      severity,
      title: `Coordinated attack pattern detected: ${result.profileName}`,
      description:
        `${result.description} ` +
        `Matched signals: ${result.matchedThreatIds.join(", ")}. ` +
        `Aggregated confidence: ${(result.aggregatedConfidence * 100).toFixed(1)}%.`,
      filePath: "manifest-correlation",
      evidence: `profile=${result.profileId} signals=${result.matchedThreatIds.join("+")} confidence=${result.aggregatedConfidence}`,
      recommendation:
        "Do not install this package. The combination of detected behaviors matches " +
        `a known attack pattern (${result.profileId}). Report to your security team and ` +
        "block this package in your dependency policy.",
    };
  }
}
