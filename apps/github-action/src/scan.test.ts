import { describe, expect, it } from "vitest";

import {
  buildFailureMessage,
  renderComment,
  shouldFail,
  summarize,
  shouldPublishComment,
  shouldPublishSummary
} from "./report";

describe("github action helpers", () => {
  it("fails based on threshold ordering", () => {
    expect(shouldFail("high", "medium")).toBe(true);
    expect(shouldFail("low", "high")).toBe(false);
    expect(shouldFail("critical", "never")).toBe(false);
  });

  it("renders a markdown comment", () => {
    const comment = renderComment([
      {
        target: {
          name: "bcrypt",
          version: "5.1.1",
          path: "node_modules/bcrypt",
          source: "lockfile",
          nativeCandidate: true
        },
        analysis: {
          id: "pkg_bcrypt_5_1_1",
          ecosystem: "npm",
          packageName: "bcrypt",
          version: "5.1.1",
          status: "complete",
          riskScore: 12,
          riskLevel: "low",
          summary: "Standard bcrypt native addon",
          sourceMatchConfidence: "high",
          binaryCount: 1,
          totalBinarySize: 100,
          aiModel: "claude",
          createdAt: "2026-03-21T00:00:00.000Z",
          binaries: [
            {
              id: "bin_1",
              filename: "bcrypt_lib.node",
              architecture: "x86_64",
              format: "ELF",
              fileSize: 100,
              functionCount: 10,
              importCount: 3,
              riskScore: 12,
              riskLevel: "low",
              decompiledPreview: "int bcrypt_hash(...) {}",
              aiExplanation: "Expected bcrypt behavior",
              imports: ["EVP_sha512"],
              strings: ["/dev/urandom"],
              behaviors: {
                network: { detected: false, details: [] },
                filesystem: { detected: true, details: ["Reads /dev/urandom for entropy."] },
                process: { detected: false, details: [] },
                crypto: { detected: true, details: ["Uses crypto routines."] },
                obfuscation: { detected: false, details: [] },
                dataExfiltration: { detected: false, details: [] }
              },
              findings: [
                {
                  severity: "info",
                  title: "Entropy source access",
                  description: "Reads system entropy for password hashing.",
                  recommendation: "No action needed."
                }
              ]
            }
          ]
        }
      }
    ]);
    expect(comment).toContain("BinShield");
    expect(comment).toContain("bcrypt@5.1.1");
    expect(comment).toContain("Evidence cues");
    expect(comment).toContain("Remediation");
  });

  it("summarizes outcomes and comment modes", () => {
    const summary = summarize([
      {
        target: {
          name: "sharp",
          version: "0.33.2",
          path: "node_modules/sharp",
          source: "lockfile",
          nativeCandidate: true
        },
        error: "timeout"
      }
    ]);

    expect(summary.failures).toBe(1);
    expect(shouldPublishComment("both")).toBe(true);
    expect(shouldPublishSummary("summary")).toBe(true);
  });

  it("builds a failure message with evidence and remediation", () => {
    const message = buildFailureMessage(
      [
        {
          target: {
            name: "sharp",
            version: "0.33.2",
            path: "node_modules/sharp",
            source: "lockfile",
            nativeCandidate: true
          },
          analysis: {
            id: "pkg_sharp_0_33_2",
            ecosystem: "npm",
            packageName: "sharp",
            version: "0.33.2",
            status: "complete",
            riskScore: 88,
            riskLevel: "critical",
            summary: "Unexpected outbound activity",
            sourceMatchConfidence: "high",
            binaryCount: 1,
            totalBinarySize: 200,
            aiModel: "claude",
            createdAt: "2026-03-21T00:00:00.000Z",
            binaries: []
          }
        }
      ],
      "high"
    );

    expect(message).toContain("exceeded the high threshold");
    expect(message).toContain("Block the merge");
  });
});
