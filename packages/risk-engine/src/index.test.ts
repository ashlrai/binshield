import { describe, expect, it } from "vitest";

import { emptyBehaviorSummary, sampleAnalyses } from "@binshield/analysis-types";
import { aggregatePackageRisk, riskLevelFromScore, scoreBinary } from "./index";

describe("risk engine", () => {
  it("maps scores to levels", () => {
    expect(riskLevelFromScore(0)).toBe("none");
    expect(riskLevelFromScore(12)).toBe("low");
    expect(riskLevelFromScore(34)).toBe("medium");
    expect(riskLevelFromScore(65)).toBe("high");
    expect(riskLevelFromScore(91)).toBe("critical");
  });

  it("scores suspicious behaviors above benign ones", () => {
    const low = scoreBinary({
      behaviors: emptyBehaviorSummary(),
      findings: [],
      importCount: 4,
      functionCount: 20
    });
    const high = scoreBinary({
      behaviors: {
        ...emptyBehaviorSummary(),
        network: { detected: true, details: ["Connects to remote host"] },
        dataExfiltration: { detected: true, details: ["Uploads environment variables"] },
        obfuscation: { detected: true, details: ["Encrypted strings"] }
      },
      findings: [
        {
          severity: "critical",
          title: "Outbound exfiltration",
          description: "Sends data to an unknown domain",
          recommendation: "Block package"
        }
      ],
      importCount: 18,
      functionCount: 52
    });

    expect(high.riskScore).toBeGreaterThan(low.riskScore);
    expect(high.riskLevel).toBe("critical");
  });

  it("aggregates package risk from binaries", () => {
    const aggregate = aggregatePackageRisk(sampleAnalyses[0].binaries);
    expect(aggregate.riskScore).toBeGreaterThan(0);
    expect(aggregate.riskLevel).toBe("low");
  });
});
