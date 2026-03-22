import type { RiskLevel } from "@binshield/analysis-types";

const riskThresholds: Array<{ level: RiskLevel; min: number; max: number; description: string }> = [
  { level: "none", min: 0, max: 0, description: "No behaviors or findings detected." },
  { level: "low", min: 1, max: 29, description: "Expected behaviors only. Safe for most environments." },
  { level: "medium", min: 30, max: 59, description: "Some review-worthy behaviors. Inspect before deploying in hardened environments." },
  { level: "high", min: 60, max: 79, description: "Multiple risk signals. Manual review required before production use." },
  { level: "critical", min: 80, max: 100, description: "Severe risk indicators. Block until validated by a security engineer." }
];

const scoringFactors = [
  { factor: "Findings", weight: "2-45 pts per finding", detail: "Severity-weighted: info=2, low=8, medium=18, high=30, critical=45" },
  { factor: "Behaviors", weight: "3-28 pts per detected", detail: "network=14, filesystem=4, process=12, crypto=3, obfuscation=24, exfiltration=28" },
  { factor: "Import count", weight: "Up to 6 pts", detail: "importCount / 4, capped at 6. More imports = larger attack surface." },
  { factor: "Function count", weight: "Up to 5 pts", detail: "functionCount / 20, capped at 5. Complexity indicator." }
];

export function MethodologyPanel({ currentScore, currentLevel }: { currentScore: number; currentLevel: RiskLevel }) {
  return (
    <div className="panel methodology-panel">
      <div className="panel__heading">
        <h2>How this score was computed</h2>
        <span>Methodology transparency</span>
      </div>

      <div className="methodology-panel__score-bar">
        {riskThresholds.map((threshold) => {
          const width = threshold.max - threshold.min + 1;
          const isCurrent = threshold.level === currentLevel;
          return (
            <div
              key={threshold.level}
              className={`methodology-panel__segment methodology-panel__segment--${threshold.level} ${isCurrent ? "methodology-panel__segment--active" : ""}`}
              style={{ flex: width }}
            >
              <span className="methodology-panel__segment-label">{threshold.level}</span>
              <span className="methodology-panel__segment-range">
                {threshold.min}-{threshold.max}
              </span>
            </div>
          );
        })}
        <div
          className="methodology-panel__marker"
          style={{ left: `${currentScore}%` }}
        >
          <span>{currentScore}</span>
        </div>
      </div>

      <div className="methodology-panel__thresholds">
        {riskThresholds.map((threshold) => (
          <div
            key={threshold.level}
            className={`methodology-panel__threshold ${threshold.level === currentLevel ? "methodology-panel__threshold--active" : ""}`}
          >
            <strong>{threshold.level.toUpperCase()}</strong>
            <span>
              {threshold.min}-{threshold.max}
            </span>
            <p>{threshold.description}</p>
          </div>
        ))}
      </div>

      <div className="methodology-panel__factors">
        <h3>Scoring factors</h3>
        <div className="methodology-panel__factor-grid">
          {scoringFactors.map((item) => (
            <div key={item.factor} className="methodology-panel__factor">
              <strong>{item.factor}</strong>
              <code>{item.weight}</code>
              <p>{item.detail}</p>
            </div>
          ))}
        </div>
      </div>

      <p className="methodology-panel__note">
        Package-level score = 65% highest binary score + 35% average binary score.
        Scores are deterministic and reproducible.
      </p>
    </div>
  );
}
