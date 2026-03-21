import type { RiskLevel } from "@binshield/analysis-types";

const riskClasses: Record<RiskLevel, string> = {
  none: "risk-none",
  low: "risk-low",
  medium: "risk-medium",
  high: "risk-high",
  critical: "risk-critical"
};

export function RiskBadge({ level, score }: { level: RiskLevel; score: number }) {
  return (
    <span className={`risk-badge ${riskClasses[level]}`}>
      {level.toUpperCase()} ({score})
    </span>
  );
}
