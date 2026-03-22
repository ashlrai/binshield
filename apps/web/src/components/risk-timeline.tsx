"use client";

import type { RiskLevel } from "@binshield/analysis-types";

export interface TimelinePoint {
  version: string;
  riskScore: number;
  riskLevel: RiskLevel;
  binaryCount: number;
  active?: boolean;
}

const levelColor: Record<RiskLevel, string> = {
  none: "#95a9c3",
  low: "#7df9c6",
  medium: "#ffb457",
  high: "#ff7676",
  critical: "#ff4040"
};

export function RiskTimeline({
  points,
  height = 200,
  onSelect
}: {
  points: TimelinePoint[];
  height?: number;
  onSelect?: (version: string) => void;
}) {
  if (points.length === 0) return null;

  const maxScore = Math.max(...points.map((p) => p.riskScore), 20);
  const padding = { top: 24, right: 32, bottom: 40, left: 48 };
  const chartWidth = Math.max(points.length * 80, 320);
  const innerWidth = chartWidth - padding.left - padding.right;
  const innerHeight = height - padding.top - padding.bottom;

  function x(i: number) {
    return padding.left + (i / Math.max(points.length - 1, 1)) * innerWidth;
  }

  function y(score: number) {
    return padding.top + innerHeight - (score / maxScore) * innerHeight;
  }

  const pathData = points
    .map((p, i) => `${i === 0 ? "M" : "L"} ${x(i)} ${y(p.riskScore)}`)
    .join(" ");

  const areaData = `${pathData} L ${x(points.length - 1)} ${y(0)} L ${x(0)} ${y(0)} Z`;

  return (
    <div className="risk-timeline">
      <svg
        viewBox={`0 0 ${chartWidth} ${height}`}
        width="100%"
        height={height}
        preserveAspectRatio="xMidYMid meet"
      >
        <defs>
          <linearGradient id="timeline-fill" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.25" />
            <stop offset="100%" stopColor="var(--accent)" stopOpacity="0" />
          </linearGradient>
        </defs>

        {/* Grid lines */}
        {[0, 0.25, 0.5, 0.75, 1].map((pct) => (
          <g key={pct}>
            <line
              x1={padding.left}
              x2={chartWidth - padding.right}
              y1={padding.top + innerHeight * (1 - pct)}
              y2={padding.top + innerHeight * (1 - pct)}
              stroke="var(--border)"
              strokeDasharray="4 4"
            />
            <text
              x={padding.left - 8}
              y={padding.top + innerHeight * (1 - pct) + 4}
              fill="var(--muted)"
              fontSize="11"
              textAnchor="end"
              fontFamily="IBM Plex Mono, monospace"
            >
              {Math.round(maxScore * pct)}
            </text>
          </g>
        ))}

        {/* Area fill */}
        <path d={areaData} fill="url(#timeline-fill)" />

        {/* Line */}
        <path d={pathData} fill="none" stroke="var(--accent)" strokeWidth="2.5" strokeLinejoin="round" />

        {/* Points */}
        {points.map((point, i) => (
          <g key={i}>
            <circle
              cx={x(i)}
              cy={y(point.riskScore)}
              r={point.active ? 7 : 5}
              fill={levelColor[point.riskLevel]}
              stroke={point.active ? "var(--text)" : "none"}
              strokeWidth={2}
              style={{ cursor: onSelect ? "pointer" : "default" }}
              onClick={() => onSelect?.(point.version)}
            />
            <text
              x={x(i)}
              y={height - 8}
              fill={point.active ? "var(--text)" : "var(--muted)"}
              fontSize="11"
              textAnchor="middle"
              fontFamily="IBM Plex Mono, monospace"
              fontWeight={point.active ? 700 : 400}
            >
              {point.version}
            </text>
          </g>
        ))}
      </svg>
    </div>
  );
}
