"use client";

import type { BehaviorSummary } from "@binshield/analysis-types";

interface BehaviorNode {
  id: string;
  label: string;
  detected: boolean;
  details: string[];
  severity: "safe" | "watch" | "danger";
}

const behaviorMeta: Record<
  keyof BehaviorSummary,
  { label: string; icon: string; baseSeverity: "safe" | "watch" | "danger" }
> = {
  network: { label: "Network", icon: "globe", baseSeverity: "watch" },
  filesystem: { label: "Filesystem", icon: "folder", baseSeverity: "safe" },
  process: { label: "Process", icon: "terminal", baseSeverity: "watch" },
  crypto: { label: "Crypto", icon: "lock", baseSeverity: "safe" },
  obfuscation: { label: "Obfuscation", icon: "eye-off", baseSeverity: "danger" },
  dataExfiltration: { label: "Exfiltration", icon: "alert", baseSeverity: "danger" }
};

const severityColor = {
  safe: "var(--accent)",
  watch: "var(--warning)",
  danger: "var(--danger)"
};

function buildNodes(behaviors: BehaviorSummary): BehaviorNode[] {
  return (Object.entries(behaviors) as [keyof BehaviorSummary, BehaviorSummary[keyof BehaviorSummary]][]).map(
    ([key, signal]) => ({
      id: key,
      label: behaviorMeta[key].label,
      detected: signal.detected,
      details: signal.details,
      severity: signal.detected ? behaviorMeta[key].baseSeverity : "safe"
    })
  );
}

export function BehaviorFlow({
  behaviors,
  binaryName
}: {
  behaviors: BehaviorSummary;
  binaryName: string;
}) {
  const nodes = buildNodes(behaviors);
  const detectedNodes = nodes.filter((n) => n.detected);
  const inactiveNodes = nodes.filter((n) => !n.detected);

  const nodeWidth = 140;
  const nodeHeight = 56;
  const centerX = 320;
  const centerY = 48;
  const radius = 160;

  function nodePosition(i: number, total: number) {
    const startAngle = -Math.PI / 2;
    const angle = startAngle + ((2 * Math.PI) / total) * i;
    return {
      x: centerX + radius * Math.cos(angle) - nodeWidth / 2,
      y: centerY + radius + radius * Math.sin(angle) - nodeHeight / 2 + 40
    };
  }

  return (
    <div className="behavior-flow">
      <svg viewBox={`0 0 640 ${radius * 2 + 160}`} width="100%" preserveAspectRatio="xMidYMid meet">
        {/* Central node */}
        <rect
          x={centerX - 72}
          y={centerY - 18}
          width={144}
          height={36}
          rx={18}
          fill="var(--card-strong)"
          stroke="var(--border)"
          strokeWidth={1.5}
        />
        <text
          x={centerX}
          y={centerY + 5}
          fill="var(--text)"
          fontSize="12"
          textAnchor="middle"
          fontFamily="IBM Plex Mono, monospace"
          fontWeight={600}
        >
          {binaryName}
        </text>

        {/* Behavior nodes */}
        {nodes.map((node, i) => {
          const pos = nodePosition(i, nodes.length);
          const color = severityColor[node.severity];
          const opacity = node.detected ? 1 : 0.35;

          return (
            <g key={node.id} opacity={opacity}>
              {/* Connection line */}
              <line
                x1={centerX}
                y1={centerY + 18}
                x2={pos.x + nodeWidth / 2}
                y2={pos.y + nodeHeight / 2}
                stroke={node.detected ? color : "var(--border)"}
                strokeWidth={node.detected ? 2 : 1}
                strokeDasharray={node.detected ? "none" : "4 4"}
              />

              {/* Node box */}
              <rect
                x={pos.x}
                y={pos.y}
                width={nodeWidth}
                height={nodeHeight}
                rx={14}
                fill="var(--card)"
                stroke={node.detected ? color : "var(--border)"}
                strokeWidth={node.detected ? 2 : 1}
              />

              {/* Detected indicator */}
              {node.detected && (
                <circle
                  cx={pos.x + nodeWidth - 12}
                  cy={pos.y + 12}
                  r={5}
                  fill={color}
                />
              )}

              {/* Label */}
              <text
                x={pos.x + nodeWidth / 2}
                y={pos.y + 24}
                fill={node.detected ? "var(--text)" : "var(--muted)"}
                fontSize="13"
                textAnchor="middle"
                fontWeight={node.detected ? 600 : 400}
              >
                {node.label}
              </text>

              {/* Detail text */}
              {node.detected && node.details[0] && (
                <text
                  x={pos.x + nodeWidth / 2}
                  y={pos.y + 42}
                  fill="var(--muted)"
                  fontSize="9"
                  textAnchor="middle"
                >
                  {node.details[0].length > 28
                    ? node.details[0].slice(0, 26) + "..."
                    : node.details[0]}
                </text>
              )}
            </g>
          );
        })}
      </svg>

      {/* Legend */}
      <div className="behavior-flow__legend">
        <span className="behavior-flow__legend-item behavior-flow__legend-item--safe">
          {detectedNodes.filter((n) => n.severity === "safe").length} expected
        </span>
        <span className="behavior-flow__legend-item behavior-flow__legend-item--watch">
          {detectedNodes.filter((n) => n.severity === "watch").length} review
        </span>
        <span className="behavior-flow__legend-item behavior-flow__legend-item--danger">
          {detectedNodes.filter((n) => n.severity === "danger").length} flagged
        </span>
        <span className="behavior-flow__legend-item behavior-flow__legend-item--inactive">
          {inactiveNodes.length} not detected
        </span>
      </div>
    </div>
  );
}
