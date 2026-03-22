"use client";

import { useState, useMemo } from "react";

interface CallNode {
  id: string;
  label: string;
  type: "function" | "import" | "syscall" | "entry";
  suspicious?: boolean;
}

interface CallEdge {
  from: string;
  to: string;
}

interface CallGraphProps {
  imports: string[];
  callTargets: string[];
  binaryName: string;
  functionCount: number;
}

function buildGraph(props: CallGraphProps): { nodes: CallNode[]; edges: CallEdge[] } {
  const nodes: CallNode[] = [];
  const edges: CallEdge[] = [];
  const seen = new Set<string>();

  const entryId = "entry";
  nodes.push({ id: entryId, label: props.binaryName, type: "entry" });
  seen.add(entryId);

  const suspiciousPatterns = /exec|spawn|system|connect|socket|exfil|beacon|eval|atob/i;

  for (const imp of props.imports.slice(0, 16)) {
    const id = `imp_${imp}`;
    if (!seen.has(id)) {
      nodes.push({
        id,
        label: imp,
        type: "import",
        suspicious: suspiciousPatterns.test(imp)
      });
      seen.add(id);
      edges.push({ from: entryId, to: id });
    }
  }

  for (const target of props.callTargets.slice(0, 12)) {
    const id = `call_${target}`;
    if (!seen.has(id)) {
      const isSyscall = /network_request|process_spawn|filesystem_access/.test(target);
      nodes.push({
        id,
        label: target,
        type: isSyscall ? "syscall" : "function",
        suspicious: suspiciousPatterns.test(target)
      });
      seen.add(id);
      edges.push({ from: entryId, to: id });
    }
  }

  return { nodes, edges };
}

function layoutNodes(nodes: CallNode[]): Map<string, { x: number; y: number }> {
  const positions = new Map<string, { x: number; y: number }>();
  const entry = nodes.find((n) => n.type === "entry");
  const others = nodes.filter((n) => n.type !== "entry");

  if (entry) {
    positions.set(entry.id, { x: 320, y: 40 });
  }

  const imports = others.filter((n) => n.type === "import");
  const functions = others.filter((n) => n.type !== "import");

  imports.forEach((node, i) => {
    const cols = Math.min(imports.length, 4);
    const col = i % cols;
    const row = Math.floor(i / cols);
    positions.set(node.id, {
      x: 80 + col * 160,
      y: 120 + row * 80
    });
  });

  functions.forEach((node, i) => {
    const cols = Math.min(functions.length, 3);
    const col = i % cols;
    const row = Math.floor(i / cols);
    const yOffset = 120 + Math.ceil(imports.length / 4) * 80;
    positions.set(node.id, {
      x: 120 + col * 180,
      y: yOffset + row * 80
    });
  });

  return positions;
}

const typeColor: Record<CallNode["type"], string> = {
  entry: "var(--accent-strong)",
  import: "var(--accent)",
  function: "var(--muted)",
  syscall: "var(--warning)"
};

export function CallGraph({ imports, callTargets, binaryName, functionCount }: CallGraphProps) {
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const { nodes, edges } = useMemo(
    () => buildGraph({ imports, callTargets, binaryName, functionCount }),
    [imports, callTargets, binaryName, functionCount]
  );
  const positions = useMemo(() => layoutNodes(nodes), [nodes]);

  const maxY = Math.max(...Array.from(positions.values()).map((p) => p.y)) + 60;
  const height = Math.max(maxY, 240);

  return (
    <div className="call-graph">
      <div className="call-graph__header">
        <h4>Call graph</h4>
        <span className="call-graph__stats">
          {nodes.length} visible / {functionCount} total functions
        </span>
      </div>

      <svg viewBox={`0 0 640 ${height}`} width="100%" height={height} preserveAspectRatio="xMidYMid meet">
        {/* Edges */}
        {edges.map((edge) => {
          const from = positions.get(edge.from);
          const to = positions.get(edge.to);
          if (!from || !to) return null;
          const targetNode = nodes.find((n) => n.id === edge.to);
          const isHighlighted = hoveredNode === edge.from || hoveredNode === edge.to;

          return (
            <line
              key={`${edge.from}-${edge.to}`}
              x1={from.x}
              y1={from.y + 16}
              x2={to.x}
              y2={to.y - 8}
              stroke={
                targetNode?.suspicious
                  ? "var(--danger)"
                  : isHighlighted
                    ? "var(--accent)"
                    : "var(--border)"
              }
              strokeWidth={isHighlighted ? 2 : 1}
              strokeDasharray={targetNode?.type === "syscall" ? "6 3" : "none"}
              opacity={hoveredNode && !isHighlighted ? 0.2 : 1}
            />
          );
        })}

        {/* Nodes */}
        {nodes.map((node) => {
          const pos = positions.get(node.id);
          if (!pos) return null;
          const isHovered = hoveredNode === node.id;
          const color = node.suspicious ? "var(--danger)" : typeColor[node.type];
          const labelLen = Math.min(node.label.length, 20);
          const rectWidth = Math.max(labelLen * 8 + 24, 80);

          return (
            <g
              key={node.id}
              onMouseEnter={() => setHoveredNode(node.id)}
              onMouseLeave={() => setHoveredNode(null)}
              style={{ cursor: "pointer" }}
              opacity={hoveredNode && !isHovered ? 0.5 : 1}
            >
              <rect
                x={pos.x - rectWidth / 2}
                y={pos.y - 14}
                width={rectWidth}
                height={28}
                rx={14}
                fill={isHovered ? "rgba(125, 249, 198, 0.12)" : "var(--card-strong)"}
                stroke={color}
                strokeWidth={isHovered ? 2 : 1}
              />
              <text
                x={pos.x}
                y={pos.y + 4}
                fill={isHovered ? "var(--text)" : color}
                fontSize="11"
                textAnchor="middle"
                fontFamily="IBM Plex Mono, monospace"
                fontWeight={node.type === "entry" ? 700 : 400}
              >
                {node.label.length > 20 ? node.label.slice(0, 18) + ".." : node.label}
              </text>
            </g>
          );
        })}
      </svg>

      <div className="call-graph__legend">
        <span style={{ color: typeColor.entry }}>entry</span>
        <span style={{ color: typeColor.import }}>import</span>
        <span style={{ color: typeColor.function }}>function</span>
        <span style={{ color: typeColor.syscall }}>syscall</span>
        <span style={{ color: "var(--danger)" }}>suspicious</span>
      </div>
    </div>
  );
}
