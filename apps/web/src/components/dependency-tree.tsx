"use client";

import { useState } from "react";

import type { RiskLevel } from "@binshield/analysis-types";

interface DependencyNode {
  name: string;
  version: string;
  riskLevel: RiskLevel;
  riskScore: number;
  binaryCount: number;
  nativeCandidate: boolean;
}

const riskColor: Record<RiskLevel, string> = {
  none: "var(--muted)",
  low: "var(--accent)",
  medium: "var(--warning)",
  high: "var(--danger)",
  critical: "#ff4040"
};

export function DependencyTree({
  dependencies,
  title = "Dependency risk map"
}: {
  dependencies: DependencyNode[];
  title?: string;
}) {
  const [filter, setFilter] = useState<"all" | "native">("native");

  const filtered = filter === "native"
    ? dependencies.filter((d) => d.nativeCandidate)
    : dependencies;

  const sorted = [...filtered].sort((a, b) => b.riskScore - a.riskScore);

  return (
    <div className="dependency-tree panel">
      <div className="panel__heading">
        <h2>{title}</h2>
        <div className="dependency-tree__filters">
          <button
            className={`dependency-tree__filter ${filter === "native" ? "dependency-tree__filter--active" : ""}`}
            onClick={() => setFilter("native")}
          >
            Native only ({dependencies.filter((d) => d.nativeCandidate).length})
          </button>
          <button
            className={`dependency-tree__filter ${filter === "all" ? "dependency-tree__filter--active" : ""}`}
            onClick={() => setFilter("all")}
          >
            All ({dependencies.length})
          </button>
        </div>
      </div>

      <div className="dependency-tree__grid">
        {sorted.map((dep) => (
          <div
            key={`${dep.name}@${dep.version}`}
            className="dependency-tree__node"
            style={{ borderLeftColor: riskColor[dep.riskLevel] }}
          >
            <div className="dependency-tree__node-header">
              <strong>{dep.name}</strong>
              <span className={`risk-badge risk-${dep.riskLevel}`}>
                {dep.riskLevel.toUpperCase()} ({dep.riskScore})
              </span>
            </div>
            <div className="dependency-tree__node-meta">
              <span>v{dep.version}</span>
              {dep.nativeCandidate && <span className="tag">native</span>}
              {dep.binaryCount > 0 && (
                <span>{dep.binaryCount} {dep.binaryCount === 1 ? "binary" : "binaries"}</span>
              )}
            </div>
          </div>
        ))}
        {sorted.length === 0 && (
          <p className="empty-state">No dependencies match the current filter.</p>
        )}
      </div>
    </div>
  );
}
