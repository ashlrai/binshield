"use client";

import { useState, useMemo } from "react";

interface CodeRegion {
  startLine: number;
  endLine: number;
  severity: "info" | "low" | "medium" | "high" | "critical";
  label: string;
}

export function CodeViewer({
  source,
  language = "c",
  regions = [],
  maxHeight = 480
}: {
  source: string;
  language?: string;
  regions?: CodeRegion[];
  maxHeight?: number;
}) {
  const [expandedRegion, setExpandedRegion] = useState<number | null>(null);
  const lines = useMemo(() => source.split("\n"), [source]);

  function regionForLine(lineNum: number) {
    return regions.find((r) => lineNum >= r.startLine && lineNum <= r.endLine);
  }

  const severityClass: Record<string, string> = {
    info: "code-region--info",
    low: "code-region--low",
    medium: "code-region--medium",
    high: "code-region--high",
    critical: "code-region--critical"
  };

  return (
    <div className="code-viewer" style={{ maxHeight }}>
      {regions.length > 0 && (
        <div className="code-viewer__legend">
          {regions.map((region, i) => (
            <button
              key={i}
              className={`code-region-tag ${severityClass[region.severity]} ${expandedRegion === i ? "code-region-tag--active" : ""}`}
              onClick={() => setExpandedRegion(expandedRegion === i ? null : i)}
            >
              L{region.startLine}-{region.endLine}: {region.label}
            </button>
          ))}
        </div>
      )}
      <pre className="code-viewer__pre">
        <code>
          {lines.map((line, i) => {
            const lineNum = i + 1;
            const region = regionForLine(lineNum);
            return (
              <span
                key={i}
                className={`code-line ${region ? severityClass[region.severity] : ""}`}
              >
                <span className="code-line__number">{lineNum}</span>
                <span className="code-line__content">{line}</span>
              </span>
            );
          })}
        </code>
      </pre>
    </div>
  );
}
