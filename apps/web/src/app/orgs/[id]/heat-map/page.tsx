"use client";

/**
 * CVE/EPSS Risk Heat Map Dashboard
 *
 * Visualises the 100 most-relevant CVEs affecting the org's dependency graph
 * correlated by:
 *   - Exploitability  (EPSS percentile — x-axis)
 *   - Severity        (CVSS score      — y-axis / column)
 *   - Adoption rate   (ecosystem %     — blastRadius cell size)
 *
 * Colour tiers:
 *   red    — critical + actively exploited (CISA KEV) or heatScore ≥ 75
 *   yellow — patchable (patch available, heatScore 35–74)
 *   green  — low-risk  (heatScore < 35, no active exploit)
 *
 * Columns are sortable by: exploitability, severity, adoption%, blast_radius.
 */

import { useState, useEffect, useMemo } from "react";
import { useParams } from "next/navigation";

// ---------------------------------------------------------------------------
// Types (mirrored from advisory-service.ts HeatMapEntry to avoid a dep cycle)
// ---------------------------------------------------------------------------

interface HeatMapEntry {
  cveId: string;
  title: string;
  packageName: string;
  ecosystem: string;
  cvssScore: number;
  epssPercentile: number;
  severity: string;
  activeExploit: boolean;
  cisaKevDate?: string;
  patchAvailable: boolean;
  patchedVersion?: string;
  adoptionPct: number;
  blastRadius: number;
  heatScore: number;
  tier: "red" | "yellow" | "green";
}

interface HeatMapData {
  items: HeatMapEntry[];
  total: number;
  generatedAt: string;
  ecosystem: string;
}

type SortKey = "heatScore" | "cvssScore" | "epssPercentile" | "adoptionPct" | "blastRadius";
type SortDir = "asc" | "desc";
type EcosystemFilter = "npm" | "pypi" | "all";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TIER_CLASS: Record<HeatMapEntry["tier"], string> = {
  red: "heat-tier--red",
  yellow: "heat-tier--yellow",
  green: "heat-tier--green",
};

const TIER_LABEL: Record<HeatMapEntry["tier"], string> = {
  red: "Critical / Exploited",
  yellow: "Patchable",
  green: "Low Risk",
};

function fmt(n: number, decimals = 1): string {
  return n.toFixed(decimals);
}

function pctBar(value: number, max = 100): string {
  const pct = Math.min(100, Math.round((value / max) * 100));
  return `${pct}%`;
}

// ---------------------------------------------------------------------------
// Column header with sort arrow
// ---------------------------------------------------------------------------

function SortHeader({
  label,
  col,
  current,
  dir,
  onSort,
}: {
  label: string;
  col: SortKey;
  current: SortKey;
  dir: SortDir;
  onSort: (col: SortKey) => void;
}) {
  const active = current === col;
  return (
    <th
      className={`heat-th${active ? " heat-th--active" : ""}`}
      onClick={() => onSort(col)}
      role="columnheader"
      aria-sort={active ? (dir === "desc" ? "descending" : "ascending") : "none"}
      style={{ cursor: "pointer", userSelect: "none" }}
    >
      {label}
      <span aria-hidden="true" style={{ marginLeft: 4 }}>
        {active ? (dir === "desc" ? "↓" : "↑") : "↕"}
      </span>
    </th>
  );
}

// ---------------------------------------------------------------------------
// Individual heat-map row
// ---------------------------------------------------------------------------

function HeatRow({ entry }: { entry: HeatMapEntry }) {
  const tierCls = TIER_CLASS[entry.tier];

  return (
    <tr className={`heat-row ${tierCls}`}>
      <td className="heat-td heat-td--cve">
        <span className="heat-cve-id">{entry.cveId}</span>
        {entry.activeExploit && (
          <span
            className="heat-badge heat-badge--kev"
            title={`In CISA KEV since ${entry.cisaKevDate ?? "unknown"}`}
          >
            KEV
          </span>
        )}
      </td>
      <td className="heat-td heat-td--title">
        <span className="heat-pkg">{entry.packageName}</span>
        <span className="heat-title">{entry.title.slice(0, 90)}{entry.title.length > 90 ? "…" : ""}</span>
      </td>
      <td className="heat-td heat-td--severity">
        <span className={`risk-badge risk-${(entry.severity ?? "unknown").toLowerCase()}`}>
          {(entry.severity ?? "?").toUpperCase()}
        </span>
      </td>
      <td className="heat-td heat-td--cvss">
        <span className="heat-score">{fmt(entry.cvssScore, 1)}</span>
        <div className="heat-bar" title={`CVSS ${entry.cvssScore}/10`}>
          <div className="heat-bar__fill heat-bar__fill--cvss" style={{ width: pctBar(entry.cvssScore, 10) }} />
        </div>
      </td>
      <td className="heat-td heat-td--epss">
        <span className="heat-score">{fmt(entry.epssPercentile * 100, 1)}%</span>
        <div className="heat-bar" title={`EPSS ${(entry.epssPercentile * 100).toFixed(1)}th percentile`}>
          <div className="heat-bar__fill heat-bar__fill--epss" style={{ width: pctBar(entry.epssPercentile, 1) }} />
        </div>
      </td>
      <td className="heat-td heat-td--adoption">
        <span className="heat-score">{entry.adoptionPct}%</span>
        <div className="heat-bar" title={`Ecosystem adoption ${entry.adoptionPct}%`}>
          <div className="heat-bar__fill heat-bar__fill--adoption" style={{ width: pctBar(entry.adoptionPct) }} />
        </div>
      </td>
      <td className="heat-td heat-td--blast">
        <span className="heat-score">{entry.blastRadius}</span>
        <div className="heat-bar" title={`Blast radius score ${entry.blastRadius}/100`}>
          <div className="heat-bar__fill heat-bar__fill--blast" style={{ width: pctBar(entry.blastRadius) }} />
        </div>
      </td>
      <td className="heat-td heat-td--patch">
        {entry.patchAvailable ? (
          <span className="heat-badge heat-badge--patched" title={`Patch: ${entry.patchedVersion}`}>
            {entry.patchedVersion ?? "Available"}
          </span>
        ) : (
          <span className="heat-badge heat-badge--unpatched">No patch</span>
        )}
      </td>
      <td className="heat-td heat-td--tier">
        <span className={`heat-tier-label ${tierCls}`}>{TIER_LABEL[entry.tier]}</span>
      </td>
    </tr>
  );
}

// ---------------------------------------------------------------------------
// Summary metric card
// ---------------------------------------------------------------------------

function MetricPill({
  label,
  value,
  tone,
}: {
  label: string;
  value: string | number;
  tone?: "danger" | "warning" | "ok" | "neutral";
}) {
  const cls = tone ? `metric-pill metric-pill--${tone}` : "metric-pill";
  return (
    <div className={cls}>
      <span className="metric-pill__value">{value}</span>
      <span className="metric-pill__label">{label}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page component
// ---------------------------------------------------------------------------

export default function CveHeatMapPage() {
  const params = useParams<{ id: string }>();
  const orgId = params?.id ?? "";

  const [data, setData] = useState<HeatMapData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sortKey, setSortKey] = useState<SortKey>("heatScore");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [ecosystemFilter, setEcosystemFilter] = useState<EcosystemFilter>("npm");

  // Fetch heat-map data from the API
  useEffect(() => {
    if (!orgId) return;
    setLoading(true);
    setError(null);

    const url = `/api/orgs/${encodeURIComponent(orgId)}/cve-heat-map?limit=100&ecosystem=${ecosystemFilter}`;

    fetch(url, {
      headers: { "Content-Type": "application/json" },
      credentials: "include",
    })
      .then(async (res) => {
        if (!res.ok) {
          const body = await res.json().catch(() => ({})) as { error?: string };
          throw new Error(body.error ?? `HTTP ${res.status}`);
        }
        return res.json() as Promise<HeatMapData>;
      })
      .then((d) => {
        setData(d);
        setLoading(false);
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : "Failed to load heat map");
        setLoading(false);
      });
  }, [orgId, ecosystemFilter]);

  // Client-side sort
  const sorted = useMemo(() => {
    if (!data) return [];
    return [...data.items].sort((a, b) => {
      const av = a[sortKey] as number;
      const bv = b[sortKey] as number;
      return sortDir === "desc" ? bv - av : av - bv;
    });
  }, [data, sortKey, sortDir]);

  function handleSort(col: SortKey) {
    if (col === sortKey) {
      setSortDir((d) => (d === "desc" ? "asc" : "desc"));
    } else {
      setSortKey(col);
      setSortDir("desc");
    }
  }

  // Summary stats
  const redCount = sorted.filter((e) => e.tier === "red").length;
  const yellowCount = sorted.filter((e) => e.tier === "yellow").length;
  const greenCount = sorted.filter((e) => e.tier === "green").length;
  const kevCount = sorted.filter((e) => e.activeExploit).length;
  const patchableCount = sorted.filter((e) => e.patchAvailable).length;

  return (
    <main className="heat-map-page">
      {/* Page header */}
      <div className="page-header">
        <div>
          <p className="eyebrow">Supply Chain Risk Intelligence</p>
          <h1>CVE Risk Heat Map</h1>
          <p className="page-copy">
            Top CVEs affecting your dependency graph, ranked by exploitability (EPSS) ×
            severity (CVSS) × ecosystem adoption. Prioritise patching by blast radius.
          </p>
        </div>
      </div>

      {/* Ecosystem filter */}
      <div className="heat-map-controls">
        <label htmlFor="eco-filter" className="heat-map-controls__label">
          Ecosystem:
        </label>
        <select
          id="eco-filter"
          className="heat-map-controls__select"
          value={ecosystemFilter}
          onChange={(e) => setEcosystemFilter(e.target.value as EcosystemFilter)}
        >
          <option value="npm">npm</option>
          <option value="pypi">PyPI</option>
          <option value="all">All</option>
        </select>

        {data && (
          <span className="heat-map-controls__meta">
            {data.total} CVEs • updated {new Date(data.generatedAt).toLocaleTimeString()}
          </span>
        )}
      </div>

      {/* Summary metrics */}
      {data && !loading && (
        <div className="heat-map-metrics">
          <MetricPill label="Critical / Exploited" value={redCount} tone="danger" />
          <MetricPill label="Patchable" value={yellowCount} tone="warning" />
          <MetricPill label="Low Risk" value={greenCount} tone="ok" />
          <MetricPill label="CISA KEV" value={kevCount} tone={kevCount > 0 ? "danger" : "neutral"} />
          <MetricPill label="Patch Available" value={patchableCount} tone="ok" />
        </div>
      )}

      {/* State: loading */}
      {loading && (
        <div className="empty-state">
          <p>Loading CVE heat map…</p>
        </div>
      )}

      {/* State: error */}
      {!loading && error && (
        <div className="empty-state">
          <h3>Could not load heat map</h3>
          <p>{error}</p>
        </div>
      )}

      {/* State: empty */}
      {!loading && !error && sorted.length === 0 && (
        <div className="empty-state">
          <h3>No CVEs found</h3>
          <p>
            No CVE advisories are indexed yet for this organisation. Register your
            dependencies and run a scan to populate the heat map.
          </p>
        </div>
      )}

      {/* Heat map grid */}
      {!loading && !error && sorted.length > 0 && (
        <div className="heat-map-table-wrap">
          <table className="heat-map-table" aria-label="CVE risk heat map">
            <thead>
              <tr>
                <th className="heat-th">CVE ID</th>
                <th className="heat-th">Package / Title</th>
                <SortHeader label="Severity" col="cvssScore" current={sortKey} dir={sortDir} onSort={handleSort} />
                <SortHeader label="CVSS" col="cvssScore" current={sortKey} dir={sortDir} onSort={handleSort} />
                <SortHeader label="Exploitability (EPSS)" col="epssPercentile" current={sortKey} dir={sortDir} onSort={handleSort} />
                <SortHeader label="Adoption %" col="adoptionPct" current={sortKey} dir={sortDir} onSort={handleSort} />
                <SortHeader label="Blast Radius" col="blastRadius" current={sortKey} dir={sortDir} onSort={handleSort} />
                <th className="heat-th">Patch</th>
                <th className="heat-th">Tier</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((entry) => (
                <HeatRow key={entry.cveId} entry={entry} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Legend */}
      {!loading && !error && sorted.length > 0 && (
        <div className="heat-map-legend">
          <h3>Colour key</h3>
          <dl className="heat-legend-list">
            <div className="heat-legend-item heat-tier--red">
              <dt>Red — Critical / Exploited</dt>
              <dd>Active exploits in the wild (CISA KEV) or heat score ≥ 75. Patch immediately.</dd>
            </div>
            <div className="heat-legend-item heat-tier--yellow">
              <dt>Yellow — Patchable</dt>
              <dd>Patch available; heat score 35–74. Schedule remediation this sprint.</dd>
            </div>
            <div className="heat-legend-item heat-tier--green">
              <dt>Green — Low Risk</dt>
              <dd>Heat score &lt; 35, no known active exploit. Monitor and patch in next cycle.</dd>
            </div>
          </dl>
          <p className="heat-legend-formula">
            <strong>Heat score</strong> = min(100, CVSS × 5 + EPSS × 40 + KEV × 30) &nbsp;|&nbsp;
            <strong>Blast radius</strong> = adoption% × CVSS / 10
          </p>
        </div>
      )}
    </main>
  );
}
