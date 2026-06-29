/**
 * Lockfile-Level Dependency Graph Risk Aggregation & Circular Dep Detection
 *
 * Builds a deterministic dependency graph from a parsed lockfile and computes:
 *   - Max transitive risk score across the entire supply chain
 *   - Circular dependency chains via DFS
 *   - Orphaned dependencies (in graph but unreferenced by any other node)
 *   - Audit summary of risk signals
 *
 * Designed to be pure (no I/O) and deterministic so results are reproducible
 * across runs with the same input.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A single node in the lockfile dependency graph. */
export interface DepNode {
  /** Package name (scoped names like @scope/pkg are supported). */
  name: string;
  /** Resolved version string. */
  version: string;
  /** Ecosystem: npm, pypi, or pnpm. */
  ecosystem: "npm" | "pypi" | "pnpm";
  /** Direct dependency names this package declares. May be empty. */
  deps: string[];
  /**
   * Pre-computed risk score for this individual package (0–100).
   * When omitted the analyzer treats the package as having risk 0.
   */
  riskScore?: number;
}

/**
 * Detected circular dependency chain.  The `chain` array lists package names
 * in DFS traversal order; the last entry depends (directly or transitively)
 * on the first, forming the cycle.
 */
export interface CircularDep {
  /** Nodes involved in the cycle, in discovery order. */
  chain: string[];
}

/** Aggregated graph analysis result. */
export interface LockfileGraphAnalysis {
  /**
   * Total number of unique packages in the graph (direct + transitive).
   */
  totalPackages: number;
  /**
   * Maximum risk score found anywhere in the transitive dependency tree (0–100).
   * Models "weakest-link in supply chain" — a single high-risk transitive dep
   * elevates the overall score.
   */
  maxTransitiveRisk: number;
  /**
   * All unique circular dependency cycles detected via DFS.
   * Each entry contains the chain of package names that form the cycle.
   */
  circularDeps: CircularDep[];
  /**
   * Packages that exist in the graph but are not reachable from any direct
   * dependency or from any other package's dep list.
   *
   * Truly orphaned packages represent dead weight (removed dependency that
   * was not cleaned up from the lockfile) or potential phantom dep injection.
   */
  orphanedDeps: string[];
  /**
   * Human-readable summary of overall risk across the graph.
   */
  auditSummary: string;
}

// ---------------------------------------------------------------------------
// Internal graph representation
// ---------------------------------------------------------------------------

/** Normalised adjacency map: name → set of direct dependency names. */
type AdjMap = Map<string, Set<string>>;

/**
 * Build an adjacency map from an array of DepNodes.
 * Deduplicates edges and handles missing transitive nodes gracefully
 * (a dep name that has no corresponding node is treated as a leaf).
 */
function buildAdjMap(nodes: DepNode[]): AdjMap {
  const adj: AdjMap = new Map();

  for (const node of nodes) {
    if (!adj.has(node.name)) {
      adj.set(node.name, new Set());
    }
    for (const dep of node.deps) {
      adj.get(node.name)!.add(dep);
    }
  }

  return adj;
}

// ---------------------------------------------------------------------------
// Circular dependency detection via iterative DFS
// ---------------------------------------------------------------------------

/**
 * Detect all unique circular dependency cycles in the dependency graph.
 *
 * Uses an iterative DFS with an explicit call-stack to avoid stack-overflow
 * on very deep graphs (500+ nodes).  Each unique cycle (identified by its
 * canonical sorted form) is reported at most once.
 *
 * @param adj - Adjacency map built from lockfile nodes.
 * @returns Array of unique CircularDep entries.
 */
export function detectCircularDependencies(adj: AdjMap): CircularDep[] {
  const cycles: CircularDep[] = [];
  // Canonical set to deduplicate cycles that appear from multiple start nodes
  const seenCycleKeys = new Set<string>();

  // DFS colour states
  const WHITE = 0; // unvisited
  const GRAY = 1;  // on the current path (in-stack)
  const BLACK = 2; // fully processed

  const color = new Map<string, number>();
  for (const node of adj.keys()) {
    color.set(node, WHITE);
  }

  // We use an explicit stack of frames to avoid recursion depth issues.
  // Each frame records the node and an iterator over its neighbours.
  type Frame = { node: string; path: string[]; iter: Iterator<string> };

  for (const start of adj.keys()) {
    if (color.get(start) !== WHITE) continue;

    const stack: Frame[] = [];
    stack.push({
      node: start,
      path: [start],
      iter: (adj.get(start) ?? new Set()).values(),
    });
    color.set(start, GRAY);

    while (stack.length > 0) {
      const frame = stack[stack.length - 1]!;
      const next = frame.iter.next();

      if (next.done) {
        // All neighbours processed — pop the frame
        color.set(frame.node, BLACK);
        stack.pop();
        continue;
      }

      const neighbour = next.value;

      if (color.get(neighbour) === GRAY) {
        // Back-edge: found a cycle.  Extract the cycle chain from the current path.
        const cycleStart = frame.path.indexOf(neighbour);
        const chain =
          cycleStart >= 0
            ? [...frame.path.slice(cycleStart), neighbour]
            : [...frame.path, neighbour];

        // Canonical key: sort the interior nodes so A→B→A and B→A→B map to the same key
        const key = [...chain].sort().join("|");
        if (!seenCycleKeys.has(key)) {
          seenCycleKeys.add(key);
          cycles.push({ chain });
        }
        // Do not descend into the neighbour — it is already on-stack
        continue;
      }

      if (color.get(neighbour) === BLACK) {
        // Already fully explored — no cycle through this edge
        continue;
      }

      // WHITE: push onto stack
      color.set(neighbour, GRAY);
      stack.push({
        node: neighbour,
        path: [...frame.path, neighbour],
        iter: (adj.get(neighbour) ?? new Set()).values(),
      });
    }
  }

  return cycles;
}

// ---------------------------------------------------------------------------
// Orphaned dependency detection
// ---------------------------------------------------------------------------

/**
 * Find packages that are in the graph but are never referenced by any other
 * package's direct dependency list AND are not in the set of root/direct deps.
 *
 * An orphan is a lockfile entry that:
 *   1. Has a node in the graph, AND
 *   2. Is not reachable from any other node's dep list, AND
 *   3. Is not a declared root-level direct dependency.
 *
 * @param nodes - All nodes parsed from the lockfile.
 * @param directDepNames - The top-level direct dependency names (from the
 *   root package's own dependency declarations).
 * @returns Array of orphaned package names.
 */
export function detectOrphanedDeps(nodes: DepNode[], directDepNames: string[]): string[] {
  // Build the set of all packages that ARE referenced by someone
  const referenced = new Set<string>(directDepNames);

  for (const node of nodes) {
    for (const dep of node.deps) {
      referenced.add(dep);
    }
  }

  // Any node not in `referenced` is an orphan
  const orphans: string[] = [];
  for (const node of nodes) {
    if (!referenced.has(node.name)) {
      orphans.push(node.name);
    }
  }

  return orphans;
}

// ---------------------------------------------------------------------------
// Max transitive risk aggregation
// ---------------------------------------------------------------------------

/**
 * Walk the full transitive graph from every node and return the maximum
 * individual risk score encountered.
 *
 * Uses BFS from all roots to avoid O(n²) repeated traversal.  Because we want
 * the global maximum we only need one pass over all nodes.
 */
function computeMaxTransitiveRisk(nodes: DepNode[]): number {
  let max = 0;
  for (const node of nodes) {
    const score = node.riskScore ?? 0;
    if (score > max) max = score;
  }
  return max;
}

// ---------------------------------------------------------------------------
// Audit summary builder
// ---------------------------------------------------------------------------

function buildAuditSummary(
  totalPackages: number,
  maxTransitiveRisk: number,
  circularDeps: CircularDep[],
  orphanedDeps: string[]
): string {
  const parts: string[] = [];

  parts.push(`${totalPackages} package${totalPackages !== 1 ? "s" : ""} in graph`);

  if (maxTransitiveRisk === 0) {
    parts.push("no risk scores recorded");
  } else if (maxTransitiveRisk >= 75) {
    parts.push(`CRITICAL max-transitive risk score ${maxTransitiveRisk}/100`);
  } else if (maxTransitiveRisk >= 50) {
    parts.push(`HIGH max-transitive risk score ${maxTransitiveRisk}/100`);
  } else if (maxTransitiveRisk >= 25) {
    parts.push(`MEDIUM max-transitive risk score ${maxTransitiveRisk}/100`);
  } else {
    parts.push(`LOW max-transitive risk score ${maxTransitiveRisk}/100`);
  }

  if (circularDeps.length > 0) {
    parts.push(`${circularDeps.length} circular dep${circularDeps.length !== 1 ? "s" : ""} detected`);
  } else {
    parts.push("no circular deps");
  }

  if (orphanedDeps.length > 0) {
    parts.push(`${orphanedDeps.length} orphaned dep${orphanedDeps.length !== 1 ? "s" : ""}`);
  } else {
    parts.push("no orphaned deps");
  }

  return parts.join("; ") + ".";
}

// ---------------------------------------------------------------------------
// Main analyzer
// ---------------------------------------------------------------------------

/**
 * Analyze a dependency graph derived from a parsed lockfile.
 *
 * @param nodes - All packages extracted from the lockfile (direct + transitive).
 *   Each node should carry its declared dep names (not versions).
 * @param directDepNames - Names of the root package's declared direct dependencies.
 *   Used to exclude those from the orphan calculation.  Pass an empty array when
 *   all packages are considered peers (e.g. monorepo workspace roots).
 * @returns Deterministic {@link LockfileGraphAnalysis} result.
 */
export function analyzeLockfileGraph(
  nodes: DepNode[],
  directDepNames: string[] = []
): LockfileGraphAnalysis {
  if (nodes.length === 0) {
    return {
      totalPackages: 0,
      maxTransitiveRisk: 0,
      circularDeps: [],
      orphanedDeps: [],
      auditSummary: "Empty graph — no packages to analyze.",
    };
  }

  const adj = buildAdjMap(nodes);
  const circularDeps = detectCircularDependencies(adj);
  const orphanedDeps = detectOrphanedDeps(nodes, directDepNames);
  const maxTransitiveRisk = computeMaxTransitiveRisk(nodes);
  const totalPackages = nodes.length;

  const auditSummary = buildAuditSummary(
    totalPackages,
    maxTransitiveRisk,
    circularDeps,
    orphanedDeps
  );

  return {
    totalPackages,
    maxTransitiveRisk,
    circularDeps,
    orphanedDeps,
    auditSummary,
  };
}

// ---------------------------------------------------------------------------
// Lockfile-format-specific graph builders
// ---------------------------------------------------------------------------

/**
 * Build a DepNode array from a parsed npm package-lock.json (v2/v3 format).
 *
 * The `packages` section maps `node_modules/<name>` → metadata.
 * We extract `dependencies` from each metadata entry as the direct dep names.
 *
 * @param lockJson - Already-parsed JSON object from package-lock.json.
 * @param riskScores - Optional map of package name → risk score (0–100).
 */
export function buildNpmLockfileGraph(
  lockJson: Record<string, unknown>,
  riskScores: Map<string, number> = new Map()
): DepNode[] {
  const nodes: DepNode[] = [];

  // v2/v3: packages section
  const pkgs = lockJson.packages as Record<string, Record<string, unknown>> | undefined;
  if (pkgs && typeof pkgs === "object") {
    for (const [pkgPath, pkgData] of Object.entries(pkgs)) {
      if (pkgPath === "" || !pkgData || typeof pkgData !== "object") continue;

      const name = pkgPath
        .replace(/^node_modules\//, "")
        .replace(/\/node_modules\//g, "/");
      const version = (pkgData.version as string | undefined) ?? "unknown";

      // Collect direct dep names from the "dependencies" map (keys only — no versions needed)
      const rawDeps = pkgData.dependencies as Record<string, unknown> | undefined;
      const deps = rawDeps && typeof rawDeps === "object" ? Object.keys(rawDeps) : [];

      nodes.push({
        name,
        version,
        ecosystem: "npm",
        deps,
        riskScore: riskScores.get(name),
      });
    }
    return nodes;
  }

  // v1: dependencies section (flat map, nested deps not expanded here)
  const depsSection = lockJson.dependencies as Record<string, Record<string, unknown>> | undefined;
  if (depsSection && typeof depsSection === "object") {
    function extractV1(
      depMap: Record<string, Record<string, unknown>>,
    ): void {
      for (const [name, data] of Object.entries(depMap)) {
        if (!data || typeof data !== "object") continue;
        const version = (data.version as string | undefined) ?? "unknown";
        const rawReqs = data.requires as Record<string, unknown> | undefined;
        const deps = rawReqs && typeof rawReqs === "object" ? Object.keys(rawReqs) : [];
        nodes.push({
          name,
          version,
          ecosystem: "npm",
          deps,
          riskScore: riskScores.get(name),
        });
        // Recurse into nested dependencies
        if (data.dependencies && typeof data.dependencies === "object") {
          extractV1(data.dependencies as Record<string, Record<string, unknown>>);
        }
      }
    }
    extractV1(depsSection);
  }

  return nodes;
}

/**
 * Build a DepNode array from a pnpm-lock.yaml string.
 *
 * Parses the `packages:` and `importers:` sections using line-level regex —
 * no YAML library dependency required.
 *
 * @param content - Raw pnpm-lock.yaml text.
 * @param riskScores - Optional map of package name → risk score (0–100).
 */
export function buildPnpmLockfileGraph(
  content: string,
  riskScores: Map<string, number> = new Map()
): DepNode[] {
  const nodes: DepNode[] = [];
  // Match package entries: optional leading "/" then name@version or name@version(...)
  const pkgRe = /^\s{2}([A-Za-z0-9@/_.-]+)@([^:\s(]+)/gm;
  let m: RegExpExecArray | null;

  while ((m = pkgRe.exec(content)) !== null) {
    const name = (m[1] ?? "").replace(/^\//, "");
    const version = m[2] ?? "unknown";
    if (!name || name.includes("(")) continue;

    nodes.push({
      name,
      version,
      ecosystem: "pnpm",
      deps: [], // pnpm-lock.yaml dep graph is complex; dep list left empty (risk-only mode)
      riskScore: riskScores.get(name),
    });
  }

  return nodes;
}

/**
 * Build a DepNode array from a requirements.txt file (PyPI).
 *
 * requirements.txt has no dependency graph — each line is a direct dep.
 * All deps are treated as peers with no transitive edges.
 *
 * @param content - Raw requirements.txt text.
 * @param riskScores - Optional map of package name → risk score (0–100).
 */
export function buildRequirementsTxtGraph(
  content: string,
  riskScores: Map<string, number> = new Map()
): DepNode[] {
  const nodes: DepNode[] = [];

  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) continue;

    const match = line.match(/^([A-Za-z0-9_.-]+)(?:[=~><!\s].*)?$/);
    if (!match?.[1]) continue;

    const name = match[1];
    const versionMatch = line.match(/[=~><]{1,2}([^\s,;]+)/);
    const version = versionMatch?.[1] ?? "unknown";

    nodes.push({
      name,
      version,
      ecosystem: "pypi",
      deps: [],
      riskScore: riskScores.get(name),
    });
  }

  return nodes;
}
