import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Integration Guide",
  description:
    "End-to-end recipes for integrating BinShield into JavaScript, Python, and CI/CD pipelines.",
  alternates: { canonical: "https://binshield.dev/docs/integration" }
};

const API = "https://binshieldapi-production.up.railway.app";

const codeStyle = {
  margin: 0,
  padding: "14px 16px",
  borderRadius: "var(--radius-sm)",
  background: "var(--card-strong)",
  border: "1px solid var(--border)",
  overflowX: "auto" as const,
  fontSize: "0.85rem",
  lineHeight: 1.5
};

export default function IntegrationGuidePage() {
  return (
    <main>
      <div className="surface-grid">
        <div className="page-header">
          <div>
            <p className="eyebrow">Guide</p>
            <h1>Integration Guide</h1>
            <p className="page-copy">
              End-to-end recipes for JavaScript, Python, and CI/CD pipelines — from package search to watchlist alerting.
            </p>
          </div>
        </div>

        {/* Quick Start with GitHub Action */}
        <div className="panel" style={{ display: "grid", gap: "24px" }}>
          <div className="panel__heading">
            <h2>Quick Start with GitHub Action</h2>
          </div>

          <div style={{ display: "grid", gap: "16px" }}>
            <h3 style={{ margin: 0 }}>Step 1 -- Add the workflow file</h3>
            <p style={{ margin: 0, color: "var(--muted)" }}>
              Create <code>.github/workflows/binshield.yml</code>:
            </p>
            <pre style={codeStyle}>
              <code>{`name: Binary Dependency Check
on: [pull_request]

jobs:
  binshield:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ashlrai/binshield-action@v1
        with:
          fail-on: high
          github-token: \${{ secrets.GITHUB_TOKEN }}`}</code>
            </pre>
          </div>

          <div style={{ display: "grid", gap: "16px" }}>
            <h3 style={{ margin: 0 }}>Step 2 -- Add an API key (optional)</h3>
            <p style={{ margin: 0, color: "var(--muted)" }}>
              Store your BinShield API key as a repository secret named <code>BINSHIELD_API_KEY</code>:
            </p>
            <pre style={codeStyle}>
              <code>{`      - uses: ashlrai/binshield-action@v1
        with:
          api-key: \${{ secrets.BINSHIELD_API_KEY }}
          fail-on: high
          github-token: \${{ secrets.GITHUB_TOKEN }}`}</code>
            </pre>
          </div>

          <div style={{ display: "grid", gap: "16px" }}>
            <h3 style={{ margin: 0 }}>Step 3 -- Tune your policy</h3>
            <p style={{ margin: 0, color: "var(--muted)" }}>
              Set <code>fail-on</code> to <code>critical</code>, <code>high</code>, <code>medium</code>, <code>low</code>, or <code>never</code>:
            </p>
            <pre style={codeStyle}>
              <code>{`          fail-on: medium          # block on medium-risk or above
          scan-mode: all-dependencies  # full lockfile audit
          comment-mode: pr-comment     # post results as a PR comment`}</code>
            </pre>
          </div>
        </div>

        {/* JavaScript API Integration */}
        <div className="panel" style={{ display: "grid", gap: "24px" }}>
          <div className="panel__heading">
            <h2>JavaScript API Integration</h2>
          </div>

          <div style={{ display: "grid", gap: "16px" }}>
            <h3 style={{ margin: 0 }}>Search packages</h3>
            <pre style={codeStyle}>
              <code>{`const res = await fetch(
  "${API}/packages/search?q=bcrypt"
);
const results = await res.json();
console.log(results);`}</code>
            </pre>
          </div>

          <div style={{ display: "grid", gap: "16px" }}>
            <h3 style={{ margin: 0 }}>Submit a scan</h3>
            <pre style={codeStyle}>
              <code>{`const scanRes = await fetch(
  "${API}/scans",
  {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: \`Bearer \${process.env.BINSHIELD_API_KEY}\`,
    },
    body: JSON.stringify({
      ecosystem: "npm",
      package: "bcrypt",
      version: "6.0.0",
    }),
  }
);
const { scanId } = await scanRes.json();`}</code>
            </pre>
          </div>

          <div style={{ display: "grid", gap: "16px" }}>
            <h3 style={{ margin: 0 }}>Poll for results</h3>
            <pre style={codeStyle}>
              <code>{`async function pollScan(scanId, intervalMs = 1500, timeoutMs = 120000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const res = await fetch(
      \`${API}/scans/\${scanId}\`,
      { headers: { Authorization: \`Bearer \${process.env.BINSHIELD_API_KEY}\` } }
    );
    const data = await res.json();
    if (data.status === "complete") return data;
    if (data.status === "error") throw new Error(data.error);
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error("Scan timed out");
}

const result = await pollScan(scanId);
console.log(result.riskLevel, result.riskScore);`}</code>
            </pre>
          </div>
        </div>

        {/* Python Integration */}
        <div className="panel" style={{ display: "grid", gap: "24px" }}>
          <div className="panel__heading">
            <h2>Python Integration</h2>
          </div>

          <div style={{ display: "grid", gap: "16px" }}>
            <h3 style={{ margin: 0 }}>Search packages</h3>
            <pre style={codeStyle}>
              <code>{`import requests

res = requests.get(
    "${API}/packages/search",
    params={"q": "bcrypt"},
)
print(res.json())`}</code>
            </pre>
          </div>

          <div style={{ display: "grid", gap: "16px" }}>
            <h3 style={{ margin: 0 }}>Submit and poll a scan</h3>
            <pre style={codeStyle}>
              <code>{`import os, time, requests

API = "${API}"
HEADERS = {"Authorization": f"Bearer {os.environ['BINSHIELD_API_KEY']}"}

# Submit
scan = requests.post(
    f"{API}/scans",
    json={"ecosystem": "npm", "package": "bcrypt", "version": "6.0.0"},
    headers=HEADERS,
).json()

scan_id = scan["scanId"]

# Poll
timeout = time.time() + 120
while time.time() < timeout:
    result = requests.get(f"{API}/scans/{scan_id}", headers=HEADERS).json()
    if result["status"] == "complete":
        print(result["riskLevel"], result["riskScore"])
        break
    if result["status"] == "error":
        raise RuntimeError(result["error"])
    time.sleep(1.5)
else:
    raise TimeoutError("Scan timed out")`}</code>
            </pre>
          </div>
        </div>

        {/* CI/CD Patterns */}
        <div className="panel" style={{ display: "grid", gap: "24px" }}>
          <div className="panel__heading">
            <h2>CI/CD Patterns</h2>
          </div>

          <div style={{ display: "grid", gap: "16px" }}>
            <h3 style={{ margin: 0 }}>GitHub Actions (full example)</h3>
            <pre style={codeStyle}>
              <code>{`name: Binary Dependency Check
on: [pull_request]

jobs:
  binshield:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ashlrai/binshield-action@v1
        with:
          api-key: \${{ secrets.BINSHIELD_API_KEY }}
          fail-on: high
          scan-mode: native-only
          comment-mode: both
          github-token: \${{ secrets.GITHUB_TOKEN }}`}</code>
            </pre>
          </div>

          <div style={{ display: "grid", gap: "16px" }}>
            <h3 style={{ margin: 0 }}>GitLab CI</h3>
            <pre style={codeStyle}>
              <code>{`binshield:
  stage: test
  image: node:20
  script:
    - npx @binshield/cli scan --fail-on high --format json > binshield-report.json
  artifacts:
    reports:
      security: binshield-report.json
  rules:
    - if: $CI_MERGE_REQUEST_ID`}</code>
            </pre>
          </div>

          <div style={{ display: "grid", gap: "16px" }}>
            <h3 style={{ margin: 0 }}>CircleCI</h3>
            <pre style={codeStyle}>
              <code>{`version: 2.1

jobs:
  binshield:
    docker:
      - image: cimg/node:20.0
    steps:
      - checkout
      - run:
          name: BinShield scan
          command: npx @binshield/cli scan --fail-on high

workflows:
  security:
    jobs:
      - binshield`}</code>
            </pre>
          </div>
        </div>

        {/* SBOM Export Pipeline */}
        <div className="panel" style={{ display: "grid", gap: "24px" }}>
          <div className="panel__heading">
            <h2>SBOM Export Pipeline</h2>
          </div>

          <div style={{ display: "grid", gap: "16px" }}>
            <p style={{ margin: 0, color: "var(--muted)" }}>
              BinShield generates CycloneDX 1.5 SBOMs with binary-level detail. Export and save for compliance workflows:
            </p>
            <pre style={codeStyle}>
              <code>{`# Export a single package SBOM
curl -s \\
  "${API}/packages/npm/bcrypt/versions/6.0.0/sbom" \\
  | jq .

# Save for audit
curl -s \\
  "${API}/packages/npm/bcrypt/versions/6.0.0/sbom" \\
  -o bcrypt-6.0.0-sbom.json

# Extract component list
curl -s \\
  "${API}/packages/npm/bcrypt/versions/6.0.0/sbom" \\
  | jq '.components[] | {name, version, type}'`}</code>
            </pre>
          </div>
        </div>
      </div>
    </main>
  );
}
