# BinShield Integration Guide

Comprehensive recipes for integrating BinShield into your supply-chain security workflow.

---

## 1. GitHub Action Setup (3-Step Quick Start)

### Step 1 -- Add the workflow file

Create `.github/workflows/binshield.yml`:

```yaml
name: Binary Dependency Check
on: [pull_request]

jobs:
  binshield:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ashlrai/binshield/apps/github-action@v1
        with:
          fail-on: high
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

### Step 2 -- (Optional) Add an API key for authenticated scans

Store your BinShield API key as a repository secret named `BINSHIELD_API_KEY`, then reference it:

```yaml
      - uses: ashlrai/binshield/apps/github-action@v1
        with:
          api-key: ${{ secrets.BINSHIELD_API_KEY }}
          fail-on: high
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

### Step 3 -- Tune your policy

Set `fail-on` to `critical`, `high`, `medium`, `low`, or `never` depending on your risk tolerance:

```yaml
          fail-on: medium          # block on medium-risk or above
          scan-mode: all-dependencies  # full lockfile audit
          comment-mode: pr-comment     # post results as a PR comment
```

---

## 2. API Integration in JavaScript

### Search packages

```javascript
const res = await fetch(
  "https://binshieldapi-production.up.railway.app/packages/search?q=bcrypt"
);
const results = await res.json();
console.log(results);
```

### Submit a scan

```javascript
const scanRes = await fetch(
  "https://binshieldapi-production.up.railway.app/scans",
  {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${process.env.BINSHIELD_API_KEY}`,
    },
    body: JSON.stringify({
      ecosystem: "npm",
      package: "bcrypt",
      version: "6.0.0",
    }),
  }
);
const { scanId } = await scanRes.json();
```

### Poll for results

```javascript
async function pollScan(scanId, intervalMs = 1500, timeoutMs = 120000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const res = await fetch(
      `https://binshieldapi-production.up.railway.app/scans/${scanId}`,
      { headers: { Authorization: `Bearer ${process.env.BINSHIELD_API_KEY}` } }
    );
    const data = await res.json();
    if (data.status === "complete") return data;
    if (data.status === "error") throw new Error(data.error);
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error("Scan timed out");
}

const result = await pollScan(scanId);
console.log(result.riskLevel, result.riskScore);
```

---

## 3. API Integration in Python

### Search packages

```python
import requests

res = requests.get(
    "https://binshieldapi-production.up.railway.app/packages/search",
    params={"q": "bcrypt"},
)
print(res.json())
```

### Submit and poll a scan

```python
import os, time, requests

API = "https://binshieldapi-production.up.railway.app"
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
    raise TimeoutError("Scan timed out")
```

---

## 4. CI/CD Patterns

### GitHub Actions (full example)

```yaml
name: Binary Dependency Check
on: [pull_request]

jobs:
  binshield:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ashlrai/binshield/apps/github-action@v1
        with:
          api-key: ${{ secrets.BINSHIELD_API_KEY }}
          fail-on: high
          scan-mode: native-only
          comment-mode: both
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

### GitLab CI

```yaml
binshield:
  stage: test
  image: node:20
  script:
    - npx @binshield/cli scan --fail-on high --format json > binshield-report.json
  artifacts:
    reports:
      security: binshield-report.json
  rules:
    - if: $CI_MERGE_REQUEST_ID
```

### CircleCI

```yaml
version: 2.1

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
      - binshield
```

---

## 5. SBOM Export for Compliance

BinShield generates CycloneDX 1.5 SBOMs with binary-level detail.

### Export a single package SBOM

```bash
curl -s \
  "https://binshieldapi-production.up.railway.app/packages/npm/bcrypt/versions/6.0.0/sbom" \
  | jq .
```

### Export and save for audit

```bash
curl -s \
  "https://binshieldapi-production.up.railway.app/packages/npm/bcrypt/versions/6.0.0/sbom" \
  -o bcrypt-6.0.0-sbom.json
```

### Extract component list

```bash
curl -s \
  "https://binshieldapi-production.up.railway.app/packages/npm/bcrypt/versions/6.0.0/sbom" \
  | jq '.components[] | {name, version, type}'
```

---

## 6. Watchlist and Alerting Setup

Monitor packages for new versions and risk changes.

### Add a package to your watchlist

```bash
curl -X POST \
  "https://binshieldapi-production.up.railway.app/orgs/me/watchlists" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $BINSHIELD_API_KEY" \
  -d '{"ecosystem": "npm", "package": "sharp"}'
```

### List your current watchlist

```bash
curl \
  "https://binshieldapi-production.up.railway.app/orgs/me/watchlists" \
  -H "Authorization: Bearer $BINSHIELD_API_KEY"
```

### Remove a package from the watchlist

```bash
curl -X DELETE \
  "https://binshieldapi-production.up.railway.app/orgs/me/watchlists/sharp" \
  -H "Authorization: Bearer $BINSHIELD_API_KEY"
```

When a watched package publishes a new version, BinShield automatically re-scans and sends an email alert to all organization members if the risk level changes.

You can also configure watchlist alerts in the dashboard at [binshield.dev/dashboard/watchlists](https://binshield.dev/dashboard/watchlists).
