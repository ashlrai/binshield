# BinShield API Reference

BinShield analyzes native binaries inside open-source packages to detect hidden behaviors, supply-chain risks, and malicious code.

**Base URL:** `https://api.binshield.dev`
**Alternate:** `https://binshieldapi-production.up.railway.app`

**OpenAPI Spec:** Available at `/openapi.json` on the web app.

---

## Authentication

BinShield uses API keys for authenticated endpoints. All `/scans/*` and `/orgs/*` endpoints require authentication. Package read endpoints (`/packages/*`) are public.

### API Key Header

Pass your key in the `x-binshield-api-key` header:

```bash
curl https://api.binshield.dev/scans/scan_123 \
  -H "x-binshield-api-key: bsh_live_YOUR_KEY"
```

### Bearer Token

Alternatively, use the `Authorization` header:

```bash
curl https://api.binshield.dev/scans/scan_123 \
  -H "Authorization: Bearer bsh_live_YOUR_KEY"
```

### Obtaining an API Key

1. Sign in to the BinShield dashboard.
2. Navigate to **Settings > API Keys**.
3. Click **Create Key**, give it a label (e.g., "GitHub Actions"), and copy the key immediately -- it is only shown once.
4. Or use the API: `POST /orgs/{orgId}/api-keys` with `{ "label": "CI Pipeline" }`.

---

## Rate Limiting

| Plan       | Requests / minute | Monthly scans |
|------------|-------------------|---------------|
| Free       | 60                | 50            |
| Pro        | 300               | 2,500         |
| Team       | 600               | 10,000        |
| Enterprise | Unlimited         | 100,000       |

Rate limit headers are included in every response:

- `X-RateLimit-Limit` -- max requests per window
- `X-RateLimit-Remaining` -- remaining requests
- `X-RateLimit-Reset` -- UTC epoch when the window resets

When exceeded, the API returns `429 Too Many Requests`.

---

## Error Handling

All errors return a JSON body with an `error` field:

```json
{
  "error": "Human-readable error message"
}
```

| Status | Meaning                                      |
|--------|----------------------------------------------|
| 400    | Bad request -- missing or invalid parameters |
| 401    | Authentication required or invalid API key    |
| 403    | Forbidden -- not a member of the organization |
| 404    | Resource not found                            |
| 429    | Rate limit exceeded                           |

---

## Packages

Public endpoints for searching, inspecting, diffing, and exporting package analysis data.

### GET /health

Health check for the API service.

```bash
curl https://api.binshield.dev/health
```

**Response:**

```json
{
  "ok": true,
  "service": "binshield-api",
  "mode": "supabase",
  "repository": {
    "mode": "supabase",
    "ready": true,
    "description": "Supabase-backed repository"
  },
  "defaultFailOn": "high"
}
```

---

### GET /packages/search

Search analyzed packages by name.

**Query parameters:**

| Param | Type   | Required | Description            |
|-------|--------|----------|------------------------|
| `q`   | string | No       | Search query string    |

```bash
curl "https://api.binshield.dev/packages/search?q=bcrypt"
```

**Response:**

```json
[
  {
    "ecosystem": "npm",
    "packageName": "bcrypt",
    "latestVersion": "5.1.1",
    "riskLevel": "low",
    "riskScore": 12,
    "summary": "Standard bcrypt native addon with expected entropy access and no suspicious network activity.",
    "binaryCount": 1
  }
]
```

---

### GET /packages/{ecosystem}/{name}

List all analyzed versions of a package.

**Path parameters:**

| Param       | Type   | Description                |
|-------------|--------|----------------------------|
| `ecosystem` | string | `npm` or `pypi`            |
| `name`      | string | Package name               |

```bash
curl https://api.binshield.dev/packages/npm/bcrypt
```

**Response:**

```json
{
  "packageName": "bcrypt",
  "ecosystem": "npm",
  "versions": [
    {
      "id": "pkg_bcrypt_5_1_0",
      "ecosystem": "npm",
      "packageName": "bcrypt",
      "version": "5.1.0",
      "status": "complete",
      "riskScore": 11,
      "riskLevel": "low",
      "summary": "Standard bcrypt native addon with entropy access and no suspicious network activity.",
      "binaryCount": 1,
      "totalBinarySize": 194820,
      "createdAt": "2026-03-20T12:00:00.000Z",
      "binaries": []
    }
  ]
}
```

---

### GET /packages/{ecosystem}/{name}/versions/{version}

Get the full analysis for a specific package version, including all binary analyses, behavior summaries, and findings.

**Path parameters:**

| Param       | Type   | Description      |
|-------------|--------|------------------|
| `ecosystem` | string | `npm` or `pypi`  |
| `name`      | string | Package name     |
| `version`   | string | Package version  |

```bash
curl https://api.binshield.dev/packages/npm/bcrypt/versions/5.1.1
```

**Response:**

```json
{
  "id": "pkg_bcrypt_5_1_1",
  "ecosystem": "npm",
  "packageName": "bcrypt",
  "version": "5.1.1",
  "status": "complete",
  "riskScore": 12,
  "riskLevel": "low",
  "summary": "Standard bcrypt native addon with expected entropy access and no suspicious network activity.",
  "sourceMatchConfidence": "high",
  "binaryCount": 1,
  "totalBinarySize": 198451,
  "aiModel": "claude-sonnet",
  "createdAt": "2026-03-21T12:00:00.000Z",
  "binaries": [
    {
      "id": "bin_bcrypt_lib_511",
      "filename": "bcrypt_lib.node",
      "architecture": "x86_64",
      "format": "ELF",
      "fileSize": 198451,
      "functionCount": 43,
      "importCount": 17,
      "riskScore": 12,
      "riskLevel": "low",
      "decompiledPreview": "int bcrypt_hash(...) { /* native hashing flow */ }",
      "aiExplanation": "The binary performs native password hashing and seed generation using expected runtime libraries.",
      "imports": ["EVP_sha512", "uv_queue_work", "node_module_register"],
      "strings": ["/dev/urandom", "Invalid salt version"],
      "behaviors": {
        "network": { "detected": false, "details": [] },
        "filesystem": { "detected": true, "details": ["Reads /dev/urandom for entropy and salts."] },
        "process": { "detected": false, "details": [] },
        "crypto": { "detected": true, "details": ["Uses OpenSSL EVP routines for hashing and key stretching."] },
        "obfuscation": { "detected": false, "details": [] },
        "dataExfiltration": { "detected": false, "details": [] }
      },
      "findings": [
        {
          "severity": "info",
          "title": "Entropy source access",
          "description": "Reads system entropy for password hashing.",
          "location": "bcrypt_gensalt",
          "recommendation": "No action needed."
        }
      ]
    }
  ]
}
```

---

### GET /packages/{ecosystem}/{name}/versions/{version}/sbom

Export a CycloneDX 1.5 SBOM (Software Bill of Materials) for a package version.

**Path parameters:**

| Param       | Type   | Description      |
|-------------|--------|------------------|
| `ecosystem` | string | `npm` or `pypi`  |
| `name`      | string | Package name     |
| `version`   | string | Package version  |

```bash
curl -o sbom.cdx.json \
  https://api.binshield.dev/packages/npm/bcrypt/versions/5.1.1/sbom
```

The response includes `Content-Disposition: attachment; filename="sbom-bcrypt-5.1.1.cdx.json"` for direct download.

**Response:** A CycloneDX 1.5 JSON document following the [CycloneDX specification](https://cyclonedx.org/specification/overview/).

---

### GET /packages/{ecosystem}/{name}/diff

Compare two versions of a package to see risk changes and behavior differences.

**Path parameters:**

| Param       | Type   | Description      |
|-------------|--------|------------------|
| `ecosystem` | string | `npm` or `pypi`  |
| `name`      | string | Package name     |

**Query parameters:**

| Param  | Type   | Required | Description               |
|--------|--------|----------|---------------------------|
| `from` | string | Yes      | Source version             |
| `to`   | string | Yes      | Target version             |

```bash
curl "https://api.binshield.dev/packages/npm/sqlite3/diff?from=5.1.6&to=5.1.7"
```

**Response:**

```json
{
  "packageName": "sqlite3",
  "ecosystem": "npm",
  "fromVersion": "5.1.6",
  "toVersion": "5.1.7",
  "riskDelta": 4,
  "summary": "Version 5.1.7 adds stricter extension loading checks and a slightly larger native payload.",
  "addedBehaviors": [
    "Additional filesystem path validation before extension loading.",
    "Guarded extension loading before execution."
  ],
  "removedBehaviors": []
}
```

---

## Scans

Authenticated endpoints for submitting and monitoring binary scan jobs.

### POST /scans/packages

Submit a package for binary analysis. Returns `200` with the result if the package was already analyzed (cache hit), or `202` with a queued scan job.

**Requires authentication.**

**Request body:**

| Field         | Type   | Required | Description                           |
|---------------|--------|----------|---------------------------------------|
| `ecosystem`   | string | Yes      | `npm` or `pypi`                       |
| `packageName` | string | Yes      | Package name                          |
| `version`     | string | Yes      | Package version                       |
| `repo`        | string | No       | GitHub repo context                   |
| `source`      | string | No       | `api`, `github-action`, `seed`, `dashboard` |

```bash
curl -X POST https://api.binshield.dev/scans/packages \
  -H "x-binshield-api-key: bsh_live_YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "ecosystem": "npm",
    "packageName": "bcrypt",
    "version": "5.1.1"
  }'
```

**Response (202 -- queued):**

```json
{
  "id": "scan_abc123",
  "status": "queued",
  "stage": "ingest",
  "requestedAt": "2026-03-22T10:00:00.000Z",
  "request": {
    "ecosystem": "npm",
    "packageName": "bcrypt",
    "version": "5.1.1"
  }
}
```

**Response (200 -- cache hit):**

```json
{
  "id": "scan_abc123",
  "status": "complete",
  "requestedAt": "2026-03-22T10:00:00.000Z",
  "completedAt": "2026-03-22T10:00:01.000Z",
  "request": {
    "ecosystem": "npm",
    "packageName": "bcrypt",
    "version": "5.1.1"
  },
  "result": { "...full PackageAnalysis..." },
  "cacheHit": true
}
```

---

### GET /scans/{id}

Get the status and result of a scan job.

**Requires authentication.**

**Path parameters:**

| Param | Type   | Description   |
|-------|--------|---------------|
| `id`  | string | Scan job ID   |

```bash
curl https://api.binshield.dev/scans/scan_abc123 \
  -H "x-binshield-api-key: bsh_live_YOUR_KEY"
```

**Response:**

```json
{
  "id": "scan_abc123",
  "status": "complete",
  "stage": "persist",
  "requestedAt": "2026-03-22T10:00:00.000Z",
  "startedAt": "2026-03-22T10:00:00.500Z",
  "completedAt": "2026-03-22T10:00:05.000Z",
  "request": {
    "ecosystem": "npm",
    "packageName": "bcrypt",
    "version": "5.1.1"
  },
  "result": { "...full PackageAnalysis..." },
  "cacheHit": false
}
```

---

## Organizations

Authenticated endpoints for managing organizations, repos, watchlists, and API keys.

### GET /orgs/{orgId}

Get organization details.

**Requires authentication.** The API key must belong to the specified organization.

```bash
curl https://api.binshield.dev/orgs/org_ashlrai \
  -H "x-binshield-api-key: bsh_live_YOUR_KEY"
```

**Response:**

```json
{
  "id": "org_ashlrai",
  "name": "Ashlr AI",
  "slug": "ashlrai",
  "plan": "pro",
  "billingStatus": "active",
  "createdAt": "2026-03-21T12:00:00.000Z"
}
```

---

### GET /orgs/{orgId}/repos

List all monitored repositories.

```bash
curl https://api.binshield.dev/orgs/org_ashlrai/repos \
  -H "x-binshield-api-key: bsh_live_YOUR_KEY"
```

**Response:**

```json
{
  "items": [
    {
      "id": "repo_1",
      "orgId": "org_ashlrai",
      "githubRepo": "ashlrai/platform-web",
      "nativeDependencyCount": 4,
      "aggregateRiskScore": 22,
      "lastScanAt": "2026-03-21T13:30:00.000Z"
    }
  ]
}
```

---

### POST /orgs/{orgId}/repos

Add a GitHub repository for monitoring.

```bash
curl -X POST https://api.binshield.dev/orgs/org_ashlrai/repos \
  -H "x-binshield-api-key: bsh_live_YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{ "githubRepo": "ashlrai/new-service" }'
```

**Response (201):**

```json
{
  "id": "repo_3",
  "orgId": "org_ashlrai",
  "githubRepo": "ashlrai/new-service",
  "nativeDependencyCount": 0,
  "aggregateRiskScore": 0
}
```

---

### GET /orgs/{orgId}/watchlists

List all watchlists. Watchlists send alerts when monitored packages change.

```bash
curl https://api.binshield.dev/orgs/org_ashlrai/watchlists \
  -H "x-binshield-api-key: bsh_live_YOUR_KEY"
```

**Response:**

```json
{
  "items": [
    {
      "id": "wl_1",
      "orgId": "org_ashlrai",
      "name": "Critical Packages",
      "channel": "email",
      "destination": "security@ashlr.ai",
      "createdAt": "2026-03-21T13:00:00.000Z",
      "packageCount": 3
    }
  ]
}
```

---

### POST /orgs/{orgId}/watchlists

Create a new watchlist.

**Request body:**

| Field         | Type   | Required | Description                                                   |
|---------------|--------|----------|---------------------------------------------------------------|
| `name`        | string | Yes      | Display name                                                  |
| `channel`     | string | Yes      | `email`, `slack`, or `webhook`                                |
| `destination` | string | Yes      | Email address, Slack webhook URL, or HTTP endpoint            |

```bash
curl -X POST https://api.binshield.dev/orgs/org_ashlrai/watchlists \
  -H "x-binshield-api-key: bsh_live_YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Crypto Libraries",
    "channel": "slack",
    "destination": "https://hooks.slack.com/services/T.../B.../xxx"
  }'
```

**Response (201):**

```json
{
  "id": "wl_2",
  "orgId": "org_ashlrai",
  "name": "Crypto Libraries",
  "channel": "slack",
  "destination": "https://hooks.slack.com/services/T.../B.../xxx",
  "createdAt": "2026-03-22T10:00:00.000Z",
  "packageCount": 0
}
```

---

### POST /orgs/{orgId}/watchlists/{watchlistId}/packages

Add a package to a watchlist.

**Request body:**

| Field         | Type   | Required | Description                                    |
|---------------|--------|----------|------------------------------------------------|
| `ecosystem`   | string | Yes      | `npm` or `pypi`                                |
| `packageName` | string | Yes      | Package name                                   |
| `version`     | string | No       | Specific version to watch (omit for all)       |

```bash
curl -X POST https://api.binshield.dev/orgs/org_ashlrai/watchlists/wl_2/packages \
  -H "x-binshield-api-key: bsh_live_YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "ecosystem": "npm",
    "packageName": "argon2"
  }'
```

**Response (201):**

```json
{
  "id": "wp_1",
  "watchlistId": "wl_2",
  "ecosystem": "npm",
  "packageName": "argon2",
  "createdAt": "2026-03-22T10:05:00.000Z"
}
```

---

### GET /orgs/{orgId}/api-keys

List API keys for the organization. Key values are masked.

```bash
curl https://api.binshield.dev/orgs/org_ashlrai/api-keys \
  -H "x-binshield-api-key: bsh_live_YOUR_KEY"
```

**Response:**

```json
{
  "items": [
    {
      "id": "key_1",
      "label": "GitHub Actions",
      "prefix": "bsh_live_****7A91",
      "createdAt": "2026-03-21T12:30:00.000Z"
    }
  ]
}
```

---

### POST /orgs/{orgId}/api-keys

Create a new API key. The full key value is only returned once.

```bash
curl -X POST https://api.binshield.dev/orgs/org_ashlrai/api-keys \
  -H "x-binshield-api-key: bsh_live_YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{ "label": "CI Pipeline" }'
```

**Response (201):**

```json
{
  "id": "key_2",
  "label": "CI Pipeline",
  "prefix": "bsh_live_****B3F0",
  "createdAt": "2026-03-22T10:00:00.000Z"
}
```

---

## Billing

### GET /orgs/{orgId}/subscription

Get subscription details for an organization.

```bash
curl https://api.binshield.dev/orgs/org_ashlrai/subscription \
  -H "x-binshield-api-key: bsh_live_YOUR_KEY"
```

**Response:**

```json
{
  "items": [
    {
      "id": "sub_1",
      "orgId": "org_ashlrai",
      "provider": "stripe",
      "plan": "pro",
      "status": "active",
      "currentPeriodEnd": "2026-04-21T00:00:00.000Z",
      "cancelAtPeriodEnd": false,
      "createdAt": "2026-03-21T12:00:00.000Z",
      "updatedAt": "2026-03-21T12:00:00.000Z"
    }
  ]
}
```

---

### POST /orgs/{orgId}/subscription

Create or update a subscription.

**Request body:**

| Field    | Type   | Required | Description                                              |
|----------|--------|----------|----------------------------------------------------------|
| `plan`   | string | Yes      | `free`, `pro`, `team`, or `enterprise`                   |
| `status` | string | Yes      | `trialing`, `active`, `past_due`, `canceled`, `incomplete` |

```bash
curl -X POST https://api.binshield.dev/orgs/org_ashlrai/subscription \
  -H "x-binshield-api-key: bsh_live_YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{ "plan": "team", "status": "active" }'
```

**Response (200):**

```json
{
  "id": "sub_1",
  "orgId": "org_ashlrai",
  "provider": "stripe",
  "plan": "team",
  "status": "active",
  "cancelAtPeriodEnd": false,
  "createdAt": "2026-03-21T12:00:00.000Z",
  "updatedAt": "2026-03-22T10:00:00.000Z"
}
```

---

### POST /billing/checkout

Create a Stripe checkout session to upgrade to a paid plan.

**Requires authentication.**

**Request body:**

| Field  | Type   | Required | Description                      |
|--------|--------|----------|----------------------------------|
| `plan` | string | Yes      | `pro`, `team`, or `enterprise`   |

```bash
curl -X POST https://api.binshield.dev/billing/checkout \
  -H "x-binshield-api-key: bsh_live_YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{ "plan": "pro" }'
```

**Response (201):**

```json
{
  "checkoutUrl": "https://checkout.stripe.com/c/pay/cs_live_...",
  "customerId": "cus_abc123",
  "subscriptionId": "sub_abc123",
  "plan": "pro",
  "status": "pending"
}
```

Redirect the user to `checkoutUrl` to complete payment.

---

### POST /billing/webhook

Stripe webhook endpoint. This is called by Stripe, not by your application.

Stripe sends events (e.g., `checkout.session.completed`, `invoice.paid`, `customer.subscription.updated`) to this endpoint. The API verifies the `stripe-signature` header using your webhook secret before processing.

**Setup:**

1. In the [Stripe Dashboard](https://dashboard.stripe.com/webhooks), create a new webhook endpoint pointing to `https://api.binshield.dev/billing/webhook`.
2. Select the events you want to receive (recommended: `checkout.session.completed`, `invoice.paid`, `customer.subscription.updated`, `customer.subscription.deleted`).
3. Copy the webhook signing secret and set it as `STRIPE_WEBHOOK_SECRET` in your API environment.

```bash
# Example: testing with the Stripe CLI
stripe listen --forward-to https://api.binshield.dev/billing/webhook
stripe trigger checkout.session.completed
```

**Response:**

```json
{
  "ok": true
}
```

---

## SBOM Export

BinShield generates [CycloneDX 1.5](https://cyclonedx.org/) SBOMs for every analyzed package version. SBOMs include component metadata, binary hashes, and risk annotations.

### Download an SBOM

```bash
# Save to file
curl -o sbom-bcrypt-5.1.1.cdx.json \
  https://api.binshield.dev/packages/npm/bcrypt/versions/5.1.1/sbom

# Pipe to a compliance tool
curl -s https://api.binshield.dev/packages/npm/bcrypt/versions/5.1.1/sbom \
  | your-compliance-tool validate --format cyclonedx
```

The SBOM includes:
- Package metadata (name, version, ecosystem)
- Binary component inventory with SHA-256 hashes
- Risk scores and behavior annotations
- Finding details as vulnerability-like entries

SBOMs are served with `Content-Disposition: attachment` for direct download by browsers and CI pipelines.
