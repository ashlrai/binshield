# Security Policy

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

BinShield uses GitHub's private vulnerability reporting as the primary channel.
Open the **Security** tab on this repository and click **"Report a vulnerability"**.

If you prefer email, contact **security@binshield.dev**. We will acknowledge
your report within 2 business days and aim to provide an initial assessment
within 5 business days.

## Scope

**In scope:**
- BinShield platform code (this repository)
- The public API (`api.binshield.dev`)
- The GitHub Action (`apps/github-action`)
- Authentication, authorization, and data-access logic

**Out of scope:**
- Third-party dependencies (report those upstream; we will patch promptly once
  a fix is available)
- Hosted infrastructure, cloud providers, or CDN configuration
- Denial-of-service without a meaningful security impact

## Coordinated Disclosure

We follow coordinated disclosure. We ask that you:

1. Give us reasonable time to investigate and release a fix before any public
   disclosure.
2. Avoid accessing, modifying, or destroying data that does not belong to you.
3. Act in good faith.

In return, we will credit reporters in the release notes unless you prefer to
remain anonymous.

## Supported Versions

BinShield is pre-1.0. Only the latest commit on `main` is actively supported.
Older releases do not receive security backports.
