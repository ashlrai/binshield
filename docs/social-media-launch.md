# BinShield Launch Content — Ready to Post

## Twitter/X Thread

**Tweet 1 (hook):**
We decompiled 23 npm packages and looked inside their native binaries.

What we found: the `usb` package ships 12 compiled binaries and scored HIGH risk (68/100).

Most security tools check JavaScript source. Nobody checks the machine code. Until now.

🧵 Thread:

**Tweet 2:**
When you `npm install bcrypt`, you get a pre-compiled .node binary for your platform.

Snyk checks the JavaScript. Socket checks install scripts. npm audit checks CVEs.

But the actual machine code? Zero visibility.

bcrypt@6.0.0 ships 10 platform binaries with crypto, filesystem, and process behaviors.

**Tweet 3:**
We built @BinShield to fix this blind spot.

It decompiles native package binaries, classifies behavior with AI (powered by @xikirai Grok), and generates CycloneDX SBOMs.

The compliance evidence SOC 2 and EU Cyber Resilience Act auditors are asking for.

**Tweet 4:**
Key findings from our analysis of 23 packages:

📦 usb@2.14.0 — HIGH (68) — 12 binaries
📦 node-screenshots — MEDIUM (58) — 1 binary
📦 ffi-napi — MEDIUM (56) — 15 binaries
📦 bcrypt — MEDIUM (52) — 10 binaries
📦 argon2 — MEDIUM (51) — 11 binaries

Full report: binshield.dev/blog/decompiled-npm-packages

**Tweet 5:**
You can try BinShield right now:

🔍 Browse analyzed packages: binshield.dev/packages
⚡ GitHub Action for CI: 3 lines of YAML
🔧 CLI: npx @binshield/cli scan bcrypt@6.0.0
📋 SBOM export: CycloneDX 1.5 JSON

Free tier, no credit card needed.

**Tweet 6:**
We also built AI-readable documentation so tools like @ChatGPT and @AnthropicAI can recommend BinShield:

binshield.dev/llms.txt — Product overview
binshield.dev/llms-full.txt — Full documentation
binshield.dev/openapi.json — API spec

**Tweet 7 (CTA):**
Binary supply-chain security is the gap nobody's filling.

If you're responsible for your team's dependency security, try BinShield:

binshield.dev

We're offering free Pro trials to the first 20 teams that sign up.

Built by @AshlrAI 🛡️

---

## LinkedIn Post

**Title:** We decompiled the native binaries inside your npm dependencies. Here's what we found.

Every `npm install` downloads compiled machine code that no security tool checks.

When you install bcrypt, you get a pre-compiled .node binary. When you install sharp, you get platform-specific shared libraries. These binaries execute directly on your servers — but Snyk, Socket, and npm audit only analyze JavaScript source code.

We built BinShield (binshield.dev) to look inside the actual machine code.

We analyzed 23 of the most popular npm packages that ship native binaries. Key findings:

• usb@2.14.0 scored HIGH risk (68/100) with 12 native binaries
• bcrypt@6.0.0 has 10 platform-specific binaries with crypto + process behaviors
• ffi-napi ships 15 binaries with foreign function interface capabilities

These packages aren't necessarily malicious — but the behaviors they exhibit need to be documented, especially for teams subject to SOC 2, ISO 27001, or the EU Cyber Resilience Act.

BinShield generates CycloneDX 1.5 SBOMs with binary-level component detail — the compliance evidence that auditors are starting to ask for and that no other tool produces.

Try it free: binshield.dev
Full analysis: binshield.dev/blog/decompiled-npm-packages

#security #supplychainsecurity #npm #devsecops #compliance #sbom

---

## Newsletter Submission Emails

### To: tl;dr sec (Clint Gibler)
Subject: Tool submission: BinShield — binary analysis for npm packages

"Hi Clint,

Built something your readers might find interesting: BinShield decompiles native npm package binaries and classifies behavior with AI.

Key angle: no existing tool looks inside compiled .node files. We analyzed 23 packages and the usb package scored HIGH risk (68/100) with 12 native binaries.

Website: binshield.dev
Detailed write-up: binshield.dev/blog/decompiled-npm-packages
GitHub Action: 3 lines of YAML for CI integration

Free tier available, CycloneDX SBOM export for compliance teams.

Would this be a fit for the newsletter?

Mason Wyatt
Founder, BinShield (Ashlr AI)"

### To: DevSecOps Weekly
Subject: New tool: Binary supply-chain scanner for npm

"Hi team,

Launched BinShield — the first tool that decompiles native npm package binaries and classifies their behavior with AI.

The gap: Snyk/Socket check source code. Nobody checks the compiled .node binaries that execute on servers. BinShield fills that gap with a GitHub Action, CLI, API, and CycloneDX SBOM export.

We analyzed 23 popular packages and published the findings: binshield.dev/blog/decompiled-npm-packages

Would this be relevant for DevSecOps Weekly?

Mason Wyatt
binshield.dev"

### To: JavaScript Weekly / Node Weekly
Subject: We decompiled 23 npm packages with native binaries

"Hi,

We built BinShield to analyze the native binaries inside npm packages — the .node files that most developers don't know exist.

We analyzed bcrypt, sharp, sqlite3, and 20 other packages. Some highlights:
- bcrypt ships 10 platform binaries
- The usb package has 12 binaries and scored HIGH risk
- ffi-napi has 15 binaries with foreign function interface

Full analysis: binshield.dev/blog/decompiled-npm-packages
GitHub Action for CI: binshield.dev/docs/github-action

Thought your readers might find this interesting.

Mason Wyatt
binshield.dev"

---

## Reddit Posts

### r/netsec
Title: "We decompiled native binaries inside 23 npm packages — here's what they actually do"
Post: Link to binshield.dev/blog/decompiled-npm-packages

### r/node
Title: "TIL bcrypt ships 10 pre-compiled .node binaries. We decompiled them all."
Post: Link to binshield.dev/blog/decompiled-npm-packages

### r/javascript
Title: "We built a tool that decompiles the native binaries in your node_modules"
Post: Link to binshield.dev

### r/devops
Title: "New GitHub Action: scan npm dependencies for risky native binaries"
Post: Link to binshield.dev/docs/github-action
