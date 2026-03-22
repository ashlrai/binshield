# BinShield Outreach Sequences

## LinkedIn Connection Request Templates (under 100 chars)

### For Compliance Officers
"Hi [Name] — building binary-level SBOM tooling for compliance teams. Would love to connect."

### For DevSecOps Engineers
"Hi [Name] — we decompile npm native binaries for security teams. Thought you'd find it interesting."

### For Security Researchers
"Hi [Name] — enjoyed your [article/talk] on supply chain security. Building in this space too."

---

## LinkedIn Follow-Up Messages (after connection accepted)

### For Compliance Officers
"Thanks for connecting, [Name]. I noticed [Company] is [SOC 2 certified / ISO 27001 / EU-based].

We built BinShield to solve a gap we kept seeing: no tool generates binary-level SBOMs. When auditors ask 'what do the compiled binaries in your dependencies actually do?' — most teams have no answer.

BinShield decompiles native npm binaries, classifies their behavior with AI, and exports CycloneDX 1.5 SBOMs with binary-level component detail.

Here's what our analysis of bcrypt looks like: https://binshield.dev/packages/bcrypt

Would a 15-minute walkthrough be useful for your team? Happy to show how it maps to [SOC 2 / ISO 27001 / EU CRA] requirements."

### For DevSecOps Engineers
"Thanks for connecting, [Name]. I saw [Company] uses [bcrypt/sharp/sqlite3] — we actually decompiled those packages and found some interesting things.

For example, bcrypt@6.0.0 ships 10 platform-specific native binaries with crypto, filesystem, and process-spawning behaviors. Not malicious, but worth documenting.

We built BinShield to give teams visibility into what their native dependencies actually execute. It's a GitHub Action + web dashboard + SBOM export.

Here's the full analysis: https://binshield.dev/packages/bcrypt

Would your team find this useful? Happy to run a free scan of your full dependency tree."

### For Security Researchers
"Thanks for connecting, [Name]. Loved your [article/talk] about [topic].

We're building BinShield — it decompiles native npm binaries and classifies behavior with AI. We analyzed 23 packages and found some interesting patterns. For instance, the `usb` package scored 68/100 (HIGH risk) with 12 native binaries.

Full write-up: https://binshield.dev/blog/decompiled-npm-packages

Would love your take on the approach. Are there specific packages you'd want us to analyze?"

---

## Cold Email Sequences

### Sequence 1: Compliance-Focused (3 emails)

**Email 1: The Gap**
Subject: Binary-level SBOMs for [Company]'s audit

"Hi [Name],

Quick question: when your auditors ask what the compiled binaries inside your npm dependencies actually do — what do you show them?

Most teams show nothing, because no tool generates binary-level documentation. Snyk checks source code. Socket checks install scripts. But the actual .node binaries that execute on your servers? Nobody looks.

We built BinShield to fix this. It decompiles native package binaries, classifies behavior with AI, and exports CycloneDX 1.5 SBOMs with binary-level detail.

Here's an example for bcrypt: https://binshield.dev/packages/bcrypt

Would a 15-minute demo be useful before your next audit?

Mason Wyatt
Founder, BinShield (Ashlr AI)
binshield.dev"

**Email 2: The Finding (sent 3 days later if no reply)**
Subject: Re: Binary-level SBOMs for [Company]'s audit

"Hi [Name],

Following up — we analyzed 23 of the most popular npm packages with native binaries. Some highlights:

• usb@2.14.0: HIGH risk (68/100), 12 native binaries
• bcrypt@6.0.0: MEDIUM (52/100), 10 binaries with crypto + process behaviors
• ffi-napi@4.0.3: MEDIUM (56/100), 15 binaries with foreign function interface

These aren't malicious — but they're the kind of evidence that SOC 2 and EU CRA auditors are starting to ask about.

Full analysis: https://binshield.dev/blog/decompiled-npm-packages

Worth a quick chat?

Mason"

**Email 3: The Ask (sent 5 days later if no reply)**
Subject: Re: Binary-level SBOMs for [Company]'s audit

"Hi [Name],

Last note — I know compliance prep is busy work. If binary-level documentation isn't on your radar yet, no worries.

But if you're seeing auditors ask about compiled dependencies, or if the EU Cyber Resilience Act is on your roadmap, BinShield is worth 15 minutes.

We offer a free tier with public database access and 50 scans/month. No commitment needed.

binshield.dev

Mason"

### Sequence 2: DevSecOps-Focused (3 emails)

**Email 1: The Discovery**
Subject: What's inside your native npm binaries?

"Hi [Name],

We scanned [Company]'s public dependencies and found [X] packages that ship native binaries. These binaries execute directly on your servers but aren't checked by Snyk, Socket, or npm audit.

We built BinShield — a GitHub Action that decompiles native binaries and classifies their behavior. It takes 3 lines of YAML to add to your CI:

```yaml
- uses: ashlrai/binshield-action@v1
  with:
    fail-on: high
```

Want us to run a free analysis of your full dependency tree?

Mason Wyatt
binshield.dev"

**Email 2: The Result (3 days later)**
Subject: Your dependency scan results

"Hi [Name],

We ran BinShield on packages commonly used by [Company-type] companies. Here's what we found:

[Personalized finding based on their likely stack]

Full public database: https://binshield.dev/packages

Want to see results for your specific repos?

Mason"

**Email 3: The Close (5 days later)**
Subject: Quick question about [Company]'s dependency security

"Hi [Name],

Simple question: does your team currently have visibility into what the compiled binaries in your npm dependencies actually do?

If not, BinShield gives you that in your CI pipeline. Free tier available.

binshield.dev/docs/github-action

Mason"

---

## Warm Follow-Up (after demo/call)

Subject: Great talking — next steps for [Company]

"Hi [Name],

Thanks for the conversation! Here's a summary of what we discussed:

• [Key pain point they mentioned]
• [Specific feature they were interested in]
• [Timeline they mentioned]

To get started:
1. Sign up at binshield.dev (free tier, no credit card)
2. Install the GitHub Action (3 lines of YAML)
3. Your first scan results will appear as a PR comment

If you need to make the case internally, here's the ROI framing:
• BinShield replaces [X] hours/month of manual binary review
• Generates compliance evidence that no other tool produces
• CycloneDX SBOMs ready for [SOC 2 / ISO 27001 / EU CRA] audits

Happy to do a deeper technical demo with your team if helpful.

Mason"

---

## Hacker News Post

Title: "Show HN: We decompile the native binaries inside your npm dependencies"

Post text:
"Hey HN — we built BinShield (https://binshield.dev) to solve a gap in npm security: nobody checks the compiled binaries.

When you npm install bcrypt, you get a pre-compiled .node binary. Snyk checks the JavaScript source. Socket checks install scripts. But the actual machine code? No tool looks inside.

BinShield does. We analyzed 23 popular npm packages and found:
- bcrypt ships 10 platform-specific binaries with crypto + process behaviors
- The usb package scored HIGH risk (68/100) with 12 native binaries
- ffi-napi has 15 binaries with foreign function interface capabilities

We use AI (Grok) to classify behavior across 6 categories: network, filesystem, process, crypto, obfuscation, and data exfiltration. Results are available as a GitHub Action, API, CLI, or CycloneDX SBOM export.

Public database with all analyses: https://binshield.dev/packages
GitHub Action: https://github.com/ashlrai/binshield
Blog post with full findings: https://binshield.dev/blog/decompiled-npm-packages

Free tier available. Would love feedback from the HN security community."
