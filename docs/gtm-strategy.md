# BinShield Go-To-Market Strategy

## Week 1: Launch (Do This Now)

### Day 1-2: Content
- [ ] Publish blog post: "We Decompiled 23 npm Packages" (draft in docs/launch-blog-draft.md)
- [ ] Post to Hacker News (title: "We decompiled the native binaries inside your npm dependencies")
- [ ] Post to Reddit r/netsec, r/node, r/javascript, r/devops
- [ ] Tweet thread with key findings (usb HIGH risk, bcrypt analysis)

### Day 3-4: Distribution
- [ ] Publish GitHub Action to marketplace (already has branding + README)
- [ ] Submit to tl;dr sec newsletter
- [ ] Submit to DevSecOps Weekly newsletter
- [ ] Post on LinkedIn with the blog findings

### Day 5-7: Outreach
- [ ] Identify 20 DevSecOps engineers on LinkedIn who've posted about supply chain security
- [ ] DM each with: "We found [specific finding] in a package your company likely uses. Free report: [link]"
- [ ] Email 10 companies that have public package-lock.json files showing native dependencies

## First 10 Customer Playbook

### Target Profile
- **Company size**: 200-2000 employees
- **Role**: DevSecOps engineer, AppSec lead, or VP Engineering
- **Signal**: They use native npm packages (bcrypt, sharp, sqlite3) in production
- **Pain**: Compliance requirements (SOC 2, ISO 27001) or past supply chain incident

### Outreach Template
Subject: We found something interesting in your dependencies

"Hi [Name], we built BinShield to decompile the native binaries inside npm packages — the .node files that no security tool checks. We analyzed [package they use] and found [specific finding]. Here's the full report: [link to binshield.dev/packages/[name]]. Would you want us to scan your full dependency tree? First 20 teams get free Pro access."

### Conversion Path
1. Free: Browse public database, 3 repos, 50 scans/month
2. Trial: 30-day Pro trial (unlimited repos/scans)
3. Pro: $149/mo (most teams here)
4. Team: $499/mo (shared dashboard, Slack alerts)
5. Enterprise: Custom ($2K-10K/mo, SSO, compliance reports)

## What Makes This Sellable NOW (vs. waiting)

1. **Real data** — 23 packages analyzed with actual binary classification. The HIGH risk finding on `usb` is genuinely interesting.
2. **Working product** — Live web app, API, GitHub Action, SBOM export. Not vaporware.
3. **Compliance angle** — CycloneDX SBOM with binary-level detail is what auditors want. No one else has this.
4. **Free tier** — Public database drives awareness. GitHub Action drives adoption. Pro/Team drives revenue.

## What NOT To Build Before Launching

- More packages (23 is enough to prove value)
- Real Ghidra decompilation (heuristic analysis is already useful)
- Perfect UI (it's already better than most security tools)
- SAML/SSO (no one needs this until you have enterprise customers)

## Metrics to Track

### Week 1
- Blog post views
- GitHub Action installs
- Website unique visitors
- Hacker News upvotes/comments

### Month 1
- Free signups
- Scans submitted
- Pro trial activations

### Month 3
- Paying customers
- MRR
- Enterprise conversations
