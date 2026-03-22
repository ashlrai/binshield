# BinShield Outreach Targets (50 Targets)

## How to Find These People

### LinkedIn Search Queries
1. **Compliance:** `"Head of Compliance" OR "CISO" OR "VP Security" AND ("SOC 2" OR "ISO 27001") AND ("fintech" OR "healthcare" OR "SaaS")`
2. **DevSecOps:** `"DevSecOps" OR "AppSec Engineer" OR "Security Engineer" AND "npm" OR "Node.js"`
3. **Researchers:** `"supply chain security" OR "dependency security" AND ("researcher" OR "author" OR "speaker")`

### GitHub Search for Native Package Users
Search for companies with public repos containing native npm packages:
```
filename:package-lock.json "bcrypt" OR "sharp" OR "sqlite3" language:JSON
```

---

## ICP 1: Compliance Officers & CISOs (20 targets)

### Fintech Companies (use native npm packages, SOC 2 required)
| # | Target Role | Company Type | Hook |
|---|------------|-------------|------|
| 1 | CISO or VP Security | Payment processing company (like Stripe, Square) | "Your payment APIs likely use native crypto binaries — are they documented for PCI DSS?" |
| 2 | Head of Compliance | Neobank / digital banking | "Banking regulators are asking about compiled dependencies — binary SBOMs are the answer" |
| 3 | Security Manager | Trading / investment platform | "Financial services need binary-level audit evidence for SOC 2 Type II" |
| 4 | GRC Analyst | Insurance tech | "Insurtech compliance requires documenting what compiled code executes in production" |
| 5 | CISO | Lending / credit platform | "Your underwriting APIs ship native binaries — do your auditors know?" |

### Healthcare Companies (HIPAA + SOC 2)
| # | Target Role | Company Type | Hook |
|---|------------|-------------|------|
| 6 | CISO | Health tech / EHR platform | "HIPAA requires knowing what software executes — including compiled binaries" |
| 7 | Security Director | Telehealth company | "Patient data flows through native npm binaries your team hasn't documented" |
| 8 | Compliance Manager | Health data analytics | "Binary-level SBOMs for HIPAA compliance — no other tool generates these" |

### EU-Based Companies (EU CRA impacted)
| # | Target Role | Company Type | Hook |
|---|------------|-------------|------|
| 9 | CISO | EU SaaS company (>50 employees) | "EU Cyber Resilience Act requires binary-level security documentation by 2027" |
| 10 | Head of Engineering | EU fintech | "CRA compliance needs binary SBOMs — BinShield generates them automatically" |
| 11 | VP Security | EU enterprise software | "Are your compiled npm dependencies documented for CRA?" |
| 12 | Compliance Director | EU e-commerce | "CRA deadline approaching — binary compliance evidence you can generate today" |

### Government Contractors (FedRAMP / Biden EO)
| # | Target Role | Company Type | Hook |
|---|------------|-------------|------|
| 13 | CISO | GovTech company | "Biden EO requires machine-readable SBOMs — including binary components" |
| 14 | Security Architect | Defense contractor | "FedRAMP needs binary-level documentation for supply chain transparency" |
| 15 | Compliance Lead | Federal SaaS provider | "Your government contracts require SBOM evidence that includes compiled code" |

### Large SaaS Companies (SOC 2 + ISO 27001)
| # | Target Role | Company Type | Hook |
|---|------------|-------------|------|
| 16 | CISO | Developer tools company | "You build tools for developers — does your security team document the binaries in your own deps?" |
| 17 | VP Security | Enterprise SaaS (500+ employees) | "SOC 2 evidence gap: what your compiled dependencies actually execute" |
| 18 | Head of AppSec | Cloud infrastructure company | "Your infrastructure likely ships dozens of native binaries — are they classified?" |
| 19 | Security Director | Data platform company | "Data platforms handling sensitive data need binary-level supply chain evidence" |
| 20 | CISO | Communication/collaboration SaaS | "Real-time communication platforms use native bindings — document them for auditors" |

---

## ICP 2: DevSecOps Engineers (20 targets)

### Companies Known to Use Native npm Packages
Find via GitHub: search for companies with public repos using bcrypt, sharp, sqlite3, canvas, argon2.

| # | Target Role | Signal | Hook |
|---|------------|--------|------|
| 21 | DevSecOps Engineer | Uses bcrypt in production | "We analyzed bcrypt@6.0.0 — 10 native binaries, medium risk. Want to see your full dep tree?" |
| 22 | Security Engineer | Uses sharp for image processing | "sharp ships platform-specific binaries — have your security tools checked them?" |
| 23 | AppSec Lead | Uses sqlite3 / better-sqlite3 | "Your database bindings include native code no scanner checks" |
| 24 | Platform Engineer | Uses canvas / node-canvas | "canvas ships cairo + freetype binaries — BinShield found medium risk behaviors" |
| 25 | DevSecOps | Uses argon2 for auth | "argon2 has 11 native binaries — AI classified with crypto + process behaviors" |
| 26 | Security Engineer | Uses sodium-native | "sodium-native ships 10 platform binaries — all classified by BinShield" |
| 27 | DevOps Lead | Uses node-pty / terminal emulators | "node-pty has native bindings — process spawning detected" |
| 28 | AppSec Engineer | Uses isolated-vm | "isolated-vm's native code should be documented for your security team" |
| 29 | Platform Security | Uses bufferutil / ws | "WebSocket packages ship native binaries most teams don't know about" |
| 30 | DevSecOps | Uses ffi-napi | "ffi-napi has 15 binaries with foreign function interface — highest binary count we've seen" |

### Companies with Strong Security Culture
| # | Target Role | Company Trait | Hook |
|---|------------|-------------|------|
| 31-35 | DevSecOps / AppSec | Companies that blog about security, sponsor BSides, contribute to OWASP | "We share your commitment to supply chain security — BinShield adds the binary layer" |
| 36-40 | Security Engineers | Companies with security.txt on their domains | "You clearly care about security — have you looked at what's inside your native npm binaries?" |

---

## ICP 3: Security Researchers & Influencers (10 targets)

| # | Target | Why They'd Care | Hook |
|---|--------|----------------|------|
| 41 | tl;dr sec newsletter author (Clint Gibler) | Covers supply chain security weekly | "We decompiled 23 npm native packages — might be worth a mention in tl;dr sec" |
| 42 | Socket.dev researchers | They analyze install scripts, not binaries | "Complement to Socket's work — we look at the compiled output, not install scripts" |
| 43 | Supply chain security blogger | Writes about npm threats | "We found the usb package scores HIGH (68/100) — thought you'd find this interesting" |
| 44 | OWASP chapter leaders | Supply chain security talks | "Binary analysis for npm — potential talk topic for your next meetup?" |
| 45 | BSides/DefCon speakers | AppSec / supply chain track | "We built an open approach to binary supply chain analysis — would love your feedback" |
| 46-47 | Node.js security team members | Core concern about ecosystem security | "We're documenting what native npm packages actually execute — alignment with Node.js security goals" |
| 48 | DevSecOps Weekly newsletter | Covers tooling | "New tool: BinShield decompiles native npm binaries and classifies behavior with AI" |
| 49 | JavaScript Weekly newsletter | Covers npm ecosystem | "We analyzed bcrypt, sharp, and 21 other native packages — here's what we found" |
| 50 | InfoSec Twitter influencer | Supply chain security content | "Binary-level analysis of npm packages — no one else does this" |

---

## Outreach Tracking Template

Copy this to a spreadsheet:

| Name | Company | Role | LinkedIn URL | Email | Status | First Contact | Response | Notes |
|------|---------|------|-------------|-------|--------|--------------|----------|-------|
| | | | | | Not contacted | | | |

**Status values:** Not contacted → Connection sent → Connected → Message sent → Replied → Call booked → Demo done → Trial → Customer

---

## Weekly Outreach Cadence

**Week 1:** Send 15 LinkedIn connection requests (5 per ICP)
**Week 2:** Follow up with accepted connections, send 15 more
**Week 3:** Start cold email sequences for non-responders, send 10 more LinkedIn
**Week 4:** Follow up on all conversations, book demo calls

**Goal:** 50 contacts → 20 connections → 10 conversations → 3 demos → 1 customer
