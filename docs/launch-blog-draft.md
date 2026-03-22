# We Decompiled 23 npm Packages — Here's What Their Native Binaries Actually Do

**Every `npm install` downloads compiled machine code that no security tool checks.**

When you install `bcrypt`, you get a pre-compiled `.node` binary. When you install `sharp`, you get platform-specific shared libraries. These binaries execute directly on your servers — but Snyk, Socket, and npm audit only analyze JavaScript source code and package metadata.

We built BinShield to answer a simple question: **what do these binaries actually do?**

## What We Found

We analyzed 23 of the most popular npm packages that ship native binaries, running each through our AI-powered decompilation pipeline. Here are the results:

### High Risk: usb@2.14.0

**Risk Score: 68/100 (HIGH)** — 12 native binaries detected

The `usb` package ships 12 compiled binaries across platforms. Our analysis flagged network-capable symbols, process spawning indicators, and filesystem access patterns that go beyond expected USB device communication. This doesn't mean it's malicious — but it means your CI pipeline should be aware of what it's doing.

### Medium Risk Packages

| Package | Binaries | Risk Score | Key Behaviors |
|---------|----------|------------|---------------|
| node-screenshots@0.2.8 | 1 | 58 | Screen capture, process access |
| ffi-napi@4.0.3 | 15 | 56 | Foreign function interface, arbitrary native calls |
| bcrypt@6.0.0 | 10 | 52 | Crypto operations, filesystem (expected) |
| argon2@0.44.0 | 11 | 51 | Memory-hard hashing, entropy access |
| fsevents@2.3.3 | 1 | 45 | macOS filesystem monitoring |
| utf-8-validate@6.0.5 | 5 | 43 | WebSocket validation |
| sodium-native@5.1.0 | 10 | 42 | Libsodium crypto bindings |
| bufferutil@4.0.9 | 4 | 38 | WebSocket buffer operations |

### Low Risk

| Package | Risk Score | Notes |
|---------|------------|-------|
| node-sass@9.0.0 | 7 | LibSass binding, minimal surface |

### Key Insight: Most Risk Is Expected — But You Should Know

The majority of these packages do exactly what they claim. `bcrypt` does password hashing. `sharp` does image processing. The risk scores reflect the *attack surface* of the binary, not malicious intent.

But here's the problem: **you have zero visibility into this today.** If a package maintainer's build pipeline was compromised and a backdoor was injected into the compiled binary, no existing tool would catch it. The JavaScript source could look clean while the binary exfiltrates data.

## How BinShield Works

1. **Download** — We fetch the actual platform-specific binaries that `npm install` downloads
2. **Extract** — We identify every `.node`, `.so`, `.dylib`, and `.wasm` file in the package
3. **Classify** — Our AI (powered by Grok) analyzes each binary for: network calls, filesystem access, process spawning, crypto operations, obfuscation, and data exfiltration patterns
4. **Score** — A deterministic risk engine produces a 0-100 score based on findings and behaviors
5. **Report** — Results are available via web UI, API, GitHub Action, and CycloneDX SBOM export

## Try It Now

- **Browse the database**: [binshield.dev](https://binshield.dev)
- **Add to your CI**: Install the [BinShield GitHub Action](https://github.com/ashlrai/binshield)
- **Export SBOMs**: `curl https://api.binshield.dev/packages/npm/bcrypt/versions/6.0.0/sbom`

## Why This Matters for Compliance

The EU Cyber Resilience Act and Biden's Executive Order on Cybersecurity both require machine-readable SBOMs from software suppliers. But current SBOM tools only document JavaScript dependencies — they can't tell you what the compiled binaries inside those dependencies actually do.

BinShield produces CycloneDX 1.5 SBOMs with binary-level component detail, behavior classifications, and risk scores. This is the evidence your auditors are asking for.

---

*BinShield is built by [Ashlr AI](https://ashlr.ai). We're offering free Pro trials to the first 20 teams that sign up. [Get started at binshield.dev](https://binshield.dev)*
