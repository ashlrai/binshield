"use client";

import { useEffect, useState } from "react";

const behaviors = [
  { name: "crypto", label: "CRYPTO", color: "#5ffbbd", detected: true },
  { name: "filesystem", label: "FS", color: "#5ffbbd", detected: true },
  { name: "process", label: "PROC", color: "#ffb040", detected: true },
  { name: "network", label: "NET", color: "#ff5c5c", detected: false },
  { name: "obfuscation", label: "OBFS", color: "#ff5c5c", detected: false },
  { name: "exfiltration", label: "EXFIL", color: "#ff5c5c", detected: false },
];

const binaries = [
  { name: "bcrypt_lib.node", arch: "x64", size: "194K", risk: 18 },
  { name: "bcrypt_lib.node", arch: "arm64", size: "201K", risk: 15 },
  { name: "bcrypt_lib.node", arch: "ia32", size: "178K", risk: 12 },
  { name: "napi.node", arch: "x64", size: "89K", risk: 8 },
];

const imports = [
  "EVP_sha512", "uv_queue_work", "napi_register",
  "bcrypt_gensalt", "getrandom", "node_module_register",
];

export function HeroViz() {
  const [phase, setPhase] = useState(0);
  const [scanProgress, setScanProgress] = useState(0);

  useEffect(() => {
    const timers = [
      setTimeout(() => setPhase(1), 800),
      setTimeout(() => setPhase(2), 2000),
      setTimeout(() => setPhase(3), 3200),
      setTimeout(() => setPhase(4), 4400),
    ];

    const progressInterval = setInterval(() => {
      setScanProgress((p) => {
        if (p >= 100) return 100;
        return p + 2;
      });
    }, 80);

    return () => {
      timers.forEach(clearTimeout);
      clearInterval(progressInterval);
    };
  }, []);

  return (
    <div className="hero-viz">
      {/* Terminal header */}
      <div className="hero-viz__header">
        <div className="hero-viz__dots">
          <span className="hero-viz__dot hero-viz__dot--red" />
          <span className="hero-viz__dot hero-viz__dot--yellow" />
          <span className="hero-viz__dot hero-viz__dot--green" />
        </div>
        <span className="hero-viz__title">binshield — analysis</span>
      </div>

      {/* Command line */}
      <div className="hero-viz__cmd">
        <span className="hero-viz__prompt">$</span>
        <code className="typing-text">binshield scan bcrypt@6.0.0</code>
      </div>

      {/* Scan progress */}
      <div className="hero-viz__progress" style={{ opacity: phase >= 1 ? 1 : 0 }}>
        <div className="hero-viz__progress-bar">
          <div
            className="hero-viz__progress-fill"
            style={{ width: `${Math.min(scanProgress, 100)}%` }}
          />
        </div>
        <span className="hero-viz__progress-label">
          {scanProgress >= 100 ? "Analysis complete" : `Scanning... ${scanProgress}%`}
        </span>
      </div>

      {/* Binary artifacts */}
      <div className="hero-viz__section" style={{ opacity: phase >= 2 ? 1 : 0 }}>
        <div className="hero-viz__section-header">
          <span className="hero-viz__section-label">ARTIFACTS</span>
          <span className="hero-viz__section-count">{binaries.length} binaries</span>
        </div>
        <div className="hero-viz__binaries">
          {binaries.map((bin, i) => (
            <div
              key={i}
              className="hero-viz__binary"
              style={{ animationDelay: `${2 + i * 0.12}s` }}
            >
              <span className="hero-viz__binary-name">{bin.name}</span>
              <span className="hero-viz__binary-meta">{bin.arch}</span>
              <span className="hero-viz__binary-meta">{bin.size}</span>
              <span className="hero-viz__binary-risk" data-risk={bin.risk > 15 ? "medium" : "low"}>
                {bin.risk}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Behavior detection */}
      <div className="hero-viz__section" style={{ opacity: phase >= 3 ? 1 : 0 }}>
        <div className="hero-viz__section-header">
          <span className="hero-viz__section-label">BEHAVIORS</span>
          <span className="hero-viz__section-count">3/6 detected</span>
        </div>
        <div className="hero-viz__behaviors">
          {behaviors.map((b, i) => (
            <div
              key={b.name}
              className={`hero-viz__behavior ${b.detected ? "hero-viz__behavior--active" : ""}`}
              style={{
                borderColor: b.detected ? b.color : "var(--border)",
                animationDelay: `${3.2 + i * 0.1}s`,
              }}
            >
              <span
                className="hero-viz__behavior-dot"
                style={{ background: b.detected ? b.color : "var(--muted)", opacity: b.detected ? 1 : 0.3 }}
              />
              <span>{b.label}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Risk verdict */}
      <div className="hero-viz__verdict" style={{ opacity: phase >= 4 ? 1 : 0 }}>
        <div className="hero-viz__verdict-score">
          <span className="hero-viz__verdict-number">52</span>
          <span className="hero-viz__verdict-label">MEDIUM</span>
        </div>
        <div className="hero-viz__verdict-bar">
          <div className="hero-viz__verdict-fill" style={{ width: "52%" }} />
          <div className="hero-viz__verdict-marker" style={{ left: "52%" }} />
        </div>
        <div className="hero-viz__verdict-imports">
          {imports.map((imp) => (
            <span key={imp} className="hero-viz__import">{imp}</span>
          ))}
        </div>
      </div>
    </div>
  );
}
