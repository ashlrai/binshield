import { useCurrentFrame, interpolate, spring, useVideoConfig } from "remotion";

const ACCENT = "#5ffbbd";
const MUTED = "#7b93b0";
const TEXT = "#e4edf8";
const CARD = "rgba(10, 20, 36, 0.92)";
const WARNING = "#ffb040";
const DANGER = "#ff5c5c";

const behaviors = [
  { name: "Cryptographic operations", category: "CRYPTO", detected: true, color: ACCENT, detail: "Uses OpenSSL EVP routines for bcrypt hashing" },
  { name: "Filesystem access", category: "FILESYSTEM", detected: true, color: ACCENT, detail: "Reads /dev/urandom for entropy and salt generation" },
  { name: "Process spawning", category: "PROCESS", detected: true, color: WARNING, detail: "Spawns worker threads for parallel hashing" },
  { name: "Network activity", category: "NETWORK", detected: false, color: DANGER, detail: "No outbound network calls detected" },
  { name: "Code obfuscation", category: "OBFUSCATION", detected: false, color: DANGER, detail: "No packed or encoded regions found" },
  { name: "Data exfiltration", category: "EXFILTRATION", detected: false, color: DANGER, detail: "No telemetry or beacon patterns" },
];

export const ClassifyScene: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  /* Step pill */
  const pillSpring = spring({
    frame,
    fps,
    config: { damping: 14, stiffness: 120, mass: 0.5 },
    durationInFrames: 20,
  });

  /* Model label */
  const modelOpacity = spring({
    frame: Math.max(0, frame - 8),
    fps,
    config: { damping: 14, stiffness: 100, mass: 0.5 },
    durationInFrames: 20,
  });

  return (
    <div
      style={{
        position: "absolute",
        top: 120,
        left: 80,
        right: 80,
      }}
    >
      {/* Step pill */}
      <div
        style={{
          display: "inline-flex",
          alignItems: "center",
          gap: 8,
          padding: "6px 18px",
          borderRadius: 999,
          background: `${ACCENT}12`,
          border: `1px solid ${ACCENT}33`,
          marginBottom: 20,
          opacity: pillSpring,
          transform: `scale(${pillSpring})`,
        }}
      >
        <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 12, fontWeight: 700, color: ACCENT, letterSpacing: "0.1em" }}>
          03
        </span>
        <span style={{ width: 1, height: 14, background: `${ACCENT}44` }} />
        <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 12, fontWeight: 600, color: ACCENT, letterSpacing: "0.1em", textTransform: "uppercase" }}>
          AI Classification
        </span>
      </div>

      {/* Model label */}
      <div
        style={{
          fontFamily: "JetBrains Mono, monospace",
          fontSize: 13,
          color: MUTED,
          marginBottom: 20,
          opacity: modelOpacity,
          display: "flex",
          alignItems: "center",
          gap: 8,
        }}
      >
        <span style={{ color: `${ACCENT}88` }}>Model:</span> grok-4-1-fast-reasoning
        <span style={{ color: `${MUTED}66` }}>|</span>
        <span>Analyzing decompiled output...</span>
      </div>

      {/* Behavior rows */}
      <div style={{ display: "grid", gap: 8 }}>
        {behaviors.map((behavior, i) => {
          const rowSpring = spring({
            frame: Math.max(0, frame - 15 - i * 12),
            fps,
            config: { damping: 14, stiffness: 120, mass: 0.5 },
            durationInFrames: 22,
          });

          const indicatorSpring = spring({
            frame: Math.max(0, frame - 22 - i * 12),
            fps,
            config: { damping: 8, stiffness: 200, mass: 0.3 },
            durationInFrames: 18,
          });

          const borderColor = behavior.detected ? `${behavior.color}28` : `${ACCENT}0d`;
          const glowShadow = behavior.detected && behavior.color === WARNING
            ? `0 0 16px ${WARNING}11`
            : "none";

          return (
            <div
              key={behavior.name}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 16,
                padding: "14px 24px",
                background: CARD,
                border: `1px solid ${borderColor}`,
                borderRadius: 12,
                opacity: rowSpring,
                transform: `translateX(${(1 - rowSpring) * 24}px)`,
                boxShadow: glowShadow,
              }}
            >
              {/* Status indicator */}
              <div
                style={{
                  width: 34,
                  height: 34,
                  borderRadius: "50%",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  background: behavior.detected ? `${behavior.color}12` : `${MUTED}08`,
                  border: `2px solid ${behavior.detected ? behavior.color : `${MUTED}28`}`,
                  transform: `scale(${indicatorSpring})`,
                  boxShadow: behavior.detected ? `0 0 12px ${behavior.color}22` : "none",
                }}
              >
                {behavior.detected ? (
                  <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                    <path d="M4 8l3 3 5-6" stroke={behavior.color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                ) : (
                  <span style={{ color: `${MUTED}44`, fontSize: 14, fontWeight: 300 }}>--</span>
                )}
              </div>

              {/* Category badge */}
              <div
                style={{
                  padding: "4px 14px",
                  borderRadius: 999,
                  background: behavior.detected ? `${behavior.color}10` : `${MUTED}08`,
                  border: `1px solid ${behavior.detected ? `${behavior.color}28` : `${MUTED}18`}`,
                  fontFamily: "JetBrains Mono, monospace",
                  fontSize: 11,
                  fontWeight: 700,
                  letterSpacing: "0.08em",
                  color: behavior.detected ? behavior.color : `${MUTED}88`,
                  minWidth: 110,
                  textAlign: "center" as const,
                }}
              >
                {behavior.category}
              </div>

              {/* Details */}
              <div style={{ flex: 1 }}>
                <div
                  style={{
                    fontFamily: "Instrument Sans, sans-serif",
                    fontSize: 16,
                    color: behavior.detected ? TEXT : `${MUTED}66`,
                    fontWeight: 500,
                  }}
                >
                  {behavior.name}
                </div>
                <div
                  style={{
                    fontFamily: "JetBrains Mono, monospace",
                    fontSize: 12,
                    color: `${MUTED}aa`,
                    marginTop: 2,
                  }}
                >
                  {behavior.detail}
                </div>
              </div>

              {/* Status label */}
              <div
                style={{
                  fontFamily: "JetBrains Mono, monospace",
                  fontSize: 12,
                  fontWeight: 700,
                  color: behavior.detected ? behavior.color : `${MUTED}44`,
                  textShadow: behavior.detected ? `0 0 8px ${behavior.color}22` : "none",
                }}
              >
                {behavior.detected ? "DETECTED" : "CLEAR"}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
