import { useCurrentFrame, interpolate } from "remotion";

const ACCENT = "#5ffbbd";
const MUTED = "#7b93b0";
const TEXT = "#e4edf8";
const CARD = "rgba(10, 20, 36, 0.9)";
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

  const labelOpacity = interpolate(frame, [0, 15], [0, 1], { extrapolateRight: "clamp" });

  return (
    <div
      style={{
        position: "absolute",
        top: 140,
        left: 60,
        right: 60,
      }}
    >
      <div
        style={{
          fontFamily: "JetBrains Mono, monospace",
          fontSize: 14,
          color: ACCENT,
          letterSpacing: "0.14em",
          textTransform: "uppercase",
          marginBottom: 16,
          opacity: labelOpacity,
        }}
      >
        03 — AI BEHAVIOR CLASSIFICATION
      </div>

      <div
        style={{
          fontFamily: "JetBrains Mono",
          fontSize: 13,
          color: MUTED,
          marginBottom: 20,
          opacity: labelOpacity,
        }}
      >
        Model: grok-4-1-fast-reasoning • Analyzing decompiled output...
      </div>

      <div style={{ display: "grid", gap: 8 }}>
        {behaviors.map((behavior, i) => {
          const rowDelay = 20 + i * 20;
          const rowOpacity = interpolate(frame, [rowDelay, rowDelay + 15], [0, 1], {
            extrapolateLeft: "clamp",
            extrapolateRight: "clamp",
          });
          const rowX = interpolate(frame, [rowDelay, rowDelay + 15], [30, 0], {
            extrapolateLeft: "clamp",
            extrapolateRight: "clamp",
          });

          const dotScale = interpolate(frame, [rowDelay + 10, rowDelay + 18], [0, 1], {
            extrapolateLeft: "clamp",
            extrapolateRight: "clamp",
          });

          return (
            <div
              key={behavior.name}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 16,
                padding: "16px 24px",
                background: CARD,
                border: `1px solid ${behavior.detected ? behavior.color + "33" : ACCENT + "0d"}`,
                borderRadius: 12,
                opacity: rowOpacity,
                transform: `translateX(${rowX}px)`,
              }}
            >
              {/* Status indicator */}
              <div
                style={{
                  width: 36,
                  height: 36,
                  borderRadius: "50%",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  background: behavior.detected ? `${behavior.color}15` : `${MUTED}10`,
                  border: `2px solid ${behavior.detected ? behavior.color : MUTED + "33"}`,
                  transform: `scale(${dotScale})`,
                }}
              >
                {behavior.detected ? (
                  <span style={{ color: behavior.color, fontSize: 18 }}>✓</span>
                ) : (
                  <span style={{ color: MUTED, fontSize: 14, opacity: 0.5 }}>—</span>
                )}
              </div>

              {/* Category badge */}
              <div
                style={{
                  padding: "4px 12px",
                  borderRadius: 999,
                  background: behavior.detected ? `${behavior.color}15` : `${MUTED}10`,
                  border: `1px solid ${behavior.detected ? behavior.color + "33" : MUTED + "22"}`,
                  fontFamily: "JetBrains Mono",
                  fontSize: 11,
                  fontWeight: 700,
                  letterSpacing: "0.08em",
                  color: behavior.detected ? behavior.color : MUTED,
                  minWidth: 110,
                  textAlign: "center",
                }}
              >
                {behavior.category}
              </div>

              {/* Details */}
              <div style={{ flex: 1 }}>
                <div style={{ fontFamily: "Instrument Sans", fontSize: 16, color: behavior.detected ? TEXT : `${MUTED}88` }}>
                  {behavior.name}
                </div>
                <div style={{ fontFamily: "JetBrains Mono", fontSize: 12, color: MUTED, marginTop: 2 }}>
                  {behavior.detail}
                </div>
              </div>

              {/* Status label */}
              <div
                style={{
                  fontFamily: "JetBrains Mono",
                  fontSize: 12,
                  fontWeight: 700,
                  color: behavior.detected ? behavior.color : `${MUTED}66`,
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
