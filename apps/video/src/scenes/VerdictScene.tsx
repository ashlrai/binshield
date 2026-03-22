import { useCurrentFrame, interpolate, spring, useVideoConfig } from "remotion";

const ACCENT = "#5ffbbd";
const MUTED = "#7b93b0";
const TEXT = "#e4edf8";
const CARD = "rgba(10, 20, 36, 0.9)";
const WARNING = "#ffb040";

export const VerdictScene: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const labelOpacity = interpolate(frame, [0, 15], [0, 1], { extrapolateRight: "clamp" });
  const cardOpacity = interpolate(frame, [10, 30], [0, 1], { extrapolateRight: "clamp" });

  const scoreValue = interpolate(frame, [30, 90], [0, 52], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const barWidth = interpolate(frame, [30, 90], [0, 52], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

  const summaryOpacity = interpolate(frame, [80, 100], [0, 1], { extrapolateRight: "clamp" });

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
        04 — RISK VERDICT
      </div>

      <div
        style={{
          background: CARD,
          border: `1px solid ${WARNING}33`,
          borderRadius: 20,
          padding: 48,
          opacity: cardOpacity,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          gap: 32,
        }}
      >
        {/* Giant score */}
        <div style={{ textAlign: "center" }}>
          <div
            style={{
              fontFamily: "JetBrains Mono",
              fontSize: 120,
              fontWeight: 800,
              color: WARNING,
              lineHeight: 1,
            }}
          >
            {Math.round(scoreValue)}
          </div>
          <div
            style={{
              fontFamily: "JetBrains Mono",
              fontSize: 24,
              fontWeight: 700,
              color: WARNING,
              letterSpacing: "0.12em",
              marginTop: 8,
            }}
          >
            MEDIUM RISK
          </div>
        </div>

        {/* Risk bar */}
        <div style={{ width: "100%", maxWidth: 700 }}>
          <div
            style={{
              height: 8,
              borderRadius: 4,
              background: `linear-gradient(90deg, ${ACCENT}44 0%, ${WARNING}44 50%, #ff5c5c44 100%)`,
              position: "relative",
            }}
          >
            <div
              style={{
                height: "100%",
                borderRadius: 4,
                width: `${barWidth}%`,
                background: `linear-gradient(90deg, ${ACCENT}, ${WARNING})`,
              }}
            />
            <div
              style={{
                position: "absolute",
                top: -6,
                left: `${barWidth}%`,
                width: 4,
                height: 20,
                borderRadius: 2,
                background: TEXT,
                transform: "translateX(-50%)",
              }}
            />
          </div>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              marginTop: 8,
              fontFamily: "JetBrains Mono",
              fontSize: 11,
              color: MUTED,
            }}
          >
            <span>NONE (0)</span>
            <span>LOW (30)</span>
            <span>MEDIUM (60)</span>
            <span>HIGH (80)</span>
            <span>CRITICAL (100)</span>
          </div>
        </div>

        {/* Summary */}
        <div
          style={{
            opacity: summaryOpacity,
            textAlign: "center",
            maxWidth: 600,
          }}
        >
          <div style={{ fontFamily: "Instrument Sans", fontSize: 18, color: TEXT, lineHeight: 1.5 }}>
            bcrypt@6.0.0 exposes expected cryptographic and filesystem behaviors.
            Process spawning detected for parallel hashing. No network or exfiltration indicators.
          </div>
          <div
            style={{
              fontFamily: "JetBrains Mono",
              fontSize: 13,
              color: MUTED,
              marginTop: 12,
            }}
          >
            Classified by grok-4-1-fast-reasoning in 4.2s
          </div>
        </div>
      </div>
    </div>
  );
};
