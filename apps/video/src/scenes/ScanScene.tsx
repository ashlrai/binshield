import { useCurrentFrame, interpolate, spring, useVideoConfig } from "remotion";

const BG = "#050d18";
const ACCENT = "#5ffbbd";
const MUTED = "#7b93b0";
const TEXT = "#e4edf8";
const CARD = "rgba(10, 20, 36, 0.9)";

export const ScanScene: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const cardOpacity = interpolate(frame, [0, 20], [0, 1], { extrapolateRight: "clamp" });
  const cardY = interpolate(frame, [0, 20], [30, 0], { extrapolateRight: "clamp" });

  const commandChars = Math.min(Math.floor(frame / 2), 28);
  const command = "binshield scan bcrypt@6.0.0".slice(0, commandChars);
  const showCursor = frame % 16 < 10;

  const progressWidth = interpolate(frame, [60, 150], [0, 100], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const progressOpacity = interpolate(frame, [55, 65], [0, 1], { extrapolateRight: "clamp" });

  const labelOpacity = interpolate(frame, [60, 70], [0, 1], { extrapolateRight: "clamp" });

  return (
    <div
      style={{
        position: "absolute",
        top: 140,
        left: 60,
        right: 60,
        opacity: cardOpacity,
        transform: `translateY(${cardY}px)`,
      }}
    >
      {/* Section label */}
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
        01 — SCAN PACKAGE
      </div>

      {/* Terminal card */}
      <div
        style={{
          background: CARD,
          border: `1px solid ${ACCENT}1a`,
          borderRadius: 16,
          overflow: "hidden",
        }}
      >
        {/* Terminal header */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            padding: "12px 20px",
            background: "rgba(0,0,0,0.3)",
            borderBottom: `1px solid ${ACCENT}1a`,
          }}
        >
          <div style={{ width: 12, height: 12, borderRadius: "50%", background: "#ff5c5c" }} />
          <div style={{ width: 12, height: 12, borderRadius: "50%", background: "#f0c040" }} />
          <div style={{ width: 12, height: 12, borderRadius: "50%", background: ACCENT }} />
          <span style={{ marginLeft: 12, fontFamily: "JetBrains Mono", fontSize: 13, color: MUTED }}>
            binshield — terminal
          </span>
        </div>

        {/* Command */}
        <div style={{ padding: "24px 28px", fontFamily: "JetBrains Mono", fontSize: 22 }}>
          <span style={{ color: MUTED, opacity: 0.5 }}>$ </span>
          <span style={{ color: ACCENT }}>{command}</span>
          {commandChars < 28 && showCursor && (
            <span style={{ color: ACCENT, opacity: 0.8 }}>▊</span>
          )}
        </div>

        {/* Progress bar */}
        <div style={{ padding: "0 28px 24px", opacity: progressOpacity }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
            <span style={{ fontFamily: "JetBrains Mono", fontSize: 13, color: MUTED }}>
              {progressWidth >= 100 ? "✓ Analysis complete" : `Downloading and extracting...`}
            </span>
            <span style={{ fontFamily: "JetBrains Mono", fontSize: 13, color: ACCENT }}>
              {Math.round(progressWidth)}%
            </span>
          </div>
          <div style={{ height: 4, borderRadius: 2, background: `${ACCENT}1a` }}>
            <div
              style={{
                height: "100%",
                borderRadius: 2,
                width: `${progressWidth}%`,
                background: `linear-gradient(90deg, ${ACCENT}, #f0c040)`,
                transition: "width 0.1s",
              }}
            />
          </div>
        </div>
      </div>
    </div>
  );
};
