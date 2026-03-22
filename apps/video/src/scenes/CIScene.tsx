import { useCurrentFrame, interpolate } from "remotion";

const ACCENT = "#5ffbbd";
const MUTED = "#7b93b0";
const TEXT = "#e4edf8";
const CARD = "rgba(10, 20, 36, 0.9)";
const WARNING = "#ffb040";

const packages = [
  { name: "bcrypt@6.0.0", risk: "MEDIUM", score: 52, binaries: 10, color: WARNING },
  { name: "argon2@0.44.0", risk: "MEDIUM", score: 51, binaries: 11, color: WARNING },
  { name: "sodium-native@5.1.0", risk: "MEDIUM", score: 42, binaries: 10, color: WARNING },
  { name: "bufferutil@4.0.9", risk: "MEDIUM", score: 38, binaries: 4, color: WARNING },
];

export const CIScene: React.FC = () => {
  const frame = useCurrentFrame();

  const labelOpacity = interpolate(frame, [0, 15], [0, 1], { extrapolateRight: "clamp" });
  const cardOpacity = interpolate(frame, [10, 30], [0, 1], { extrapolateRight: "clamp" });
  const cardY = interpolate(frame, [10, 30], [20, 0], { extrapolateRight: "clamp" });

  const passOpacity = interpolate(frame, [100, 120], [0, 1], { extrapolateRight: "clamp" });

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
        05 — CI / PR REPORT
      </div>

      {/* GitHub PR comment mockup */}
      <div
        style={{
          background: CARD,
          border: `1px solid ${ACCENT}1a`,
          borderRadius: 16,
          overflow: "hidden",
          opacity: cardOpacity,
          transform: `translateY(${cardY}px)`,
        }}
      >
        {/* PR header */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 12,
            padding: "16px 24px",
            borderBottom: `1px solid ${ACCENT}0d`,
            background: "rgba(0,0,0,0.2)",
          }}
        >
          <svg width="20" height="20" viewBox="0 0 16 16" fill={ACCENT}>
            <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
          </svg>
          <span style={{ fontFamily: "Instrument Sans", fontSize: 16, fontWeight: 600, color: TEXT }}>
            BinShield — Binary Dependency Scan
          </span>
          <span
            style={{
              marginLeft: "auto",
              fontFamily: "JetBrains Mono",
              fontSize: 12,
              padding: "4px 12px",
              borderRadius: 999,
              background: `${ACCENT}15`,
              border: `1px solid ${ACCENT}33`,
              color: ACCENT,
            }}
          >
            PR #247
          </span>
        </div>

        {/* Summary */}
        <div style={{ padding: "20px 24px", borderBottom: `1px solid ${ACCENT}0d` }}>
          <div style={{ fontFamily: "Instrument Sans", fontSize: 15, color: TEXT }}>
            <strong>35 native binaries found</strong> across 4 packages
          </div>
        </div>

        {/* Table */}
        <div>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "2fr 1fr 0.8fr 0.8fr",
              gap: 12,
              padding: "10px 24px",
              fontFamily: "JetBrains Mono",
              fontSize: 11,
              color: MUTED,
              textTransform: "uppercase",
              letterSpacing: "0.08em",
              borderBottom: `1px solid ${ACCENT}0d`,
            }}
          >
            <span>Package</span>
            <span>Risk</span>
            <span>Score</span>
            <span>Binaries</span>
          </div>

          {packages.map((pkg, i) => {
            const rowDelay = 40 + i * 15;
            const rowOpacity = interpolate(frame, [rowDelay, rowDelay + 12], [0, 1], {
              extrapolateLeft: "clamp",
              extrapolateRight: "clamp",
            });

            return (
              <div
                key={pkg.name}
                style={{
                  display: "grid",
                  gridTemplateColumns: "2fr 1fr 0.8fr 0.8fr",
                  gap: 12,
                  padding: "12px 24px",
                  fontFamily: "JetBrains Mono",
                  fontSize: 14,
                  opacity: rowOpacity,
                  borderBottom: `1px solid ${ACCENT}08`,
                }}
              >
                <span style={{ color: TEXT }}>{pkg.name}</span>
                <span
                  style={{
                    color: pkg.color,
                    fontWeight: 700,
                    fontSize: 12,
                  }}
                >
                  {pkg.risk}
                </span>
                <span style={{ color: pkg.color }}>{pkg.score}</span>
                <span style={{ color: MUTED }}>{pkg.binaries}</span>
              </div>
            );
          })}
        </div>

        {/* Verdict */}
        <div
          style={{
            padding: "16px 24px",
            display: "flex",
            alignItems: "center",
            gap: 12,
            opacity: passOpacity,
          }}
        >
          <div
            style={{
              width: 28,
              height: 28,
              borderRadius: "50%",
              background: `${ACCENT}20`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <span style={{ color: ACCENT, fontSize: 16 }}>✓</span>
          </div>
          <span style={{ fontFamily: "Instrument Sans", fontSize: 15, color: ACCENT, fontWeight: 600 }}>
            All packages passed the HIGH threshold. Merge allowed.
          </span>
        </div>
      </div>
    </div>
  );
};
