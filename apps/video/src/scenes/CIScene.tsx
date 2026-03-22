import { useCurrentFrame, interpolate, spring, useVideoConfig } from "remotion";

const ACCENT = "#5ffbbd";
const MUTED = "#7b93b0";
const TEXT = "#e4edf8";
const CARD = "rgba(10, 20, 36, 0.92)";
const WARNING = "#ffb040";

const packages = [
  { name: "bcrypt@6.0.0", risk: "MEDIUM", score: 52, binaries: 10, color: WARNING },
  { name: "argon2@0.44.0", risk: "MEDIUM", score: 51, binaries: 11, color: WARNING },
  { name: "sodium-native@5.1.0", risk: "MEDIUM", score: 42, binaries: 10, color: WARNING },
  { name: "bufferutil@4.0.9", risk: "MEDIUM", score: 38, binaries: 4, color: WARNING },
];

export const CIScene: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  /* Step pill */
  const pillSpring = spring({
    frame,
    fps,
    config: { damping: 14, stiffness: 120, mass: 0.5 },
    durationInFrames: 20,
  });

  /* Card entrance */
  const cardSpring = spring({
    frame: Math.max(0, frame - 6),
    fps,
    config: { damping: 16, stiffness: 100, mass: 0.7 },
    durationInFrames: 25,
  });

  /* Pass verdict */
  const passSpring = spring({
    frame: Math.max(0, frame - 60),
    fps,
    config: { damping: 10, stiffness: 160, mass: 0.5 },
    durationInFrames: 25,
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
          marginBottom: 24,
          opacity: pillSpring,
          transform: `scale(${pillSpring})`,
        }}
      >
        <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 12, fontWeight: 700, color: ACCENT, letterSpacing: "0.1em" }}>
          05
        </span>
        <span style={{ width: 1, height: 14, background: `${ACCENT}44` }} />
        <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 12, fontWeight: 600, color: ACCENT, letterSpacing: "0.1em", textTransform: "uppercase" }}>
          CI / PR Report
        </span>
      </div>

      {/* GitHub PR comment card */}
      <div
        style={{
          background: CARD,
          border: `1px solid ${ACCENT}1a`,
          borderRadius: 16,
          overflow: "hidden",
          opacity: cardSpring,
          transform: `translateY(${(1 - cardSpring) * 20}px)`,
          boxShadow: `0 8px 32px rgba(0,0,0,0.4), 0 0 0 1px ${ACCENT}0a inset`,
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
            background: "rgba(0,0,0,0.25)",
          }}
        >
          <svg width="20" height="20" viewBox="0 0 16 16" fill={`${MUTED}88`}>
            <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
          </svg>
          <span style={{ fontFamily: "Instrument Sans, sans-serif", fontSize: 16, fontWeight: 600, color: TEXT }}>
            BinShield -- Binary Dependency Scan
          </span>
          <span
            style={{
              marginLeft: "auto",
              fontFamily: "JetBrains Mono, monospace",
              fontSize: 11,
              padding: "4px 14px",
              borderRadius: 999,
              background: `${ACCENT}10`,
              border: `1px solid ${ACCENT}28`,
              color: ACCENT,
            }}
          >
            PR #247
          </span>
        </div>

        {/* Summary */}
        <div style={{ padding: "16px 24px", borderBottom: `1px solid ${ACCENT}0d` }}>
          <div style={{ fontFamily: "Instrument Sans, sans-serif", fontSize: 15, color: TEXT }}>
            <strong>35 native binaries found</strong> across 4 packages
          </div>
        </div>

        {/* Table header */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "2fr 1fr 0.8fr 0.8fr",
            gap: 12,
            padding: "10px 24px",
            fontFamily: "JetBrains Mono, monospace",
            fontSize: 11,
            color: `${MUTED}aa`,
            textTransform: "uppercase",
            letterSpacing: "0.1em",
            borderBottom: `1px solid ${ACCENT}0d`,
          }}
        >
          <span>Package</span>
          <span>Risk</span>
          <span>Score</span>
          <span>Binaries</span>
        </div>

        {/* Rows */}
        {packages.map((pkg, i) => {
          const rowSpring = spring({
            frame: Math.max(0, frame - 20 - i * 8),
            fps,
            config: { damping: 16, stiffness: 120, mass: 0.4 },
            durationInFrames: 18,
          });

          return (
            <div
              key={pkg.name}
              style={{
                display: "grid",
                gridTemplateColumns: "2fr 1fr 0.8fr 0.8fr",
                gap: 12,
                padding: "12px 24px",
                fontFamily: "JetBrains Mono, monospace",
                fontSize: 14,
                opacity: rowSpring,
                borderBottom: `1px solid ${ACCENT}08`,
              }}
            >
              <span style={{ color: TEXT }}>{pkg.name}</span>
              <span style={{ color: pkg.color, fontWeight: 700, fontSize: 12 }}>{pkg.risk}</span>
              <span style={{ color: pkg.color }}>{pkg.score}</span>
              <span style={{ color: MUTED }}>{pkg.binaries}</span>
            </div>
          );
        })}

        {/* Verdict */}
        <div
          style={{
            padding: "16px 24px",
            display: "flex",
            alignItems: "center",
            gap: 12,
            opacity: passSpring,
            transform: `scale(${0.95 + passSpring * 0.05})`,
          }}
        >
          <div
            style={{
              width: 28,
              height: 28,
              borderRadius: "50%",
              background: `${ACCENT}18`,
              border: `2px solid ${ACCENT}44`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              boxShadow: `0 0 12px ${ACCENT}22`,
            }}
          >
            <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
              <path d="M4 8l3 3 5-6" stroke={ACCENT} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </div>
          <span
            style={{
              fontFamily: "Instrument Sans, sans-serif",
              fontSize: 15,
              color: ACCENT,
              fontWeight: 600,
              textShadow: `0 0 12px ${ACCENT}22`,
            }}
          >
            All packages passed the HIGH threshold. Merge allowed.
          </span>
        </div>
      </div>
    </div>
  );
};
