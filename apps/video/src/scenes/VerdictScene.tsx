import { useCurrentFrame, interpolate, spring, useVideoConfig } from "remotion";

const ACCENT = "#5ffbbd";
const MUTED = "#7b93b0";
const TEXT = "#e4edf8";
const CARD = "rgba(10, 20, 36, 0.92)";
const WARNING = "#ffb040";

export const VerdictScene: React.FC = () => {
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
    frame: Math.max(0, frame - 8),
    fps,
    config: { damping: 16, stiffness: 100, mass: 0.7 },
    durationInFrames: 25,
  });

  /* Score animation: linear count up then spring overshoot at end */
  const rawScore = interpolate(frame, [20, 60], [0, 52], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  // Spring bounce that kicks in near the target
  const bounceSpring = spring({
    frame: Math.max(0, frame - 58),
    fps,
    config: { damping: 6, stiffness: 180, mass: 0.5 },
    durationInFrames: 30,
  });

  // The score overshoots to 58 then settles at 52
  const scoreValue = frame < 58
    ? rawScore
    : 52 + (1 - bounceSpring) * 6;

  /* Bar width tracks score */
  const barWidth = scoreValue;

  /* Summary fade */
  const summarySpring = spring({
    frame: Math.max(0, frame - 70),
    fps,
    config: { damping: 14, stiffness: 100, mass: 0.6 },
    durationInFrames: 25,
  });

  /* Score glow pulse */
  const glowPulse = frame > 58
    ? 0.3 + Math.sin((frame - 58) * 0.15) * 0.15
    : 0;

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
          04
        </span>
        <span style={{ width: 1, height: 14, background: `${ACCENT}44` }} />
        <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 12, fontWeight: 600, color: ACCENT, letterSpacing: "0.1em", textTransform: "uppercase" }}>
          Risk Verdict
        </span>
      </div>

      {/* Verdict card */}
      <div
        style={{
          background: CARD,
          border: `1px solid ${WARNING}28`,
          borderRadius: 20,
          padding: "48px 48px 40px",
          opacity: cardSpring,
          transform: `translateY(${(1 - cardSpring) * 20}px)`,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          gap: 32,
          boxShadow: `0 8px 32px rgba(0,0,0,0.4), 0 0 60px ${WARNING}08`,
        }}
      >
        {/* Giant score */}
        <div style={{ textAlign: "center" }}>
          <div
            style={{
              fontFamily: "JetBrains Mono, monospace",
              fontSize: 120,
              fontWeight: 800,
              color: WARNING,
              lineHeight: 1,
              textShadow: `0 0 ${40 * glowPulse}px ${WARNING}${Math.round(glowPulse * 80).toString(16).padStart(2, "0")}`,
            }}
          >
            {Math.round(scoreValue)}
          </div>
          <div
            style={{
              fontFamily: "JetBrains Mono, monospace",
              fontSize: 22,
              fontWeight: 700,
              color: WARNING,
              letterSpacing: "0.14em",
              marginTop: 8,
              opacity: frame > 45 ? 1 : 0,
            }}
          >
            MEDIUM RISK
          </div>
        </div>

        {/* Risk bar */}
        <div style={{ width: "100%", maxWidth: 700 }}>
          <div
            style={{
              height: 6,
              borderRadius: 3,
              background: `linear-gradient(90deg, ${ACCENT}22 0%, ${WARNING}22 50%, #ff5c5c22 100%)`,
              position: "relative",
              overflow: "visible",
            }}
          >
            <div
              style={{
                height: "100%",
                borderRadius: 3,
                width: `${barWidth}%`,
                background: `linear-gradient(90deg, ${ACCENT}, ${WARNING})`,
                boxShadow: `0 0 12px ${WARNING}33`,
              }}
            />
            {/* Needle */}
            <div
              style={{
                position: "absolute",
                top: -8,
                left: `${barWidth}%`,
                width: 3,
                height: 22,
                borderRadius: 2,
                background: TEXT,
                transform: "translateX(-50%)",
                boxShadow: `0 0 6px ${TEXT}44`,
              }}
            />
          </div>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              marginTop: 10,
              fontFamily: "JetBrains Mono, monospace",
              fontSize: 10,
              color: `${MUTED}88`,
              letterSpacing: "0.04em",
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
            opacity: summarySpring,
            transform: `translateY(${(1 - summarySpring) * 12}px)`,
            textAlign: "center",
            maxWidth: 640,
          }}
        >
          <div
            style={{
              fontFamily: "Instrument Sans, sans-serif",
              fontSize: 17,
              color: `${TEXT}cc`,
              lineHeight: 1.6,
            }}
          >
            bcrypt@6.0.0 exposes expected cryptographic and filesystem behaviors.
            Process spawning detected for parallel hashing. No network or exfiltration indicators.
          </div>
          <div
            style={{
              fontFamily: "JetBrains Mono, monospace",
              fontSize: 12,
              color: `${MUTED}88`,
              marginTop: 14,
            }}
          >
            Classified by grok-4-1-fast-reasoning in 4.2s
          </div>
        </div>
      </div>
    </div>
  );
};
