import { useCurrentFrame, interpolate, spring, useVideoConfig } from "remotion";

const ACCENT = "#5ffbbd";
const MUTED = "#7b93b0";
const TEXT = "#e4edf8";
const CARD = "rgba(10, 20, 36, 0.92)";

export const ScanScene: React.FC = () => {
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

  /* Typing animation */
  const commandChars = Math.min(Math.floor((frame - 10) / 1.5), 28);
  const command = "binshield scan bcrypt@6.0.0".slice(0, Math.max(0, commandChars));
  const showCursor = frame % 16 < 10;
  const doneTyping = commandChars >= 28;

  /* Progress bar */
  const progressStart = 55;
  const progressWidth = interpolate(frame, [progressStart, 100], [0, 100], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const progressOpacity = interpolate(frame, [progressStart - 5, progressStart + 5], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  /* Checkmark bounce when complete */
  const checkSpring = spring({
    frame: Math.max(0, frame - 100),
    fps,
    config: { damping: 8, stiffness: 200, mass: 0.4 },
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
          marginBottom: 24,
          opacity: pillSpring,
          transform: `scale(${pillSpring})`,
        }}
      >
        <span
          style={{
            fontFamily: "JetBrains Mono, monospace",
            fontSize: 12,
            fontWeight: 700,
            color: ACCENT,
            letterSpacing: "0.1em",
          }}
        >
          01
        </span>
        <span
          style={{
            width: 1,
            height: 14,
            background: `${ACCENT}44`,
          }}
        />
        <span
          style={{
            fontFamily: "JetBrains Mono, monospace",
            fontSize: 12,
            fontWeight: 600,
            color: ACCENT,
            letterSpacing: "0.1em",
            textTransform: "uppercase",
          }}
        >
          Scan Package
        </span>
      </div>

      {/* Terminal card */}
      <div
        style={{
          background: CARD,
          border: `1px solid ${ACCENT}1a`,
          borderRadius: 16,
          overflow: "hidden",
          opacity: cardSpring,
          transform: `translateY(${(1 - cardSpring) * 24}px)`,
          boxShadow: `0 8px 32px rgba(0,0,0,0.4), 0 0 0 1px ${ACCENT}0a inset`,
        }}
      >
        {/* Terminal header */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            padding: "14px 20px",
            background: "rgba(0,0,0,0.35)",
            borderBottom: `1px solid ${ACCENT}12`,
          }}
        >
          <div style={{ width: 12, height: 12, borderRadius: "50%", background: "#ff5c5c" }} />
          <div style={{ width: 12, height: 12, borderRadius: "50%", background: "#ffb040" }} />
          <div style={{ width: 12, height: 12, borderRadius: "50%", background: ACCENT }} />
          <span
            style={{
              marginLeft: 16,
              fontFamily: "JetBrains Mono, monospace",
              fontSize: 13,
              color: `${MUTED}88`,
            }}
          >
            binshield -- terminal
          </span>
        </div>

        {/* Command line */}
        <div style={{ padding: "28px 32px 16px", fontFamily: "JetBrains Mono, monospace", fontSize: 22 }}>
          <span style={{ color: MUTED, opacity: 0.4 }}>$ </span>
          <span style={{ color: ACCENT }}>{command}</span>
          {!doneTyping && showCursor && (
            <span
              style={{
                color: ACCENT,
                opacity: 0.8,
                textShadow: `0 0 8px ${ACCENT}66`,
              }}
            >
              |
            </span>
          )}
        </div>

        {/* Progress bar */}
        <div style={{ padding: "8px 32px 28px", opacity: progressOpacity }}>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              marginBottom: 10,
            }}
          >
            <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 13, color: MUTED }}>
              {progressWidth >= 100 ? (
                <span style={{ transform: `scale(${checkSpring})`, display: "inline-block" }}>
                  <span style={{ color: ACCENT }}>Done</span> -- Analysis complete
                </span>
              ) : (
                "Downloading and extracting..."
              )}
            </span>
            <span
              style={{
                fontFamily: "JetBrains Mono, monospace",
                fontSize: 13,
                color: ACCENT,
                textShadow: progressWidth >= 100 ? `0 0 8px ${ACCENT}44` : "none",
              }}
            >
              {Math.round(progressWidth)}%
            </span>
          </div>
          <div
            style={{
              height: 4,
              borderRadius: 2,
              background: `${ACCENT}15`,
              overflow: "hidden",
            }}
          >
            <div
              style={{
                height: "100%",
                borderRadius: 2,
                width: `${progressWidth}%`,
                background: `linear-gradient(90deg, ${ACCENT}, #ffb040)`,
                boxShadow: progressWidth >= 100 ? `0 0 12px ${ACCENT}44` : "none",
              }}
            />
          </div>
        </div>
      </div>
    </div>
  );
};
