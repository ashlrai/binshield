import { useCurrentFrame, interpolate, spring, useVideoConfig } from "remotion";

const ACCENT = "#5ffbbd";
const MUTED = "#7b93b0";
const TEXT = "#e4edf8";
const CARD = "rgba(10, 20, 36, 0.92)";
const WARNING = "#ffb040";

const binaries = [
  { name: "bcrypt_lib.node", arch: "linux-x64", format: "ELF", size: "194 KB", sha: "a7f3c2..d91e" },
  { name: "bcrypt_lib.node", arch: "linux-arm64", format: "ELF", size: "201 KB", sha: "b8e4d1..f2a0" },
  { name: "bcrypt_lib.node", arch: "darwin-x64", format: "Mach-O", size: "178 KB", sha: "c9d5e2..03b1" },
  { name: "bcrypt_lib.node", arch: "darwin-arm64", format: "Mach-O", size: "182 KB", sha: "d0e6f3..14c2" },
  { name: "bcrypt_lib.node", arch: "win32-x64", format: "PE", size: "256 KB", sha: "e1f704..25d3" },
  { name: "napi.node", arch: "linux-x64", format: "ELF", size: "89 KB", sha: "f2g815..36e4" },
];

export const BinaryScene: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  /* Step pill */
  const pillSpring = spring({
    frame,
    fps,
    config: { damping: 14, stiffness: 120, mass: 0.5 },
    durationInFrames: 20,
  });

  /* Counter spring animation */
  const countSpring = spring({
    frame: Math.max(0, frame - 10),
    fps,
    config: { damping: 10, stiffness: 150, mass: 0.6 },
    durationInFrames: 30,
  });

  const countValue = Math.round(countSpring * 10);

  /* Card entrance */
  const cardSpring = spring({
    frame: Math.max(0, frame - 15),
    fps,
    config: { damping: 16, stiffness: 100, mass: 0.7 },
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
          02
        </span>
        <span style={{ width: 1, height: 14, background: `${ACCENT}44` }} />
        <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 12, fontWeight: 600, color: ACCENT, letterSpacing: "0.1em", textTransform: "uppercase" }}>
          Binary Artifacts
        </span>
      </div>

      {/* Count + label */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 20,
          marginBottom: 24,
          opacity: countSpring,
        }}
      >
        <div
          style={{
            fontFamily: "JetBrains Mono, monospace",
            fontSize: 56,
            fontWeight: 800,
            color: WARNING,
            lineHeight: 1,
            textShadow: `0 0 24px ${WARNING}33`,
            transform: `scale(${0.8 + countSpring * 0.2})`,
          }}
        >
          {countValue}
        </div>
        <div>
          <div style={{ fontFamily: "Instrument Sans, sans-serif", fontSize: 20, color: TEXT, fontWeight: 500 }}>
            native binaries extracted
          </div>
          <div style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 13, color: MUTED, marginTop: 2 }}>
            from bcrypt@6.0.0 package tree
          </div>
        </div>
      </div>

      {/* Table card */}
      <div
        style={{
          background: CARD,
          border: `1px solid ${ACCENT}1a`,
          borderRadius: 16,
          padding: 4,
          opacity: cardSpring,
          transform: `translateY(${(1 - cardSpring) * 20}px)`,
          boxShadow: `0 8px 32px rgba(0,0,0,0.4), 0 0 0 1px ${ACCENT}0a inset`,
        }}
      >
        {/* Table header */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "2fr 1.2fr 0.8fr 0.8fr 1.2fr",
            gap: 12,
            padding: "14px 24px",
            fontFamily: "JetBrains Mono, monospace",
            fontSize: 11,
            color: `${MUTED}aa`,
            textTransform: "uppercase",
            letterSpacing: "0.12em",
            borderBottom: `1px solid ${ACCENT}0d`,
          }}
        >
          <span>Filename</span>
          <span>Platform</span>
          <span>Format</span>
          <span>Size</span>
          <span>SHA-256</span>
        </div>

        {/* Rows */}
        {binaries.map((bin, i) => {
          const rowSpring = spring({
            frame: Math.max(0, frame - 30 - i * 8),
            fps,
            config: { damping: 18, stiffness: 120, mass: 0.4 },
            durationInFrames: 20,
          });

          return (
            <div
              key={`${bin.name}-${bin.arch}`}
              style={{
                display: "grid",
                gridTemplateColumns: "2fr 1.2fr 0.8fr 0.8fr 1.2fr",
                gap: 12,
                padding: "11px 24px",
                fontFamily: "JetBrains Mono, monospace",
                fontSize: 14,
                opacity: rowSpring,
                transform: `translateX(${(1 - rowSpring) * 16}px)`,
                borderBottom: i < binaries.length - 1 ? `1px solid ${ACCENT}08` : "none",
              }}
            >
              <span style={{ color: TEXT }}>{bin.name}</span>
              <span style={{ color: ACCENT }}>{bin.arch}</span>
              <span style={{ color: MUTED }}>{bin.format}</span>
              <span style={{ color: MUTED }}>{bin.size}</span>
              <span style={{ color: `${MUTED}66` }}>{bin.sha}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
};
