import { useCurrentFrame, interpolate } from "remotion";

const ACCENT = "#5ffbbd";
const MUTED = "#7b93b0";
const TEXT = "#e4edf8";
const CARD = "rgba(10, 20, 36, 0.9)";
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

  const labelOpacity = interpolate(frame, [0, 15], [0, 1], { extrapolateRight: "clamp" });
  const cardOpacity = interpolate(frame, [10, 30], [0, 1], { extrapolateRight: "clamp" });
  const cardY = interpolate(frame, [10, 30], [20, 0], { extrapolateRight: "clamp" });

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
        02 — BINARY ARTIFACTS DISCOVERED
      </div>

      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 16,
          marginBottom: 20,
          opacity: cardOpacity,
        }}
      >
        <div
          style={{
            fontFamily: "JetBrains Mono",
            fontSize: 48,
            fontWeight: 800,
            color: WARNING,
          }}
        >
          10
        </div>
        <div>
          <div style={{ fontFamily: "Instrument Sans", fontSize: 18, color: TEXT }}>
            native binaries extracted
          </div>
          <div style={{ fontFamily: "JetBrains Mono", fontSize: 13, color: MUTED }}>
            from bcrypt@6.0.0 package tree
          </div>
        </div>
      </div>

      <div
        style={{
          background: CARD,
          border: `1px solid ${ACCENT}1a`,
          borderRadius: 16,
          padding: 4,
          opacity: cardOpacity,
          transform: `translateY(${cardY}px)`,
        }}
      >
        {/* Table header */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "2fr 1.2fr 0.8fr 0.8fr 1.2fr",
            gap: 12,
            padding: "12px 20px",
            fontFamily: "JetBrains Mono",
            fontSize: 11,
            color: MUTED,
            textTransform: "uppercase",
            letterSpacing: "0.1em",
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
          const rowDelay = 30 + i * 12;
          const rowOpacity = interpolate(frame, [rowDelay, rowDelay + 10], [0, 1], {
            extrapolateLeft: "clamp",
            extrapolateRight: "clamp",
          });
          const rowX = interpolate(frame, [rowDelay, rowDelay + 10], [20, 0], {
            extrapolateLeft: "clamp",
            extrapolateRight: "clamp",
          });

          return (
            <div
              key={i}
              style={{
                display: "grid",
                gridTemplateColumns: "2fr 1.2fr 0.8fr 0.8fr 1.2fr",
                gap: 12,
                padding: "10px 20px",
                fontFamily: "JetBrains Mono",
                fontSize: 14,
                opacity: rowOpacity,
                transform: `translateX(${rowX}px)`,
                borderBottom: i < binaries.length - 1 ? `1px solid ${ACCENT}08` : "none",
              }}
            >
              <span style={{ color: TEXT }}>{bin.name}</span>
              <span style={{ color: ACCENT }}>{bin.arch}</span>
              <span style={{ color: MUTED }}>{bin.format}</span>
              <span style={{ color: MUTED }}>{bin.size}</span>
              <span style={{ color: `${MUTED}88` }}>{bin.sha}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
};
