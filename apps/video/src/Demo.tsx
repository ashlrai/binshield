import { AbsoluteFill, Sequence, useCurrentFrame, interpolate, spring, useVideoConfig } from "remotion";
import { ScanScene } from "./scenes/ScanScene";
import { BinaryScene } from "./scenes/BinaryScene";
import { ClassifyScene } from "./scenes/ClassifyScene";
import { VerdictScene } from "./scenes/VerdictScene";
import { CIScene } from "./scenes/CIScene";

const BG = "#050d18";
const ACCENT = "#5ffbbd";
const MUTED = "#7b93b0";
const TEXT = "#e4edf8";

function GridDots() {
  return (
    <div
      style={{
        position: "absolute",
        inset: 0,
        opacity: 0.2,
        backgroundImage: `radial-gradient(circle, ${ACCENT}33 1.5px, transparent 1.5px)`,
        backgroundSize: "40px 40px",
        maskImage: "linear-gradient(180deg, rgba(0,0,0,0.5) 0%, transparent 50%)",
        WebkitMaskImage: "linear-gradient(180deg, rgba(0,0,0,0.5) 0%, transparent 50%)",
      }}
    />
  );
}

function ScanLine({ frame }: { frame: number }) {
  const y = (frame * 3) % 1080;
  return (
    <div
      style={{
        position: "absolute",
        left: 0,
        right: 0,
        top: y,
        height: 2,
        background: `linear-gradient(90deg, transparent, ${ACCENT}22, transparent)`,
      }}
    />
  );
}

function Logo({ opacity }: { opacity: number }) {
  return (
    <div
      style={{
        position: "absolute",
        top: 40,
        left: 60,
        display: "flex",
        alignItems: "center",
        gap: 14,
        opacity,
        fontFamily: "JetBrains Mono, monospace",
        fontSize: 24,
        fontWeight: 800,
        color: TEXT,
        letterSpacing: "0.04em",
      }}
    >
      <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
        <rect x="2" y="2" width="28" height="28" rx="5" stroke={ACCENT} strokeWidth="1.5" />
        <rect x="7" y="7" width="7" height="5" rx="1.5" fill={ACCENT} opacity="0.5" />
        <rect x="18" y="7" width="7" height="5" rx="1.5" fill={ACCENT} opacity="0.5" />
        <rect x="7" y="15" width="7" height="5" rx="1.5" fill={ACCENT} opacity="0.5" />
        <rect x="18" y="15" width="7" height="5" rx="1.5" fill={ACCENT} opacity="0.5" />
        <circle cx="16" cy="16" r="4" fill={ACCENT} />
      </svg>
      BINSHIELD
    </div>
  );
}

function Tagline({ frame }: { frame: number }) {
  const opacity = interpolate(frame, [810, 840], [0, 1], { extrapolateRight: "clamp" });
  const y = interpolate(frame, [810, 840], [20, 0], { extrapolateRight: "clamp" });

  return (
    <div
      style={{
        position: "absolute",
        bottom: 60,
        left: 0,
        right: 0,
        textAlign: "center",
        opacity,
        transform: `translateY(${y}px)`,
      }}
    >
      <div
        style={{
          fontFamily: "JetBrains Mono, monospace",
          fontSize: 20,
          color: ACCENT,
          letterSpacing: "0.12em",
          textTransform: "uppercase",
          marginBottom: 8,
        }}
      >
        binshield.dev
      </div>
      <div
        style={{
          fontFamily: "Instrument Sans, sans-serif",
          fontSize: 16,
          color: MUTED,
        }}
      >
        Binary supply-chain security for the dependencies everyone else ignores.
      </div>
    </div>
  );
}

export const BinShieldDemo: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const logoOpacity = interpolate(frame, [0, 20], [0, 1], { extrapolateRight: "clamp" });

  return (
    <AbsoluteFill style={{ backgroundColor: BG }}>
      <GridDots />
      <ScanLine frame={frame} />
      <Logo opacity={logoOpacity} />

      {/* Scene 1: Terminal scan command (frames 30-210) */}
      <Sequence from={30} durationInFrames={180}>
        <ScanScene />
      </Sequence>

      {/* Scene 2: Binary discovery (frames 210-390) */}
      <Sequence from={210} durationInFrames={180}>
        <BinaryScene />
      </Sequence>

      {/* Scene 3: AI classification (frames 390-570) */}
      <Sequence from={390} durationInFrames={180}>
        <ClassifyScene />
      </Sequence>

      {/* Scene 4: Risk verdict (frames 570-720) */}
      <Sequence from={570} durationInFrames={150}>
        <VerdictScene />
      </Sequence>

      {/* Scene 5: CI/PR comment (frames 720-870) */}
      <Sequence from={720} durationInFrames={150}>
        <CIScene />
      </Sequence>

      <Tagline frame={frame} />
    </AbsoluteFill>
  );
};
