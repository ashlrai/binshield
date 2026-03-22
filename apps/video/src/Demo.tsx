import {
  AbsoluteFill,
  Sequence,
  useCurrentFrame,
  interpolate,
  spring,
  useVideoConfig,
  Easing,
} from "remotion";
import { ScanScene } from "./scenes/ScanScene";
import { BinaryScene } from "./scenes/BinaryScene";
import { ClassifyScene } from "./scenes/ClassifyScene";
import { VerdictScene } from "./scenes/VerdictScene";
import { CIScene } from "./scenes/CIScene";
import { CTAScene } from "./scenes/CTAScene";

const BG = "#050d18";
const ACCENT = "#5ffbbd";
const MUTED = "#7b93b0";
const TEXT = "#e4edf8";

/* ------------------------------------------------------------------ */
/*  Animated dot-grid background that pulses on scene transitions      */
/* ------------------------------------------------------------------ */
function ParticleField({ frame }: { frame: number }) {
  const cols = 48;
  const rows = 27;
  const spacing = 40;

  // Pulse intensity peaks at scene boundaries
  const sceneStarts = [90, 210, 340, 460, 570, 660];
  let pulse = 0;
  for (const s of sceneStarts) {
    const dist = Math.abs(frame - s);
    pulse = Math.max(pulse, Math.max(0, 1 - dist / 20));
  }

  const baseOpacity = 0.08 + pulse * 0.14;
  const drift = Math.sin(frame * 0.02) * 4;

  return (
    <div
      style={{
        position: "absolute",
        inset: 0,
        overflow: "hidden",
        opacity: baseOpacity,
      }}
    >
      <div
        style={{
          position: "absolute",
          inset: -20,
          transform: `translate(${drift}px, ${drift * 0.5}px)`,
          backgroundImage: `radial-gradient(circle, ${ACCENT} 1.2px, transparent 1.2px)`,
          backgroundSize: `${spacing}px ${spacing}px`,
          maskImage:
            "radial-gradient(ellipse 70% 60% at 50% 50%, rgba(0,0,0,1) 0%, transparent 100%)",
          WebkitMaskImage:
            "radial-gradient(ellipse 70% 60% at 50% 50%, rgba(0,0,0,1) 0%, transparent 100%)",
        }}
      />
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Scan line overlay                                                  */
/* ------------------------------------------------------------------ */
function ScanLine({ frame }: { frame: number }) {
  const y = (frame * 2.5) % 1080;
  const opacity = interpolate(frame, [0, 60], [0, 0.06], {
    extrapolateRight: "clamp",
  });
  return (
    <div
      style={{
        position: "absolute",
        left: 0,
        right: 0,
        top: y,
        height: 1,
        background: `linear-gradient(90deg, transparent 5%, ${ACCENT}88 30%, ${ACCENT} 50%, ${ACCENT}88 70%, transparent 95%)`,
        opacity,
        filter: `blur(0.5px)`,
        boxShadow: `0 0 12px 2px ${ACCENT}44`,
      }}
    />
  );
}

/* ------------------------------------------------------------------ */
/*  Persistent top-left logo (after intro)                             */
/* ------------------------------------------------------------------ */
function PersistentLogo({ frame, fps }: { frame: number; fps: number }) {
  // Appears after the intro sequence ends (frame 90)
  const opacity = interpolate(frame, [90, 105], [0, 0.7], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  if (opacity <= 0) return null;

  return (
    <div
      style={{
        position: "absolute",
        top: 32,
        left: 48,
        display: "flex",
        alignItems: "center",
        gap: 12,
        opacity,
        fontFamily: "JetBrains Mono, monospace",
        fontSize: 18,
        fontWeight: 800,
        color: TEXT,
        letterSpacing: "0.06em",
      }}
    >
      <BinShieldLogo size={28} />
      BINSHIELD
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  The actual BinShield SVG logo (shield+grid)                        */
/* ------------------------------------------------------------------ */
export function BinShieldLogo({ size = 32, glow = false }: { size?: number; glow?: boolean }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      style={glow ? { filter: `drop-shadow(0 0 20px ${ACCENT}88) drop-shadow(0 0 40px ${ACCENT}44)` } : undefined}
    >
      <rect x="2" y="2" width="28" height="28" rx="5" stroke={ACCENT} strokeWidth="1.5" fill="none" />
      <rect x="7" y="7" width="7" height="5" rx="1.5" fill={ACCENT} opacity="0.5" />
      <rect x="18" y="7" width="7" height="5" rx="1.5" fill={ACCENT} opacity="0.5" />
      <rect x="7" y="15" width="7" height="5" rx="1.5" fill={ACCENT} opacity="0.5" />
      <rect x="18" y="15" width="7" height="5" rx="1.5" fill={ACCENT} opacity="0.5" />
      <circle cx="16" cy="16" r="4" fill={ACCENT} />
      <path d="M16 13v6M13 16h6" stroke={BG} strokeWidth="1.5" strokeLinecap="round" />
      <rect x="7" y="23" width="18" height="2" rx="1" fill={ACCENT} opacity="0.3" />
    </svg>
  );
}

/* ------------------------------------------------------------------ */
/*  Scene transition wrapper — fades in/out at edges                   */
/* ------------------------------------------------------------------ */
function SceneTransition({
  children,
  durationInFrames,
  fadeIn = 15,
  fadeOut = 12,
}: {
  children: React.ReactNode;
  durationInFrames: number;
  fadeIn?: number;
  fadeOut?: number;
}) {
  const frame = useCurrentFrame();
  const entryOpacity = interpolate(frame, [0, fadeIn], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const exitOpacity = interpolate(
    frame,
    [durationInFrames - fadeOut, durationInFrames],
    [1, 0],
    { extrapolateLeft: "clamp", extrapolateRight: "clamp" }
  );
  const entryY = interpolate(frame, [0, fadeIn], [20, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.out(Easing.cubic),
  });

  return (
    <AbsoluteFill
      style={{
        opacity: Math.min(entryOpacity, exitOpacity),
        transform: `translateY(${entryY}px)`,
      }}
    >
      {children}
    </AbsoluteFill>
  );
}

/* ------------------------------------------------------------------ */
/*  Intro sequence: logo reveal with glow, then tagline               */
/* ------------------------------------------------------------------ */
function IntroScene() {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  // Logo scale spring
  const logoScale = spring({
    frame,
    fps,
    config: { damping: 12, stiffness: 80, mass: 0.8 },
    durationInFrames: 30,
  });

  // Glow pulse
  const glowIntensity = interpolate(frame, [15, 35, 55], [0, 1, 0.3], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  // Tagline entrance
  const tagSpring = spring({
    frame: Math.max(0, frame - 30),
    fps,
    config: { damping: 14, stiffness: 100, mass: 0.6 },
    durationInFrames: 25,
  });

  const subtitleSpring = spring({
    frame: Math.max(0, frame - 42),
    fps,
    config: { damping: 14, stiffness: 100, mass: 0.6 },
    durationInFrames: 25,
  });

  // Fade out the intro
  const fadeOut = interpolate(frame, [72, 90], [1, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  return (
    <AbsoluteFill
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        opacity: fadeOut,
      }}
    >
      {/* Radial glow behind logo */}
      <div
        style={{
          position: "absolute",
          width: 400,
          height: 400,
          borderRadius: "50%",
          background: `radial-gradient(circle, ${ACCENT}${Math.round(glowIntensity * 30).toString(16).padStart(2, "0")} 0%, transparent 70%)`,
          filter: "blur(40px)",
        }}
      />

      {/* Logo */}
      <div
        style={{
          transform: `scale(${logoScale * 3})`,
          marginBottom: 32,
        }}
      >
        <BinShieldLogo size={64} glow={glowIntensity > 0.3} />
      </div>

      {/* Product name */}
      <div
        style={{
          fontFamily: "JetBrains Mono, monospace",
          fontSize: 56,
          fontWeight: 800,
          color: TEXT,
          letterSpacing: "0.08em",
          opacity: tagSpring,
          transform: `translateY(${(1 - tagSpring) * 20}px)`,
        }}
      >
        BINSHIELD
      </div>

      {/* Tagline */}
      <div
        style={{
          fontFamily: "Instrument Sans, sans-serif",
          fontSize: 22,
          color: MUTED,
          marginTop: 16,
          opacity: subtitleSpring,
          transform: `translateY(${(1 - subtitleSpring) * 15}px)`,
          letterSpacing: "0.02em",
        }}
      >
        Binary supply-chain security for the dependencies everyone else ignores.
      </div>
    </AbsoluteFill>
  );
}

/* ================================================================== */
/*  MAIN COMPOSITION                                                   */
/* ================================================================== */
export const BinShieldDemo: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  /*
   * Timeline (750 frames / 25 seconds @ 30fps):
   *   0–90    Intro (logo reveal + tagline)
   *  90–210   Scene 1: Scan (120 frames)
   * 210–340   Scene 2: Binary discovery (130 frames)
   * 340–460   Scene 3: AI classification (120 frames)
   * 460–570   Scene 4: Risk verdict (110 frames)
   * 570–660   Scene 5: CI report (90 frames)
   * 660–750   Scene 6: CTA (90 frames)
   */

  return (
    <AbsoluteFill style={{ backgroundColor: BG }}>
      <ParticleField frame={frame} />
      <ScanLine frame={frame} />

      {/* Intro */}
      <Sequence from={0} durationInFrames={90}>
        <IntroScene />
      </Sequence>

      {/* Scene 1: Scan */}
      <Sequence from={90} durationInFrames={120}>
        <SceneTransition durationInFrames={120}>
          <ScanScene />
        </SceneTransition>
      </Sequence>

      {/* Scene 2: Binary discovery */}
      <Sequence from={210} durationInFrames={130}>
        <SceneTransition durationInFrames={130}>
          <BinaryScene />
        </SceneTransition>
      </Sequence>

      {/* Scene 3: AI classification */}
      <Sequence from={340} durationInFrames={120}>
        <SceneTransition durationInFrames={120}>
          <ClassifyScene />
        </SceneTransition>
      </Sequence>

      {/* Scene 4: Risk verdict */}
      <Sequence from={460} durationInFrames={110}>
        <SceneTransition durationInFrames={110}>
          <VerdictScene />
        </SceneTransition>
      </Sequence>

      {/* Scene 5: CI report */}
      <Sequence from={570} durationInFrames={90}>
        <SceneTransition durationInFrames={90}>
          <CIScene />
        </SceneTransition>
      </Sequence>

      {/* Scene 6: CTA */}
      <Sequence from={660} durationInFrames={90}>
        <CTAScene />
      </Sequence>

      {/* Persistent logo after intro */}
      <PersistentLogo frame={frame} fps={fps} />
    </AbsoluteFill>
  );
};
