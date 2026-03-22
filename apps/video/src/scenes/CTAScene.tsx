import { useCurrentFrame, spring, useVideoConfig } from "remotion";
import { BinShieldLogo } from "../Demo";

const ACCENT = "#5ffbbd";
const MUTED = "#7b93b0";
const TEXT = "#e4edf8";

export const CTAScene: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const logoSpring = spring({ frame, fps, config: { damping: 12, stiffness: 80, mass: 0.8 }, durationInFrames: 30 });
  const textSpring = spring({ frame: Math.max(0, frame - 15), fps, config: { damping: 14, stiffness: 100, mass: 0.6 }, durationInFrames: 25 });
  const ctaSpring = spring({ frame: Math.max(0, frame - 30), fps, config: { damping: 10, stiffness: 120, mass: 0.5 }, durationInFrames: 25 });
  const glowPulse = 0.3 + Math.sin(frame * 0.08) * 0.2;

  return (
    <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 32 }}>
      <div style={{ position: "absolute", width: 600, height: 600, borderRadius: "50%", background: `radial-gradient(circle, ${ACCENT}${Math.round(glowPulse * 20).toString(16).padStart(2, "0")} 0%, transparent 70%)`, filter: "blur(60px)" }} />
      <div style={{ transform: `scale(${logoSpring * 2.5})`, opacity: logoSpring }}>
        <BinShieldLogo size={80} glow />
      </div>
      <div style={{ textAlign: "center", opacity: textSpring, transform: `translateY(${(1 - textSpring) * 20}px)` }}>
        <div style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 42, fontWeight: 800, color: TEXT, letterSpacing: "0.04em", marginBottom: 16 }}>
          Try BinShield free
        </div>
        <div style={{ fontFamily: "Instrument Sans, sans-serif", fontSize: 20, color: MUTED }}>
          See inside the compiled code your tools ignore.
        </div>
      </div>
      <div style={{ opacity: ctaSpring, transform: `scale(${0.9 + ctaSpring * 0.1})`, padding: "14px 40px", borderRadius: 999, background: `${ACCENT}15`, border: `2px solid ${ACCENT}44`, fontFamily: "JetBrains Mono, monospace", fontSize: 22, fontWeight: 700, color: ACCENT, letterSpacing: "0.06em", boxShadow: `0 0 24px ${ACCENT}22` }}>
        binshield.dev
      </div>
    </div>
  );
};
