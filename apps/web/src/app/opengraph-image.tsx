import { ImageResponse } from "next/og";

export const runtime = "edge";
export const alt = "BinShield — Binary supply-chain security";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function OgImage() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "center",
          alignItems: "center",
          background: "linear-gradient(135deg, #050d18 0%, #0a1628 50%, #050d18 100%)",
          fontFamily: "monospace",
          position: "relative",
          overflow: "hidden",
        }}
      >
        {/* Grid dot pattern */}
        <div
          style={{
            position: "absolute",
            inset: 0,
            display: "flex",
            opacity: 0.15,
            backgroundImage: "radial-gradient(circle, #5ffbbd 1.5px, transparent 1.5px)",
            backgroundSize: "28px 28px",
          }}
        />

        {/* Gradient glow */}
        <div
          style={{
            position: "absolute",
            top: "-20%",
            left: "10%",
            width: "500px",
            height: "500px",
            borderRadius: "50%",
            background: "radial-gradient(circle, rgba(95, 251, 189, 0.12), transparent 70%)",
            display: "flex",
          }}
        />

        {/* Content */}
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            gap: "24px",
            zIndex: 1,
          }}
        >
          {/* Shield icon */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              width: "80px",
              height: "80px",
              borderRadius: "16px",
              border: "2px solid rgba(95, 251, 189, 0.3)",
              background: "rgba(95, 251, 189, 0.05)",
            }}
          >
            <svg width="40" height="40" viewBox="0 0 32 32" fill="none">
              <rect x="2" y="2" width="28" height="28" rx="5" stroke="#5ffbbd" strokeWidth="1.5" />
              <rect x="7" y="7" width="7" height="5" rx="1.5" fill="#5ffbbd" opacity="0.5" />
              <rect x="18" y="7" width="7" height="5" rx="1.5" fill="#5ffbbd" opacity="0.5" />
              <rect x="7" y="15" width="7" height="5" rx="1.5" fill="#5ffbbd" opacity="0.5" />
              <rect x="18" y="15" width="7" height="5" rx="1.5" fill="#5ffbbd" opacity="0.5" />
              <circle cx="16" cy="16" r="4" fill="#5ffbbd" />
            </svg>
          </div>

          {/* Wordmark */}
          <div
            style={{
              fontSize: "64px",
              fontWeight: 800,
              color: "#e4edf8",
              letterSpacing: "0.02em",
              display: "flex",
            }}
          >
            BINSHIELD
          </div>

          {/* Tagline */}
          <div
            style={{
              fontSize: "24px",
              color: "#5ffbbd",
              letterSpacing: "0.06em",
              textTransform: "uppercase",
              display: "flex",
            }}
          >
            Binary supply-chain security
          </div>

          {/* Subtitle */}
          <div
            style={{
              fontSize: "18px",
              color: "#7b93b0",
              maxWidth: "600px",
              textAlign: "center",
              lineHeight: 1.5,
              display: "flex",
            }}
          >
            Decompile native package binaries. Classify behavior with AI. Block threats in CI.
          </div>

          {/* Stats bar */}
          <div
            style={{
              display: "flex",
              gap: "32px",
              marginTop: "16px",
            }}
          >
            {[
              { label: "Packages", value: "23+" },
              { label: "Binaries", value: "70+" },
              { label: "Risk engine", value: "AI" },
            ].map((stat) => (
              <div
                key={stat.label}
                style={{
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "center",
                  gap: "4px",
                  padding: "12px 24px",
                  borderRadius: "12px",
                  border: "1px solid rgba(95, 251, 189, 0.15)",
                  background: "rgba(95, 251, 189, 0.04)",
                }}
              >
                <span style={{ fontSize: "28px", fontWeight: 700, color: "#e4edf8" }}>
                  {stat.value}
                </span>
                <span style={{ fontSize: "12px", color: "#7b93b0", textTransform: "uppercase", letterSpacing: "0.1em" }}>
                  {stat.label}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Domain */}
        <div
          style={{
            position: "absolute",
            bottom: "28px",
            display: "flex",
            fontSize: "16px",
            color: "#5ffbbd",
            opacity: 0.6,
            letterSpacing: "0.08em",
          }}
        >
          binshield.dev
        </div>
      </div>
    ),
    { ...size }
  );
}
