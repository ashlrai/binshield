"use client";

import { useState } from "react";

export function DemoVideo() {
  const [isPlaying, setIsPlaying] = useState(false);

  return (
    <section className="demo-video-section">
      <div className="demo-video__header">
        <p className="eyebrow">See it in action</p>
        <h2>How BinShield analyzes your dependencies</h2>
        <p className="demo-video__subtitle">
          Watch a real binary analysis — from package scan to AI classification to CI report — in 25 seconds.
        </p>
      </div>

      <div className="demo-video__player">
        <video
          src="/demo.mp4"
          autoPlay
          muted
          loop
          playsInline
          controls={isPlaying}
          onPlay={() => setIsPlaying(true)}
          className="demo-video__video"
        >
          <source src="/demo.mp4" type="video/mp4" />
        </video>
        {!isPlaying && (
          <button
            className="demo-video__play-btn"
            onClick={(e) => {
              const video = (e.currentTarget.parentElement as HTMLElement).querySelector("video");
              if (video) {
                video.play();
                setIsPlaying(true);
              }
            }}
            aria-label="Play demo video"
          >
            <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
              <circle cx="24" cy="24" r="23" stroke="currentColor" strokeWidth="2" opacity="0.5" />
              <path d="M19 14l16 10-16 10V14z" fill="currentColor" />
            </svg>
          </button>
        )}
      </div>
    </section>
  );
}
