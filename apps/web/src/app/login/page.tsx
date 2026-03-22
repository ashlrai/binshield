"use client";

import { useState } from "react";
import { createBrowserClient } from "../../lib/supabase";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [status, setStatus] = useState<"idle" | "sending" | "sent" | "error">("idle");
  const [errorMsg, setErrorMsg] = useState("");

  const supabase = createBrowserClient();

  async function handleGitHub() {
    const { error } = await supabase.auth.signInWithOAuth({
      provider: "github",
      options: {
        redirectTo: `${window.location.origin}/auth/callback`
      }
    });
    if (error) {
      setErrorMsg(error.message);
      setStatus("error");
    }
  }

  async function handleMagicLink(e: React.FormEvent) {
    e.preventDefault();
    if (!email.trim()) return;

    setStatus("sending");
    setErrorMsg("");

    const { error } = await supabase.auth.signInWithOtp({
      email: email.trim(),
      options: {
        emailRedirectTo: `${window.location.origin}/auth/callback`
      }
    });

    if (error) {
      setErrorMsg(error.message);
      setStatus("error");
    } else {
      setStatus("sent");
    }
  }

  return (
    <main className="login-page">
      <div className="login-card panel">
        <p className="eyebrow">BinShield</p>
        <h1 className="login-title">Sign in</h1>
        <p className="login-subtitle">
          Authenticate to access your organization dashboard, watchlists, and billing.
        </p>

        <button type="button" className="login-github-btn" onClick={handleGitHub}>
          <GitHubIcon />
          Sign in with GitHub
        </button>

        <div className="login-divider">
          <span>or</span>
        </div>

        <form onSubmit={handleMagicLink} className="login-email-form">
          <input
            type="email"
            placeholder="you@company.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="login-email-input"
            required
            aria-label="Email address"
          />
          <button
            type="submit"
            className="login-magic-btn"
            disabled={status === "sending"}
          >
            {status === "sending" ? "Sending..." : "Send magic link"}
          </button>
        </form>

        {status === "sent" && (
          <p className="login-message login-message--success">
            Check your inbox — we sent a sign-in link to <strong>{email}</strong>.
          </p>
        )}

        {status === "error" && (
          <p className="login-message login-message--error">{errorMsg}</p>
        )}
      </div>
    </main>
  );
}

function GitHubIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
    </svg>
  );
}
