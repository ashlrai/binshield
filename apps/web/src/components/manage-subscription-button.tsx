"use client";

import { useState } from "react";

/**
 * Client component that creates a Stripe billing portal session
 * and redirects the user to manage their subscription.
 */
export function ManageSubscriptionButton() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleClick() {
    setLoading(true);
    setError(null);

    try {
      const apiBase =
        process.env.NEXT_PUBLIC_BINSHIELD_API_BASE_URL ??
        process.env.BINSHIELD_API_BASE_URL ??
        "";

      if (!apiBase) {
        setError("API not configured");
        setLoading(false);
        return;
      }

      const response = await fetch(`${apiBase.replace(/\/+$/, "")}/billing/portal`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          returnUrl: window.location.href,
        }),
      });

      if (!response.ok) {
        const body = await response.json().catch(() => ({ error: "Failed to create portal session" }));
        setError((body as { error?: string }).error ?? "Failed to create portal session");
        setLoading(false);
        return;
      }

      const data = (await response.json()) as { url?: string; portalUrl?: string };
      const portalUrl = data.url ?? data.portalUrl;

      if (!portalUrl) {
        setError("No portal URL returned");
        setLoading(false);
        return;
      }

      window.location.href = portalUrl;
    } catch {
      setError("Something went wrong. Please try again.");
      setLoading(false);
    }
  }

  return (
    <div>
      <button
        type="button"
        onClick={handleClick}
        disabled={loading}
        className="button-link"
        style={loading ? { opacity: 0.7, cursor: "wait" } : undefined}
      >
        {loading ? "Redirecting\u2026" : "Manage subscription"}
      </button>
      {error && (
        <p style={{ color: "var(--destructive, #ef4444)", fontSize: "0.8rem", marginTop: "6px" }}>
          {error}
        </p>
      )}
    </div>
  );
}
