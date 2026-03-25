"use client";

import { useState } from "react";

import { apiFetch } from "../lib/api-client";

interface CheckoutButtonProps {
  plan: string;
  label?: string;
  className?: string;
}

/**
 * Client component that initiates a Stripe Checkout session by calling the
 * BinShield API, then redirects the browser to the Stripe-hosted checkout page.
 */
export function CheckoutButton({ plan, label = "Start trial", className }: CheckoutButtonProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleClick() {
    setLoading(true);
    setError(null);

    try {
      const response = await apiFetch("/billing/checkout", {
        method: "POST",
        body: JSON.stringify({ plan }),
      });

      if (!response.ok) {
        const body = await response.json().catch(() => ({ error: "Checkout failed" }));
        setError((body as { error?: string }).error ?? "Checkout failed");
        setLoading(false);
        return;
      }

      const data = (await response.json()) as { checkoutUrl?: string; url?: string };
      const checkoutUrl = data.checkoutUrl ?? data.url;

      if (!checkoutUrl) {
        setError("No checkout URL returned");
        setLoading(false);
        return;
      }

      // Redirect to Stripe Checkout
      window.location.href = checkoutUrl;
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
        className={className ?? "button-link"}
        style={loading ? { opacity: 0.7, cursor: "wait" } : undefined}
      >
        {loading ? "Redirecting\u2026" : label}
      </button>
      {error && (
        <p style={{ color: "var(--destructive, #ef4444)", fontSize: "0.8rem", marginTop: "6px" }}>
          {error}
        </p>
      )}
    </div>
  );
}
