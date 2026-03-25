"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

import { apiFetch } from "../lib/api-client";

interface ApiKeyItem {
  id?: string;
  label: string;
  maskedKey: string;
  lastUsedLabel: string;
}

interface Props {
  orgId: string;
  keys: ApiKeyItem[];
}

export function ApiKeyManager({ orgId, keys }: Props) {
  const router = useRouter();
  const [label, setLabel] = useState("");
  const [creating, setCreating] = useState(false);
  const [newKey, setNewKey] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!label.trim()) return;
    setCreating(true);
    setError(null);
    setNewKey(null);

    try {
      const res = await apiFetch(`/orgs/${orgId}/api-keys`, {
        method: "POST",
        body: JSON.stringify({ label: label.trim() }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        setError(data.error ?? "Failed to create API key");
        return;
      }
      const data = await res.json();
      setNewKey(data.plaintextKey);
      setLabel("");
      router.refresh();
    } catch {
      setError("Network error");
    } finally {
      setCreating(false);
    }
  }

  async function handleRevoke(keyId: string) {
    setRevoking(keyId);
    setError(null);
    try {
      const res = await apiFetch(`/orgs/${orgId}/api-keys/${keyId}`, { method: "DELETE" });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        setError(data.error ?? "Failed to revoke key");
        return;
      }
      router.refresh();
    } catch {
      setError("Network error");
    } finally {
      setRevoking(null);
    }
  }

  return (
    <div>
      {newKey && (
        <div className="panel" style={{ padding: "var(--gap-md)", marginBottom: "var(--gap-md)", border: "1px solid var(--accent)" }}>
          <p style={{ color: "var(--accent)", marginBottom: "var(--gap-sm)" }}>
            <strong>Copy your API key now.</strong> It will not be shown again.
          </p>
          <code style={{ display: "block", padding: "var(--gap-sm)", background: "var(--bg)", borderRadius: "var(--radius-sm)", wordBreak: "break-all", fontSize: "0.85rem" }}>
            {newKey}
          </code>
          <button className="button-link" type="button" style={{ marginTop: "var(--gap-sm)" }} onClick={() => { navigator.clipboard.writeText(newKey); }}>
            Copy to clipboard
          </button>
        </div>
      )}

      {keys.length > 0 && (
        <div className="key-list" style={{ marginBottom: "var(--gap-md)" }}>
          {keys.map((key) => (
            <article key={key.id ?? key.label} className="key-row" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <strong>{key.label}</strong>
                <p>{key.maskedKey}</p>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: "var(--gap-sm)" }}>
                <span>{key.lastUsedLabel}</span>
                {key.id && (
                  <button
                    className="button-link button-link--ghost"
                    type="button"
                    style={{ color: "var(--danger, #dc2626)", fontSize: "0.85rem" }}
                    disabled={revoking === key.id}
                    onClick={() => handleRevoke(key.id!)}
                  >
                    {revoking === key.id ? "Revoking..." : "Revoke"}
                  </button>
                )}
              </div>
            </article>
          ))}
        </div>
      )}

      <form onSubmit={handleCreate} style={{ display: "flex", gap: "var(--gap-sm)", alignItems: "flex-end" }}>
        <div style={{ flex: 1 }}>
          <label htmlFor="api-key-label" style={{ display: "block", marginBottom: "4px", fontSize: "0.85rem", color: "var(--muted)" }}>Key label</label>
          <input
            id="api-key-label"
            type="text"
            placeholder="e.g. CI pipeline, GitHub Action"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            disabled={creating}
            style={{ width: "100%" }}
          />
        </div>
        <button type="submit" className="button-link" disabled={creating || !label.trim()}>
          {creating ? "Creating..." : "Create key"}
        </button>
      </form>

      {error && <p style={{ color: "var(--danger, #dc2626)", marginTop: "var(--gap-sm)" }}>{error}</p>}
    </div>
  );
}
