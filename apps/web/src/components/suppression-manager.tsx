"use client";

import { useState, useEffect, useCallback } from "react";

import { apiFetch } from "../lib/api-client";

interface SuppressionSummary {
  id: string;
  orgId: string;
  ecosystem: string;
  packageName: string;
  version?: string;
  findingCategory?: string;
  findingTitle?: string;
  reason: string;
  createdAt: string;
}

interface SuppressionManagerProps {
  orgId: string;
}

const EMPTY_FORM = {
  ecosystem: "npm",
  packageName: "",
  version: "",
  findingCategory: "",
  findingTitle: "",
  reason: ""
};

export function SuppressionManager({ orgId }: SuppressionManagerProps) {
  const [items, setItems] = useState<SuppressionSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [formOpen, setFormOpen] = useState(false);
  const [form, setForm] = useState(EMPTY_FORM);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const res = await apiFetch(`/orgs/${orgId}/suppressions`);
      if (res.ok) {
        const data = await res.json() as { items: SuppressionSummary[] };
        setItems(data.items);
      }
    } catch {
      // silently ignore
    } finally {
      setLoading(false);
    }
  }, [orgId]);

  useEffect(() => {
    void load();
  }, [load]);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!form.packageName.trim() || !form.reason.trim()) return;
    setSubmitting(true);
    setError(null);

    try {
      const res = await apiFetch(`/orgs/${orgId}/suppressions`, {
        method: "POST",
        body: JSON.stringify({
          ecosystem: form.ecosystem,
          packageName: form.packageName.trim(),
          version: form.version.trim() || undefined,
          findingCategory: form.findingCategory.trim() || undefined,
          findingTitle: form.findingTitle.trim() || undefined,
          reason: form.reason.trim()
        })
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({})) as { error?: string };
        setError(body.error ?? `Error ${res.status}`);
        return;
      }

      setForm(EMPTY_FORM);
      setFormOpen(false);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Network error");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleDelete(id: string) {
    try {
      await apiFetch(`/orgs/${orgId}/suppressions/${id}`, { method: "DELETE" });
      setItems((prev) => prev.filter((s) => s.id !== id));
    } catch {
      // silently ignore
    }
  }

  if (!orgId) {
    return <p style={{ color: "var(--muted)" }}>Organization context unavailable.</p>;
  }

  return (
    <div>
      {loading ? (
        <p style={{ color: "var(--muted)", fontSize: "0.88rem" }}>Loading suppressions...</p>
      ) : items.length === 0 ? (
        <p style={{ color: "var(--muted)", fontSize: "0.88rem" }}>
          No suppressions yet. Add one below to silence a confirmed false positive.
        </p>
      ) : (
        <ul className="stack-list" style={{ marginBottom: "var(--gap-md)" }}>
          {items.map((s) => (
            <li key={s.id} className="stack-item">
              <div style={{ flex: 1 }}>
                <strong>
                  {s.ecosystem}/{s.packageName}
                  {s.version ? `@${s.version}` : ""}
                </strong>
                {s.findingTitle && (
                  <p style={{ margin: "2px 0", fontSize: "0.85rem" }}>
                    Finding: <em>{s.findingTitle}</em>
                    {s.findingCategory ? ` (${s.findingCategory})` : ""}
                  </p>
                )}
                <p style={{ color: "var(--muted)", fontSize: "0.82rem", margin: "2px 0" }}>
                  {s.reason}
                </p>
                <p style={{ color: "var(--muted)", fontSize: "0.78rem", margin: 0 }}>
                  Added {new Date(s.createdAt).toLocaleDateString()}
                </p>
              </div>
              <button
                className="button-link button-link--ghost"
                style={{ fontSize: "0.82rem", padding: "2px 8px" }}
                onClick={() => handleDelete(s.id)}
                type="button"
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}

      {!formOpen ? (
        <button
          className="button-link button-link--ghost"
          onClick={() => setFormOpen(true)}
          type="button"
        >
          + Add suppression
        </button>
      ) : (
        <form onSubmit={handleCreate} style={{ marginTop: "var(--gap-md)" }}>
          <div className="scan-form__fields" style={{ flexDirection: "column", gap: "var(--gap-sm)" }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr 1fr", gap: "var(--gap-sm)" }}>
              <div>
                <label htmlFor="sup-eco" style={{ fontSize: "0.82rem" }}>Ecosystem</label>
                <select
                  id="sup-eco"
                  value={form.ecosystem}
                  onChange={(e) => setForm((f) => ({ ...f, ecosystem: e.target.value }))}
                  style={{ width: "100%", padding: "6px", background: "var(--bg-raised)", border: "1px solid var(--border)", color: "var(--text)", borderRadius: "4px" }}
                >
                  <option value="npm">npm</option>
                  <option value="pypi">pypi</option>
                  <option value="crates">crates</option>
                  <option value="go">go</option>
                </select>
              </div>
              <div>
                <label htmlFor="sup-pkg" style={{ fontSize: "0.82rem" }}>Package name *</label>
                <input
                  id="sup-pkg"
                  type="text"
                  placeholder="e.g. bcrypt"
                  value={form.packageName}
                  onChange={(e) => setForm((f) => ({ ...f, packageName: e.target.value }))}
                  required
                  style={{ width: "100%", padding: "6px", boxSizing: "border-box" }}
                />
              </div>
              <div>
                <label htmlFor="sup-ver" style={{ fontSize: "0.82rem" }}>Version (optional)</label>
                <input
                  id="sup-ver"
                  type="text"
                  placeholder="all versions"
                  value={form.version}
                  onChange={(e) => setForm((f) => ({ ...f, version: e.target.value }))}
                  style={{ width: "100%", padding: "6px", boxSizing: "border-box" }}
                />
              </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "var(--gap-sm)" }}>
              <div>
                <label htmlFor="sup-cat" style={{ fontSize: "0.82rem" }}>Finding category (optional)</label>
                <input
                  id="sup-cat"
                  type="text"
                  placeholder="e.g. network, filesystem"
                  value={form.findingCategory}
                  onChange={(e) => setForm((f) => ({ ...f, findingCategory: e.target.value }))}
                  style={{ width: "100%", padding: "6px", boxSizing: "border-box" }}
                />
              </div>
              <div>
                <label htmlFor="sup-title" style={{ fontSize: "0.82rem" }}>Finding title (optional)</label>
                <input
                  id="sup-title"
                  type="text"
                  placeholder="exact finding title to suppress"
                  value={form.findingTitle}
                  onChange={(e) => setForm((f) => ({ ...f, findingTitle: e.target.value }))}
                  style={{ width: "100%", padding: "6px", boxSizing: "border-box" }}
                />
              </div>
            </div>

            <div>
              <label htmlFor="sup-reason" style={{ fontSize: "0.82rem" }}>Reason *</label>
              <input
                id="sup-reason"
                type="text"
                placeholder="e.g. reviewed by security team — confirmed benign"
                value={form.reason}
                onChange={(e) => setForm((f) => ({ ...f, reason: e.target.value }))}
                required
                style={{ width: "100%", padding: "6px", boxSizing: "border-box" }}
              />
            </div>

            {error && <p className="scan-form__error">{error}</p>}

            <div style={{ display: "flex", gap: "var(--gap-sm)" }}>
              <button type="submit" className="button-link" disabled={submitting}>
                {submitting ? "Saving..." : "Add suppression"}
              </button>
              <button
                type="button"
                className="button-link button-link--ghost"
                onClick={() => { setFormOpen(false); setForm(EMPTY_FORM); setError(null); }}
              >
                Cancel
              </button>
            </div>
          </div>
        </form>
      )}
    </div>
  );
}
