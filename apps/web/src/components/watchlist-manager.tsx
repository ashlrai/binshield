"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

import { apiFetch } from "../lib/api-client";

interface WatchlistItem {
  packageName: string;
  ecosystem: string;
  previousVersion: string;
  currentVersion: string;
  riskChange: number;
  status: string;
  channel: string;
  note: string;
}

interface Watchlist {
  id: string;
  name: string;
  channel: string;
  destination: string;
}

interface Props {
  orgId: string;
  items: WatchlistItem[];
  watchlists: Watchlist[];
}

export function WatchlistManager({ orgId, items, watchlists }: Props) {
  const router = useRouter();
  const [showAddForm, setShowAddForm] = useState(false);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [addPackage, setAddPackage] = useState("");
  const [addVersion, setAddVersion] = useState("");
  const [selectedWatchlist, setSelectedWatchlist] = useState(watchlists[0]?.id ?? "");
  const [creating, setCreating] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Create watchlist form state
  const [newName, setNewName] = useState("");
  const [newChannel, setNewChannel] = useState("email");
  const [newDestination, setNewDestination] = useState("");

  async function handleAddPackage(e: React.FormEvent) {
    e.preventDefault();
    if (!addPackage.trim() || !selectedWatchlist) return;
    setCreating(true);
    setError(null);

    try {
      const res = await apiFetch(`/orgs/${orgId}/watchlists/${selectedWatchlist}/packages`, {
        method: "POST",
        body: JSON.stringify({
          ecosystem: "npm",
          packageName: addPackage.trim(),
          version: addVersion.trim() || undefined,
        }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        setError(data.error ?? "Failed to add package");
        return;
      }
      setAddPackage("");
      setAddVersion("");
      setShowAddForm(false);
      router.refresh();
    } catch {
      setError("Network error");
    } finally {
      setCreating(false);
    }
  }

  async function handleRemovePackage(packageName: string) {
    if (!selectedWatchlist) return;
    setRemoving(packageName);
    setError(null);

    try {
      const res = await apiFetch(`/orgs/${orgId}/watchlists/${selectedWatchlist}/packages/${encodeURIComponent(packageName)}`, {
        method: "DELETE",
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        setError(data.error ?? "Failed to remove package");
        return;
      }
      router.refresh();
    } catch {
      setError("Network error");
    } finally {
      setRemoving(null);
    }
  }

  async function handleCreateWatchlist(e: React.FormEvent) {
    e.preventDefault();
    if (!newName.trim() || !newDestination.trim()) return;
    setCreating(true);
    setError(null);

    try {
      const res = await apiFetch(`/orgs/${orgId}/watchlists`, {
        method: "POST",
        body: JSON.stringify({
          name: newName.trim(),
          channel: newChannel,
          destination: newDestination.trim(),
        }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        setError(data.error ?? "Failed to create watchlist");
        return;
      }
      setNewName("");
      setNewDestination("");
      setShowCreateForm(false);
      router.refresh();
    } catch {
      setError("Network error");
    } finally {
      setCreating(false);
    }
  }

  return (
    <div>
      <div style={{ display: "flex", gap: "var(--gap-sm)", marginBottom: "var(--gap-md)" }}>
        <button className="button-link" type="button" onClick={() => { setShowAddForm(!showAddForm); setShowCreateForm(false); }}>
          Add package
        </button>
        <button className="button-link button-link--ghost" type="button" onClick={() => { setShowCreateForm(!showCreateForm); setShowAddForm(false); }}>
          New watchlist
        </button>
      </div>

      {showAddForm && (
        <form onSubmit={handleAddPackage} className="panel" style={{ padding: "var(--gap-md)", marginBottom: "var(--gap-md)" }}>
          <div style={{ display: "flex", gap: "var(--gap-sm)", flexWrap: "wrap" }}>
            {watchlists.length > 1 && (
              <select value={selectedWatchlist} onChange={(e) => setSelectedWatchlist(e.target.value)} style={{ flex: "0 0 auto" }}>
                {watchlists.map((w) => <option key={w.id} value={w.id}>{w.name}</option>)}
              </select>
            )}
            <input type="text" placeholder="Package name (e.g. bcrypt)" value={addPackage} onChange={(e) => setAddPackage(e.target.value)} style={{ flex: 1, minWidth: "150px" }} />
            <input type="text" placeholder="Version (optional)" value={addVersion} onChange={(e) => setAddVersion(e.target.value)} style={{ width: "120px" }} />
            <button type="submit" className="button-link" disabled={creating || !addPackage.trim()}>
              {creating ? "Adding..." : "Add"}
            </button>
          </div>
        </form>
      )}

      {showCreateForm && (
        <form onSubmit={handleCreateWatchlist} className="panel" style={{ padding: "var(--gap-md)", marginBottom: "var(--gap-md)" }}>
          <div style={{ display: "flex", gap: "var(--gap-sm)", flexWrap: "wrap" }}>
            <input type="text" placeholder="Watchlist name" value={newName} onChange={(e) => setNewName(e.target.value)} style={{ flex: 1, minWidth: "150px" }} />
            <select value={newChannel} onChange={(e) => setNewChannel(e.target.value)}>
              <option value="email">Email</option>
              <option value="slack">Slack</option>
              <option value="webhook">Webhook</option>
            </select>
            <input type="text" placeholder={newChannel === "email" ? "Email address" : newChannel === "slack" ? "Webhook URL" : "Endpoint URL"} value={newDestination} onChange={(e) => setNewDestination(e.target.value)} style={{ flex: 1, minWidth: "200px" }} />
            <button type="submit" className="button-link" disabled={creating || !newName.trim() || !newDestination.trim()}>
              {creating ? "Creating..." : "Create"}
            </button>
          </div>
        </form>
      )}

      {items.length > 0 && items.map((item) => (
        <div key={item.packageName} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "var(--gap-sm) 0", borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
          <div>
            <strong>{item.packageName}</strong>
            <span style={{ color: "var(--muted)", marginLeft: "var(--gap-sm)", fontSize: "0.85rem" }}>
              {item.previousVersion} → {item.currentVersion}
            </span>
          </div>
          <button
            className="button-link button-link--ghost"
            type="button"
            style={{ color: "var(--danger, #dc2626)", fontSize: "0.85rem" }}
            disabled={removing === item.packageName}
            onClick={() => handleRemovePackage(item.packageName)}
          >
            {removing === item.packageName ? "Removing..." : "Remove"}
          </button>
        </div>
      ))}

      {error && <p style={{ color: "var(--danger, #dc2626)", marginTop: "var(--gap-sm)" }}>{error}</p>}
    </div>
  );
}
