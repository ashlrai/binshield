"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

import { apiFetch } from "../lib/api-client";

export function LockfileUpload({ apiBase }: { apiBase: string }) {
  const [status, setStatus] = useState<"idle" | "uploading" | "done" | "error">("idle");
  const [result, setResult] = useState<string>("");
  const router = useRouter();

  async function handleUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;

    setStatus("uploading");
    try {
      const content = await file.text();
      if (content.length > 5 * 1024 * 1024) {
        setStatus("error");
        setResult("File exceeds 5MB limit");
        return;
      }

      const res = await apiFetch("/scans/lockfile", {
        method: "POST",
        body: JSON.stringify({ filename: file.name, content }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: "Upload failed" }));
        setStatus("error");
        setResult(err.error || "Upload failed");
        return;
      }

      const data = await res.json();
      setStatus("done");
      setResult(`Scan submitted (ID: ${data.id}). Status: ${data.status}`);
      router.refresh();
    } catch {
      setStatus("error");
      setResult("Network error — check your connection");
    }
  }

  return (
    <div className="panel" style={{ padding: "var(--gap-lg)", textAlign: "center" }}>
      {status === "idle" && (
        <>
          <p style={{ marginBottom: "var(--gap-md)", color: "var(--text-muted)" }}>
            Drag and drop a lockfile or click to browse. Supported: package-lock.json, yarn.lock, pnpm-lock.yaml
          </p>
          <label className="button-link" style={{ cursor: "pointer", display: "inline-block" }}>
            Select lockfile
            <input type="file" accept=".json,.lock,.yaml,.yml" onChange={handleUpload} style={{ display: "none" }} />
          </label>
        </>
      )}
      {status === "uploading" && <p>Uploading and scanning...</p>}
      {status === "done" && <p style={{ color: "var(--accent)" }}>{result}</p>}
      {status === "error" && <p style={{ color: "var(--danger, #dc2626)" }}>{result}</p>}
      {status !== "idle" && (
        <button className="button-link" style={{ marginTop: "var(--gap-sm)" }} onClick={() => { setStatus("idle"); setResult(""); }}>
          Upload another
        </button>
      )}
    </div>
  );
}
