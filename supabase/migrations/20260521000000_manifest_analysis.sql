-- Install-script / manifest analysis support.
--
-- BinShield's second analysis path inspects npm/PyPI install scripts
-- (postinstall hooks, setup.py) — the vector used by supply-chain worms.
-- This migration adds storage for that analysis alongside the existing
-- native-binary analysis, and lets advisories distinguish a malicious
-- package from a merely vulnerable one.

alter table analyses
  add column if not exists manifest_analysis jsonb,
  add column if not exists script_findings jsonb not null default '[]'::jsonb;

comment on column analyses.manifest_analysis is
  'Install-script / manifest analysis (ManifestAnalysis): lifecycle hooks, script threats, findings.';
comment on column analyses.script_findings is
  'Flattened ScriptFinding[] from manifest_analysis, for fast querying.';

alter table advisories
  add column if not exists advisory_type text not null default 'vulnerability';

comment on column advisories.advisory_type is
  'vulnerability = a CVE-style flaw; malware = the package itself is malicious (OSV MAL-* / GHSA malware).';

create index if not exists advisories_advisory_type_idx on advisories (advisory_type);
