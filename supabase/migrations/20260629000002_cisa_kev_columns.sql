-- CISA Known Exploited Vulnerabilities (KEV) enrichment for the advisories table.
--
-- Adds two new columns to `advisories`:
--   cisa_kev_date           — date CISA first confirmed the CVE is being exploited
--   exploit_maturity_score  — maturity tier of real-world exploitation evidence
--
-- exploit_maturity_score values:
--   'proof-of-concept'  — PoC code exists but no confirmed exploitation in the wild
--   'active-exploitation' — actively exploited per CISA KEV catalogue
--   'widespread'          — large-scale / ransomware-level exploitation observed

alter table advisories
  add column if not exists cisa_kev_date        date         null,
  add column if not exists exploit_maturity_score text         null
    check (exploit_maturity_score in ('proof-of-concept','active-exploitation','widespread'));

-- Fast lookup: find all advisories confirmed by CISA KEV (non-null date)
create index if not exists advisories_cisa_kev_idx
  on advisories (cisa_kev_date)
  where cisa_kev_date is not null;

-- Fast lookup: advisories at a given maturity tier
create index if not exists advisories_exploit_maturity_idx
  on advisories (exploit_maturity_score)
  where exploit_maturity_score is not null;

comment on column advisories.cisa_kev_date is
  'Date CISA first added this CVE to the Known Exploited Vulnerabilities (KEV) catalogue. '
  'NULL means CISA has not confirmed exploitation in the wild.';

comment on column advisories.exploit_maturity_score is
  'Exploitation maturity tier: proof-of-concept | active-exploitation | widespread. '
  'Drives a +20 pt risk-engine boost when active-exploitation or widespread is set.';
