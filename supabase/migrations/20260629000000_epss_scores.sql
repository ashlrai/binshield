-- EPSS (Exploit Prediction Scoring System) score enrichment.
--
-- Stores per-CVE EPSS scores fetched from the Cyentia/FIRST feed
-- (https://www.first.org/epss/data) alongside their associated package so
-- risk-correlation queries can join directly on (ecosystem, package_name,
-- version, cve_id) without joining through advisories.
--
-- EPSS score    — probability [0,1] the CVE will be exploited in the next 30d
-- EPSS percentile — rank among all scored CVEs [0,1]
--
-- A percentile > 0.75 means "top-25% most-likely-to-be-exploited" and
-- triggers a 15-pt risk boost in the risk engine.  A percentile > 0.90
-- triggers an "Exploited in the Wild" badge in the UI / GH Action output.

create table if not exists epss_scores (
  id            uuid primary key default gen_random_uuid(),
  cve_id        text not null,
  package_name  text not null,
  ecosystem     text not null,
  version       text not null default '',
  epss_score    numeric(10,8) not null check (epss_score >= 0 and epss_score <= 1),
  epss_percentile numeric(10,8) not null check (epss_percentile >= 0 and epss_percentile <= 1),
  model_version text not null default '',
  score_date    date not null default current_date,
  updated_at    timestamptz not null default now()
);

-- Primary lookup: given a (package, ecosystem, version) find all CVE EPSS rows
create index if not exists epss_pkg_lookup_idx
  on epss_scores (ecosystem, package_name, version);

-- CVE-first lookup: sync worker updates by CVE ID
create index if not exists epss_cve_idx
  on epss_scores (cve_id);

-- Unique constraint: one EPSS row per (cve, package, ecosystem, version, score_date)
-- so upserts are idempotent and we keep a daily history
create unique index if not exists epss_scores_dedup_idx
  on epss_scores (cve_id, package_name, ecosystem, version, score_date);

alter table epss_scores enable row level security;

-- Service-role-only access (API backend / worker); no direct user access needed
drop policy if exists epss_scores_service_access on epss_scores;
create policy epss_scores_service_access
on epss_scores
for all
using (auth.role() = 'service_role')
with check (auth.role() = 'service_role');

-- Auto-update updated_at
drop trigger if exists epss_scores_set_updated_at on epss_scores;
create trigger epss_scores_set_updated_at
before update on epss_scores
for each row execute function set_updated_at();

comment on table epss_scores is
  'Per-CVE EPSS (Exploit Prediction Scoring System) scores from the Cyentia/FIRST feed. '
  'Enriches advisory/CVSS data with real-world exploit probability.';
comment on column epss_scores.epss_score is
  'Probability [0,1] that the CVE will be exploited in the next 30 days (from FIRST EPSS feed).';
comment on column epss_scores.epss_percentile is
  'Rank among all EPSS-scored CVEs. >0.75 = high real-world threat; >0.90 = exploited in the wild.';
