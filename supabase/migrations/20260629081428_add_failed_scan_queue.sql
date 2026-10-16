-- Failed Scan Queue (Dead-Letter Queue)
--
-- Captures scan jobs that fail or remain queued too long so they can be
-- retried with exponential backoff. After 5 failed attempts the job is
-- marked abandoned and an alert is emitted to the owning org.
--
-- Columns:
--   id              — surrogate primary key
--   scan_id         — the analysis_jobs.id that failed
--   job_id          — redundant human-readable alias (same value, kept for
--                     clarity in dashboards / CLI queries)
--   org_id          — owning organisation (may be NULL for anonymous scans)
--   ecosystem       — npm | pypi | crates | go
--   package_name    — package that was being scanned
--   version         — version that was being scanned
--   error_reason    — last error message or 'timeout' sentinel
--   failure_count   — how many times this scan has been attempted
--   last_attempt_at — timestamp of the most recent attempt
--   next_retry_at   — when the worker should attempt the next retry
--   status          — pending | retrying | abandoned | resolved
--   metadata        — arbitrary jsonb bag for extra context (headers, env, etc.)
--   created_at      — when the entry was first inserted
--   expires_at      — TTL column: purge after 30 days OR failure_count >= 5

create table if not exists failed_scan_queue (
  id               uuid         primary key default gen_random_uuid(),
  scan_id          text         not null,
  job_id           text         not null,
  org_id           text,
  ecosystem        text         not null,
  package_name     text         not null,
  version          text         not null,
  error_reason     text         not null default 'unknown',
  failure_count    integer      not null default 1,
  last_attempt_at  timestamptz  not null default now(),
  next_retry_at    timestamptz  not null default now(),
  status           text         not null default 'pending'
    check (status in ('pending', 'retrying', 'abandoned', 'resolved')),
  metadata         jsonb        not null default '{}'::jsonb,
  created_at       timestamptz  not null default now(),
  -- TTL: 30-day hard expiry
  expires_at       timestamptz  not null default (now() + interval '30 days')
);

-- Unique on the underlying scan so duplicate failure inserts upsert cleanly
create unique index if not exists failed_scan_queue_scan_id_idx
  on failed_scan_queue (scan_id);

-- Worker polls this: pending/retrying rows where next_retry_at is due
create index if not exists failed_scan_queue_ready_idx
  on failed_scan_queue (next_retry_at asc)
  where status in ('pending', 'retrying');

-- Org-scoped dashboard queries
create index if not exists failed_scan_queue_org_idx
  on failed_scan_queue (org_id, created_at desc)
  where org_id is not null;

-- Abandoned scans alert feed
create index if not exists failed_scan_queue_abandoned_idx
  on failed_scan_queue (created_at desc)
  where status = 'abandoned';

-- TTL cleanup: a pg_cron or maintenance job can DELETE WHERE expires_at < now()
create index if not exists failed_scan_queue_expires_idx
  on failed_scan_queue (expires_at asc);

comment on table failed_scan_queue is
  'Dead-letter queue for scan jobs that fail or remain queued too long. '
  'Entries are retried with exponential backoff. After 5 attempts the status '
  'transitions to ''abandoned'' and an org-level alert is emitted. '
  'Rows are automatically eligible for purge after 30 days (expires_at).';

comment on column failed_scan_queue.failure_count is
  'Number of times this scan has been attempted (including the initial failure). '
  'When this reaches 5 the status is set to ''abandoned''.';

comment on column failed_scan_queue.next_retry_at is
  'Exponential backoff schedule: 1 s → 4 s → 16 s → 60 s → 300 s.';

comment on column failed_scan_queue.metadata is
  'Arbitrary context bag. Typical keys: retry_attempt, worker_id, '
  'original_status, alert_sent.';

-- ---------------------------------------------------------------------------
-- scan_audit_log — compliance trail for all retry attempts
-- ---------------------------------------------------------------------------
-- Stores one row per retry event so operators can audit the full retry
-- lifecycle for any scan.

create table if not exists scan_audit_log (
  id               uuid         primary key default gen_random_uuid(),
  scan_id          text         not null,
  org_id           text,
  event_type       text         not null
    check (event_type in (
      'scan_queued',
      'scan_timeout',
      'scan_failed',
      'retry_scheduled',
      'retry_attempted',
      'retry_succeeded',
      'scan_abandoned',
      'alert_sent'
    )),
  retry_attempt    integer      not null default 0,
  details          jsonb        not null default '{}'::jsonb,
  created_at       timestamptz  not null default now()
);

create index if not exists scan_audit_log_scan_id_idx
  on scan_audit_log (scan_id, created_at desc);

create index if not exists scan_audit_log_org_idx
  on scan_audit_log (org_id, created_at desc)
  where org_id is not null;

comment on table scan_audit_log is
  'Immutable compliance audit trail for scan retry lifecycle events. '
  'Each row captures a single event (queued, timed-out, retry, abandon, etc.) '
  'with its retry attempt number and arbitrary details jsonb.';
