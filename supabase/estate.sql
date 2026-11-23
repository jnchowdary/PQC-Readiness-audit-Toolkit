-- Diarka PQC: estate scan leads (whole-organisation reports).
-- Run once in Supabase: SQL Editor > New query > paste > Run. Safe to re-run.

create table if not exists public.estate_scans (
  id               uuid primary key default gen_random_uuid(),
  created_at       timestamptz not null default now(),

  -- who asked (the domain scanned is always taken from this email)
  email            text not null unique check (email = lower(email)),   -- one estate scan per email
  email_domain     text not null,
  domain           text not null,

  -- what was found
  result           jsonb not null,           -- every host checked, plus the summary
  endpoints        int,                      -- hosts scanned, for quick sorting
  pq_ready         int,                      -- hosts with post-quantum key exchange
  classical_only   int,                      -- hosts with classical key exchange only

  -- the private report link
  report_token     text not null unique,
  last_sent_at     timestamptz,
  resend_count     int not null default 0,
  report_views     int not null default 0,
  first_viewed_at  timestamptz,

  -- abuse control (salted hash, the raw IP is never stored)
  ip_hash          text,

  -- your pipeline tracking, edit by hand in the Table Editor
  status           text not null default 'new'
                   check (status in ('new','contacted','call booked','proposal','won','lost','not a fit')),
  notes            text,
  opted_out        boolean not null default false
);

create index if not exists estate_scans_ip_recent on public.estate_scans (ip_hash, created_at);
create index if not exists estate_scans_created   on public.estate_scans (created_at desc);

-- Locked: no policies, so the public key can't read or write it.
alter table public.estate_scans enable row level security;
revoke all on table public.estate_scans from anon, authenticated;
grant select, insert, update, delete on table public.estate_scans to service_role;
