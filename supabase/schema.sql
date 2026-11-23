-- Diarka PQC Quick Check: lead table.
-- Run once in Supabase: SQL Editor > New query > paste > Run.

create table if not exists public.leads (
  id               uuid primary key default gen_random_uuid(),
  created_at       timestamptz not null default now(),

  -- who asked
  email            text not null unique check (email = lower(email)),  -- one report per email
  email_domain     text not null,

  -- what they checked
  domain           text not null,
  result           jsonb not null,          -- full server-side scan result
  pqc_key_exchange boolean,                 -- true / false / null (not confirmed), for quick filtering

  -- the private report link
  report_token     text not null unique,
  last_sent_at     timestamptz,
  resend_count     int not null default 0,
  report_views     int not null default 0,  -- did they open it? a strong follow-up signal
  first_viewed_at  timestamptz,

  -- abuse control (salted hash, the raw IP is never stored)
  ip_hash          text,

  -- your own pipeline tracking, edit these by hand in the Table Editor
  status           text not null default 'new'
                   check (status in ('new','contacted','call booked','proposal','won','lost','not a fit')),
  notes            text,
  opted_out        boolean not null default false
);

create index if not exists leads_ip_recent on public.leads (ip_hash, created_at);
create index if not exists leads_created   on public.leads (created_at desc);

-- Lock the table. With RLS on and no policies, the public (publishable/anon)
-- key can neither read nor write it. Only the server's secret key can.
alter table public.leads enable row level security;

-- Explicit grants. Newer Supabase projects can be created with "Grant API
-- access to new tables automatically" switched off, in which case the server
-- role has no rights on this table and every API call fails with
-- "permission denied". Only the server's secret key (service_role) gets access;
-- the public roles get none.
grant select, insert, update, delete on table public.leads to service_role;
revoke all on table public.leads from anon, authenticated;
