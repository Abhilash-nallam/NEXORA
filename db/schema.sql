-- Run this in Supabase SQL Editor (or psql) against your existing `users` table.
-- Adjust `users` table name/columns if yours differ.

-- 1. Columns on the users table
alter table users
  add column if not exists two_factor_enabled boolean not null default false,
  add column if not exists two_factor_secret_encrypted text,      -- AES-256-GCM ciphertext, NEVER store plaintext
  add column if not exists two_factor_secret_iv text,             -- IV used for encryption
  add column if not exists two_factor_secret_tag text,            -- GCM auth tag
  add column if not exists two_factor_pending_secret_encrypted text, -- set during setup, before confirmation
  add column if not exists two_factor_pending_secret_iv text,
  add column if not exists two_factor_pending_secret_tag text,
  add column if not exists two_factor_confirmed_at timestamptz;

-- 2. Backup codes: one row per code, hashed, single-use
create table if not exists backup_codes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  code_hash text not null,       -- bcrypt hash of the backup code
  used_at timestamptz,           -- null until consumed
  created_at timestamptz not null default now()
);

create index if not exists idx_backup_codes_user_id on backup_codes(user_id);

-- 3. Rate limiting for 2FA verification attempts (login + setup)
create table if not exists two_factor_attempts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  attempted_at timestamptz not null default now(),
  success boolean not null
);

create index if not exists idx_2fa_attempts_user_time on two_factor_attempts(user_id, attempted_at);

-- 4. Short-lived "pending login" tokens issued after password check,
--    consumed after successful 2FA code entry. Storing server-side
--    (instead of trusting a client JWT alone) lets you revoke/expire them.
create table if not exists pending_logins (
  token text primary key,        -- random 32-byte hex string
  user_id uuid not null references users(id) on delete cascade,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

create index if not exists idx_pending_logins_expires on pending_logins(expires_at);

-- 5. Rate limiting for password attempts on /api/auth/login, keyed by
--    email (not user_id) so unknown/nonexistent emails are covered too.
create table if not exists login_attempts (
  id uuid primary key default gen_random_uuid(),
  identifier text not null,      -- lowercased email
  attempted_at timestamptz not null default now(),
  success boolean not null
);

create index if not exists idx_login_attempts_identifier_time on login_attempts(identifier, attempted_at);


-- 6. Opaque server-side sessions. The raw session token is only ever held
--    by the browser in an HttpOnly cookie; only its SHA-256 hash is stored.
create table if not exists sessions (
  id uuid primary key default gen_random_uuid(),
  token_hash text not null unique,
  user_id uuid not null references users(id) on delete cascade,
  expires_at timestamptz not null,
  revoked_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists idx_sessions_user_id on sessions(user_id);
create index if not exists idx_sessions_expires on sessions(expires_at);

-- One-time consumption guard for pending login cookies.
alter table pending_logins
  add column if not exists consumed_at timestamptz;

create index if not exists idx_pending_logins_active
  on pending_logins(token, expires_at)
  where consumed_at is null;
