-- NEXORA encrypted password-vault recovery.
-- Run this migration in the Supabase project used by the mobile app.
-- Only authenticated users may read/write their own encrypted envelope.
-- Passwords and the unwrapped vault key are never stored in this table.

create table if not exists public.nexora_password_vaults (
  user_id uuid primary key references auth.users(id) on delete cascade,
  encrypted_vault jsonb not null,
  recovery_salt text not null,
  key_nonce text not null,
  wrapped_key text not null,
  updated_at timestamptz not null default now()
);

alter table public.nexora_password_vaults enable row level security;

revoke all on table public.nexora_password_vaults from anon;
grant select, insert, update on table public.nexora_password_vaults to authenticated;

drop policy if exists "Users can read their own encrypted NEXORA vault" on public.nexora_password_vaults;
create policy "Users can read their own encrypted NEXORA vault"
  on public.nexora_password_vaults
  for select to authenticated
  using ((select auth.uid()) = user_id);

drop policy if exists "Users can create their own encrypted NEXORA vault" on public.nexora_password_vaults;
create policy "Users can create their own encrypted NEXORA vault"
  on public.nexora_password_vaults
  for insert to authenticated
  with check ((select auth.uid()) = user_id);

drop policy if exists "Users can update their own encrypted NEXORA vault" on public.nexora_password_vaults;
create policy "Users can update their own encrypted NEXORA vault"
  on public.nexora_password_vaults
  for update to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);
