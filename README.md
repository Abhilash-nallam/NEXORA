# TOTP Two-Factor Authentication — Setup Guide

Stack: **Next.js (pages/api) + Node.js + Supabase (Postgres, free tier)**

> ⚠️ **InfinityFree note:** InfinityFree is PHP/MySQL shared hosting — it cannot run a
> Node.js/Next.js backend at all. This implementation targets **Supabase** for the
> database (Postgres, generous free tier, works natively with Node). Deploy the
> Next.js app itself on something like Vercel's free tier, which is built for it.

## 1. Install dependencies

```bash
npm install otplib qrcode bcryptjs @supabase/supabase-js
```

## 2. Create the Supabase project (free tier)

1. Go to supabase.com → New project (free tier is fine).
2. In the SQL Editor, run `db/schema.sql` from this package against your database.
   It adds 2FA columns to your `users` table and creates `backup_codes`,
   `two_factor_attempts`, and `pending_logins` tables. Adjust column names if your
   `users` table differs (e.g. if you don't already have `password_hash`).
3. Copy your project's URL and **service role key** (Settings → API) — you'll need
   both, but the service role key is secret and server-only.

## 3. Environment variables

Add to `.env.local` (never commit this file):

```
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key   # server-only, keep secret
JWT_SECRET=some-long-random-string
TOTP_ENCRYPTION_KEY=<generate below>
```

Generate `TOTP_ENCRYPTION_KEY` (32-byte hex key for AES-256-GCM):

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Store this key somewhere durable (password manager, secrets vault). If you ever
lose it, every user's stored 2FA secret becomes undecryptable and everyone with
2FA enabled will need to disable/re-enable it via backup codes or support.

## 4. Copy the files into your project

```
lib/crypto.js               → encrypt/decrypt the TOTP secret at rest
lib/totp.js                  → generate secrets, QR codes, verify codes, backup codes
lib/db.js                    → Supabase client + rate limiting (2FA codes + login attempts)
lib/backupCodes.js           → shared backup-code consumption logic
lib/session.js                → server-side opaque sessions + HttpOnly cookie handling
pages/api/2fa/setup.js
pages/api/2fa/verify-setup.js
pages/api/2fa/disable.js
pages/api/2fa/regenerate-backup-codes.js
pages/api/auth/login.js
pages/api/auth/verify-2fa.js
 pages/api/auth/logout.js
pages/api/cron/cleanup-pending-logins.js  → expired pending_logins cleanup, run on a schedule
vercel.json                   → Vercel Cron config for the cleanup job (skip if not on Vercel)
components/TwoFactorSetup.jsx   → account settings UI
components/LoginForm.jsx        → login UI
```

Add one more env var beyond the ones in step 3:

```
CRON_SECRET=<generate the same way as TOTP_ENCRYPTION_KEY>
```

If deploying to Vercel, add `CRON_SECRET` to your project's env vars — Vercel Cron automatically sends it as `Authorization: Bearer $CRON_SECRET` to routes it triggers. If you're not on Vercel, point any scheduler (cron, GitHub Actions, etc.) at `/api/cron/cleanup-pending-logins` hourly with that same header.

`lib/session.js` is a stub showing the interface (`requireAuth`, `createSessionToken`)
the routes expect — wire it to whatever session/JWT/cookie system you already use.

## 5. Wire up the UI

- Account settings page: render `<TwoFactorSetup />`.
- Login page: render `<LoginForm onLoginSuccess={(token) => { /* store cookie/redirect */ }} />`.
- Add a "Disable 2FA" button in settings that POSTs to `/api/2fa/disable` with
  `{ password, code }` — build this UI the same way as `TwoFactorSetup`, just for
  the reverse flow. Keep it as a mirror-image form (password field + code field).
  `code` can be a TOTP code or a backup code.
- Add a "Regenerate backup codes" button in settings that POSTs to
  `/api/2fa/regenerate-backup-codes` with `{ password, code }` (TOTP code only,
  not a backup code — see the comment in that file for why). Show the returned
  codes once, same UI pattern as the "done" step of `TwoFactorSetup`.

## How the login flow works

1. `POST /api/auth/login` with email + password.
   - If the user has no 2FA: a random opaque session token is generated, only its SHA-256 hash is stored server-side, and the raw token is placed in a `__Host-session` HttpOnly/Secure/SameSite=Lax cookie.
   - If 2FA is enabled: a random pending token is stored server-side and placed in a short-lived `__Host-pending-login` HttpOnly cookie. The token is never returned to JavaScript.
2. `POST /api/auth/verify-2fa` with only the 6-digit/backup code. The server reads the pending cookie, verifies it, atomically consumes it, creates the real server-side session, sets the session cookie, and clears the pending cookie.
3. Protected routes call `requireAuth`, which hashes the session cookie and looks up the live session. Expired/revoked sessions are rejected.
4. `POST /api/auth/logout` revokes the current session server-side and clears the cookie.

The browser never receives a session token or pending-login token through JSON, so application code cannot accidentally put either token into `localStorage`, `sessionStorage`, analytics, or logs.

## Security decisions explained

- **Secret encrypted at rest (AES-256-GCM)** — a raw database leak/backup alone
  isn't enough to generate valid codes; the attacker also needs `TOTP_ENCRYPTION_KEY`,
  which lives only in server env vars.
- **Backup codes are bcrypt-hashed**, shown to the user exactly once, and marked
  `used_at` (single-use) rather than deleted, so you retain an audit trail.
- **Rate limiting** (5 failed attempts / 15 min) on `two_factor_attempts` — a
  6-digit code has only 1,000,000 combinations; without this, brute-forcing it
  is realistic. This applies consistently everywhere a code is checked:
  login (`verify-2fa`), setup confirmation (`verify-setup`), disabling
  (`disable`), and backup-code regeneration — not just at login. A stolen
  session (e.g. via XSS) can't brute-force its way past 2FA at any of these
  endpoints.
- **Login itself is rate-limited too** (10 failed attempts / 15 min) on
  `login_attempts`, keyed by email — independent of whether 2FA is enabled,
  so password guessing is throttled even for accounts without 2FA on.
- **Setup requires confirmation before activation** — the secret is stored as
  "pending" until the user proves their app produces valid codes, so nobody
  locks themselves out by fat-fingering the QR scan.
- **Disabling 2FA requires password + a valid code**, not just an active
  session — protects against a hijacked session (e.g. XSS) silently turning
  protection off.
- **Constant-time-ish login** — `bcrypt.compare` always runs (even against a
  dummy hash for unknown emails) so response timing doesn't reveal which
  emails exist.

## Edge cases this handles

| Case | Behavior |
|---|---|
| User loses phone | Use a backup code to log in, then re-enable 2FA with a new device from settings (existing flow: disable → re-setup). |
| User runs out of backup codes | POST `/api/2fa/regenerate-backup-codes` with `{ password, code }` — invalidates old codes, issues 10 new ones. |
| Clock drift on user's phone | `otplib`'s `window: 1` option accepts codes from ±1 time step (30s) automatically. |
| Same code submitted twice quickly | TOTP codes are valid for their whole 30s window by design; this is standard behavior, not a bug — backup codes are single-use precisely because they don't share this property. |
| Pending login token abandoned mid-flow | Expires after 10 minutes; `pages/api/cron/cleanup-pending-logins.js` garbage-collects expired rows — schedule it (Vercel Cron config in `vercel.json`, or any external scheduler). |
| Brute-force attempts on the 6-digit code | Blocked after 5 failed attempts per 15 minutes per user, enforced at login, setup, disable, and regeneration (`lib/db.js`). |
| Brute-force attempts on the password itself | Blocked after 10 failed attempts per 15 minutes per email, independent of 2FA status (`login_attempts` table). |
| Attacker steals a live session cookie | Can't silently disable 2FA — that endpoint requires the current password too. |

## What you still need to build

- Your actual `requireAuth`/session logic in `lib/session.js` — the stub shown
  assumes a JWT in a cookie; adapt to whatever you already use.
- Basic styling for the components — they're intentionally unstyled/minimal.
- UI for "Disable 2FA" and "Regenerate backup codes" in settings (endpoints
  are done — see above for the request shape).
- Confirm your session cookie is `SameSite=Lax` or `Strict` — these are JSON
  POST endpoints and don't do their own CSRF token check, so that cookie
  setting is your CSRF defense. If you're not using cookies for the session
  (e.g. bearer tokens in a mobile app), CSRF isn't a concern here anyway.
- If you're behind Vercel/Cloudflare, consider adding edge-level IP rate
  limiting on `/api/auth/login` too — the DB-level email-based limit in this
  package holds on its own, but IP limiting adds defense in depth against
  distributed attempts across many emails from one source.
