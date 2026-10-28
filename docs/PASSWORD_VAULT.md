# NEXORA Password Vault and Encrypted Cloud Recovery

## Local vault

- The mobile app retains the TOTP authenticator and adds password entries (title, username, password, website, category, and notes).
- A random 256-bit vault key is protected by Expo SecureStore and the operating system's authentication gate.
- Password entries are encrypted with XChaCha20-Poly1305 using a fresh 192-bit nonce for each saved snapshot. Only the encrypted envelope is persisted in AsyncStorage.
- No master password is required for normal use. The app's device authentication still protects access to the local key.

## Google Sign-In and cloud recovery

The app uses Supabase Auth's Google OAuth provider with PKCE. Google proves identity; it is **not** used as an encryption key. The mobile app must use only the Supabase project URL and publishable/anon key. Never put a Supabase service-role key or Google OAuth client secret in the mobile app.

When the user enables encrypted cloud recovery, NEXORA generates a random 256-bit recovery key and shows it once. The key is not uploaded or stored by NEXORA. It derives a wrapping key with PBKDF2-HMAC-SHA256 (250,000 iterations), which encrypts the local vault key using XChaCha20-Poly1305. Supabase stores only the already-encrypted vault snapshot and the wrapped vault key, with row-level security restricting access to the authenticated user's own row.

On a new device, the user signs in to the same Google account and enters the recovery key. The app unwraps the vault key locally, validates that it can decrypt the downloaded snapshot, and only then replaces local vault storage. A wrong key or invalid ciphertext should not replace the local vault.

**Recovery key is not a master password, but it is still a critical recovery secret.** Save it somewhere private and separate from the phone. If it is lost, Google sign-in alone cannot decrypt the vault. Anyone with both the Google account session and the recovery key can recover the vault. Do not paste the recovery key into chats, tickets, or public issues.

Cloud recovery covers the password vault only. TOTP secrets remain in the existing authenticator's local SecureStore and its existing encrypted backup/export flow; this feature does not upload TOTP secrets.

## Required setup

1. In the Supabase project, enable **Authentication → Providers → Google** and configure the Google OAuth client ID and client secret there.
2. In Google Cloud Console, add the callback URL shown by Supabase (normally `https://<project-ref>.supabase.co/auth/v1/callback`) to the Google OAuth client's authorized redirect URIs.
3. In Supabase **Authentication → URL Configuration**, add `nexora://auth/callback` to the allowed redirect URLs.
4. Set these public mobile build-time variables:
   - `EXPO_PUBLIC_SUPABASE_URL=https://<project-ref>.supabase.co`
   - `EXPO_PUBLIC_SUPABASE_ANON_KEY=<publishable-or-anon-key>`
5. Run `db/migrations/20261028_password_vault_cloud.sql` in the Supabase SQL editor. It creates the encrypted-vault table and user-scoped RLS policies.
6. Rebuild/restart the Expo app after setting the environment variables.

Do not add secrets to Git. The Google client secret belongs only in Supabase's provider configuration. Do not use the service-role key in the app.

## Validation before production

- Run `npm install`, `npm run typecheck`, `npm run lint`, and `npm test -- --runInBand`.
- Verify Google sign-in on a physical Android device with the production Supabase redirect allowlist.
- Test initial recovery setup, syncing after create/edit/delete, wrong recovery key, restore on a clean second device, account mismatch, offline failures, and expired/rotated OAuth sessions.
- Confirm that a failed restore never overwrites existing local entries.
- Test Android and iOS biometric/key invalidation behavior on physical devices.
- Verify Supabase RLS by attempting to read/update another user's row; it must be denied.
- Do not advertise the app as production-ready until CI passes and these device/cloud tests are completed.
