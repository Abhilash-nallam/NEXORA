# NEXORA Password Vault — implementation notes

## What this branch adds

- A Password Vault screen reachable from the key icon on the authenticator home screen.
- Create, search, reveal/hide, edit, copy, and delete password entries.
- Entry fields: title, username/email, password, website, category, and notes.
- A random 256-bit device key stored in Expo SecureStore with OS authentication required.
- XChaCha20-Poly1305 authenticated encryption with a fresh 192-bit nonce for each saved vault snapshot.
- Only the encrypted vault envelope is persisted in AsyncStorage. Plaintext entries exist in memory only while the screen is unlocked.
- No master password is introduced. Existing TOTP authenticator behavior is retained.

## Important security and recovery limits

This first implementation is **device-local**. The key is device-bound and is not uploaded or synchronized. Reinstalling the app, losing the device, or OS biometric/key invalidation may make the vault unrecoverable unless a separately designed encrypted export/recovery flow is added. Do not promise cross-device recovery yet.

Google Sign-In is not wired into this branch. The repository does not currently provide an Expo OAuth flow or configured Google OAuth client IDs / redirect URIs. Adding a button that pretends to authenticate, or treating Google identity as the vault-encryption key, would be unsafe. Google Sign-In should be added as identity only after OAuth client IDs, redirect URIs, and the account/session storage policy are configured. It must not give the server plaintext vault contents.

## Before production release

- Add and run unit tests for vault encryption/decryption, corrupted-envelope handling, and persistence.
- Test Android and iOS biometric/key invalidation behavior on physical devices.
- Add clipboard auto-clear and platform-specific screen-capture protection for password reveal.
- Decide on a tested encrypted export/recovery design. Biometrics alone cannot recover a device-bound key on a replacement phone.
- Add Google OAuth/Supabase session integration only with real project configuration, redirect URI allowlists, and token validation.
- Run `npm ci`, `npm run typecheck`, `npm run lint`, and `npm test` on the branch before release.
