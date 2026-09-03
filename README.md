# NEXORA Authenticator

NEXORA is a local-first TOTP authenticator for Android/iOS.

## Security model

- TOTP secrets are stored individually in the OS-backed Expo SecureStore.
- Account metadata is stored in AsyncStorage and contains no TOTP secret.
- Optional biometric/device-credential app lock is provided by Expo LocalAuthentication.
- TOTP generation is offline after a secret has been added.
- Encrypted backups use PBKDF2-HMAC-SHA256 and XChaCha20-Poly1305. The backup password is never stored.
- QR scanning is limited to `otpauth://totp/...` codes.

## Supported TOTP parameters

SHA-1, SHA-256 and SHA-512; 6 or 8 digits; 15–120 second periods.

## Build

Install dependencies with `npm install`, then use EAS with the `preview` profile for an installable APK or `production` for a store-oriented build.

The app does not require Supabase, an account, or a network connection to generate codes.
