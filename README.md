# NEXORA Authenticator & 2FA Engine

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Expo](https://img.shields.io/badge/Expo-57.0-000020.svg?logo=expo)](https://expo.dev)
[![React Native](https://img.shields.io/badge/React%20Native-0.86-61DAFB.svg?logo=react)](https://reactnative.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-6.0-3178C6.svg?logo=typescript)](https://www.typescriptlang.org)
[![Security Audited](https://img.shields.io/badge/Security-Audited%20%26%20Hardened-success.svg)](https://github.com/Abhilash-nallam/NEXORA)
[![Tests Passing](https://img.shields.io/badge/Tests-31%2F31%20Passed-brightgreen.svg)](https://github.com/Abhilash-nallam/NEXORA)

NEXORA is a modern, privacy-focused Two-Factor Authentication (2FA) ecosystem consisting of:

1. **A local-first, offline mobile authenticator app** (iOS & Android) engineered with zero telemetry, hardware-backed key storage, and military-grade encrypted backups.
2. **A production-ready reference 2FA backend engine** (Next.js & Supabase) implementing RFC 6238 TOTP verification, AES-256-GCM secret encryption, single-use bcrypt-hashed recovery codes, anti-replay guards, and timing-safe API endpoints.

---

## Table of Contents

- [What is NEXORA?](#what-is-nexora)
  - [Use Cases](#use-cases)
  - [Who is it for?](#who-is-it-for)
- [Key Benefits](#key-benefits)
- [Core Features](#core-features)
  - [Mobile Authenticator (iOS & Android)](#mobile-authenticator-ios--android)
  - [Server-Side 2FA Engine (Next.js / Supabase)](#server-side-2fa-engine-nextjs--supabase)
- [Security Model & Cryptographic Specs](#security-model--cryptographic-specs)
  - [Client-Side Security](#client-side-security)
  - [Server-Side Security](#server-side-security)
- [Comparison with Alternatives](#comparison-with-alternatives)
- [Project Architecture](#project-architecture)
- [Getting Started & Local Development](#getting-started--local-development)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Running the Mobile App](#running-the-mobile-app)
  - [Testing, Linting & Type Checking](#testing-linting--type-checking)
  - [Building Binaries (EAS Build)](#building-binaries-eas-build)
- [Database Setup for 2FA Backend](#database-setup-for-2fa-backend)
- [Recent Security Audit & Hardening](#recent-security-audit--hardening)
- [License](#license)

---

## What is NEXORA?

NEXORA eliminates the security compromises, tracking, and cloud vulnerabilities common in mainstream authentication apps. It provides a complete, sovereign solution for multi-factor authentication.

Unlike proprietary authenticators that lock your credentials behind vendor accounts or silently synchronize unencrypted tokens to the cloud, **NEXORA guarantees total data sovereignty**. Your authenticator keys stay strictly on your physical device, protected by OS-level cryptographic enclaves.

### Use Cases

- **Personal Account Protection:** Secure your accounts across GitHub, Google, AWS, Discord, Cloudflare, Microsoft, Binance, password managers, and any service supporting standard RFC 6238 TOTP.
- **Air-Gapped & Offline Security:** Generate time-sensitive 6-digit or 8-digit verification codes in complete isolation without cell reception, Wi-Fi, or SIM card access. Eliminates SMS-swap vulnerabilities entirely.
- **Cross-Device Encrypted Migration:** Securely migrate or clone your authentication vault across Android and iOS devices using self-sovereign `.nxb` encrypted backup files protected with your master passphrase.
- **Full-Stack 2FA Blueprint for Developers:** Drop-in, production-tested API architecture for web applications needing robust multi-factor authentication, step-up verification, rate-limiting, and disaster-recovery backup codes.

### Who is it for?

- **Privacy Advocates & Security Professionals:** Users who want zero telemetry, zero analytics, no ad tracking, and complete control over their cryptographic credentials.
- **Developers & DevOps Engineers:** Teams needing a reliable, cross-platform authenticator with support for custom algorithms (SHA-1, SHA-256, SHA-512), 8-digit codes, and variable time steps (15s to 120s).
- **Organizations & Product Builders:** Engineering teams building custom web applications who need a hardened reference backend for TOTP enrollment, validation, and session issuance.

---

## Key Benefits

| Benefit                                  | Description                                                                                                                                                                      |
| :--------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **100% Offline by Design**               | Token generation operates entirely on-device. No network requests are made during normal authenticator operation.                                                                |
| **Hardware-Backed Isolation**            | Secrets are isolated within platform-native secure hardware (`Keychain` on iOS, `KeyStore` on Android via Expo SecureStore). Account metadata is segregated from private keys.   |
| **Biometric Vault Locking**              | Protect the app with Face ID, Touch ID, Fingerprint, or device PIN. The vault locks instantly upon backgrounding.                                                                |
| **In-Memory Zeroization**                | Sensitive secrets in active memory are scrubbed as soon as the app transitions to the background or closes.                                                                      |
| **Non-Destructive Clipboard Auto-Clear** | Copied passcodes automatically self-destruct from the device clipboard after 30 seconds without overwriting unrelated user clipboard items.                                      |
| **Sovereign, Encrypted Backups**         | Backups use authenticated encryption (**XChaCha20-Poly1305**) with key derivation via **PBKDF2-HMAC-SHA256 (200,000 iterations)**. Your password is never stored or transmitted. |
| **Zero Telemetry & Tracking**            | No third-party SDKs, no trackers, no advertising IDs, no diagnostic crash reports sent to external servers.                                                                      |
| **Enterprise Server Defense**            | Server API implements AES-256-GCM secret storage, bcrypt-hashed backup codes, anti-replay single-use tokens, CSRF protection, and timing-safe token checks.                      |

---

## Core Features

### Mobile Authenticator (iOS & Android)

- **Instant QR Code Scanner:** Point and scan standard `otpauth://totp/...` QR codes using the integrated, privacy-shielded camera module.
- **Manual Account Entry:** Add custom tokens manually by entering the issuer, account name, and Base32 secret key with real-time format validation.
- **Live Countdown & Progress Ring:** Smooth visual countdown indicator reflecting the remaining validity window for active codes.
- **One-Tap Copy:** Tap any code to copy it directly to your clipboard with an on-screen toast confirmation and an automatic 30-second clipboard wipe timer.
- **Smart Categorization & Search:** Organize your vault by tags (`Personal`, `Work`, `Finance`, `Crypto`), mark favorites, and search by account or issuer name.
- **Flexible TOTP Parameters:**
  - **Hashing Algorithms:** HMAC-SHA-1, HMAC-SHA-256, HMAC-SHA-512
  - **Digit Formats:** 6-digit and 8-digit codes
  - **Time Periods:** 15-second to 120-second time steps (standard 30s default)
- **Encrypted Backup Vault (`.nxb`):**
  - Export password-protected encrypted backups directly to the device filesystem or share via native system sheets.
  - Import existing `.nxb` backups with real-time password verification and duplicate account merging.

### Server-Side 2FA Engine (Next.js / Supabase)

- **Two-Phase Enrollment (`/api/2fa/setup` & `/api/2fa/verify-setup`):** Generates cryptographically secure random secrets, stores them encrypted as pending state, and only confirms 2FA after the user successfully verifies a live code.
- **Single-Use Recovery Codes:** Generates 10 high-entropy recovery codes per user, stored strictly as one-way `bcrypt` hashes. Consumed codes are permanently invalidated.
- **Atomic Two-Factor Login (`/api/auth/login` & `/api/auth/verify-2fa`):** First-factor authentication produces an ephemeral, server-tracked pending login token. Only valid TOTP or recovery codes exchange it for an authenticated session cookie.
- **Anti-Replay & Token Expiration:** Pending login tokens feature atomic `consumed_at` locks and short expiration intervals, preventing token reuse or racing attacks.
- **Timing-Safe Cron Maintenance (`/api/cron/cleanup-pending-logins`):** Automated cleanup worker protected by constant-time bearer token validation (`crypto.timingSafeEqual`) to eliminate timing-attack side channels.
- **State-Changing CSRF Defense:** Enforces strict same-origin header verification on sensitive authentication mutations.

---

## Security Model & Cryptographic Specs

### Client-Side Security

```
+-------------------------------------------------------+
|                   NEXORA Client                       |
|                                                       |
|  +---------------------+     +---------------------+  |
|  |     AsyncStorage    |     |  Expo SecureStore   |  |
|  | (Metadata / Labels) |     |  (Hardware Enclave) |  |
|  +---------------------+     +---------------------+  |
|             |                           |             |
|             v                           v             |
|        Account IDs             Individual Secrets     |
+-------------------------------------------------------+
                           |
                           v  (On Backup Export)
+-------------------------------------------------------+
|  Passphrase + Salt (16B)                              |
|         │                                             |
|         ▼                                             |
|  PBKDF2-HMAC-SHA256 (200,000 iterations, 32-byte key) |
|         │                                             |
|         ▼                                             |
|  XChaCha20-Poly1305 (24-byte random nonce)            |
|         │                                             |
|         ▼                                             |
|  Encrypted .nxb Vault Archive                         |
+-------------------------------------------------------+
```

1. **Storage Separation:** Non-sensitive metadata (account label, issuer, period, algorithm) is kept in `AsyncStorage`. Private TOTP secrets are stored separately in `Expo SecureStore` (iOS Keychain / Android KeyStore with hardware encryption).
2. **Key Derivation (KDF):** Encrypted backup creation derives a 256-bit encryption key using `PBKDF2` over `HMAC-SHA-256` with 200,000 rounds and a 16-byte cryptographically secure salt (`expo-crypto`).
3. **Authenticated Encryption:** Backups are encrypted with **XChaCha20-Poly1305** using a unique 24-byte nonce per backup, ensuring both confidentiality and cryptographic integrity against tampering.
4. **Active Memory Zeroization:** When the app enters the background, sensitive in-memory states are immediately scrubbed, and the biometric challenge is re-armed.

### Server-Side Security

```
+-----------------------------------------------------------------+
|                        NEXORA Server API                        |
+-----------------------------------------------------------------+
        |                                       |
        v                                       v
+-------------------------------+   +-----------------------------+
|    User TOTP Secret Key       |   |    Single-Use Backup Codes  |
|                               |   |                             |
| Cipher: AES-256-GCM           |   | Hash: bcrypt                |
| Components: Ciphertext+IV+Tag |   | State: used_at timestamp    |
| Never stored in plaintext     |   | Normalized uppercase match  |
+-------------------------------+   +-----------------------------+
```

- **Symmetric Secret Encryption:** Server-stored TOTP secrets use AES-256-GCM authenticated cipher mode with independent IVs and authentication tags.
- **Backup Code Protection:** Recovery codes are hashed with `bcrypt` (work factor 10) prior to database insertion. Raw codes are shown only once upon generation.
- **Pending Login Replay Prevention:** Two-factor login handoffs use atomic single-use tokens stored in `pending_logins` with timestamp expiration and atomic consumed-flagging.

---

## Comparison with Alternatives

| Feature / Property                     | NEXORA  | Google Authenticator | Microsoft Authenticator |  Twilio Authy   |
| :------------------------------------- | :-----: | :------------------: | :---------------------: | :-------------: |
| **100% Offline by Default**            | **Yes** |       Partial        |           No            |       No        |
| **Zero Telemetry / Trackers**          | **Yes** |          No          |           No            |       No        |
| **Open Source & Audited**              | **Yes** |          No          |           No            |       No        |
| **Hardware Enclave Storage**           | **Yes** |         Yes          |           Yes           |       Yes       |
| **Encrypted Offline Backups (`.nxb`)** | **Yes** | No (Cloud QR export) |     Cloud sync only     | Cloud sync only |
| **Custom Password for Backups**        | **Yes** |         N/A          |           N/A           |       Yes       |
| **In-Memory Secret Zeroization**       | **Yes** |       Unknown        |         Unknown         |     Unknown     |
| **Auto-Clearing Clipboard (30s)**      | **Yes** |          No          |           No            |       No        |
| **Biometric / PIN App Lock**           | **Yes** |         Yes          |           Yes           |       Yes       |
| **Custom Algorithms (SHA-256/512)**    | **Yes** |   No (SHA-1 only)    |         Limited         |       No        |
| **Configurable Time Step (15s–120s)**  | **Yes** |    No (30s fixed)    |     No (30s fixed)      | No (30s fixed)  |
| **Includes 2FA Server Backend**        | **Yes** |          No          |           No            |       No        |

---

## Project Architecture

```
NEXORA/
├── App.tsx                     # React Native / Expo Mobile Authenticator root
├── app.json                    # Expo project configuration and native permissions
├── src/
│   └── backup.ts               # XChaCha20-Poly1305 + PBKDF2 backup encryption engine
├── lib/
│   ├── crypto.js               # Server-side AES-256-GCM cryptographic utilities
│   ├── totp.js                 # Server-side RFC 6238 TOTP generation & verification
│   ├── backupCodes.js          # Bcrypt backup code generation & verification
│   ├── session.js              # Session cookie handling & CSRF verification
│   └── db.js                   # Supabase database client wrapper
├── pages/api/
│   ├── 2fa/
│   │   ├── setup.js            # Initial TOTP secret generation & QR code
│   │   ├── verify-setup.js     # Step-up verification & backup code issue
│   │   ├── disable.js          # 2FA deactivation with code confirmation
│   │   └── regenerate-backup-codes.js # Backup code reissuance
│   ├── auth/
│   │   ├── login.js            # Credential check & pending login token issue
│   │   ├── logout.js           # Session revocation & cookie wipe
│   │   └── verify-2fa.js       # TOTP/backup code validation & session creation
│   └── cron/
│       └── cleanup-pending-logins.js # Automated expired token purger
├── db/
│   └── schema.sql              # PostgreSQL / Supabase database migration schema
└── __tests__/
    └── security.test.ts        # Comprehensive security test suite (Jest)
```

---

## Getting Started & Local Development

### Prerequisites

- **Node.js:** v18.x or v20.x LTS
- **Package Manager:** `npm` (v9+)
- **Mobile Environment:** Expo Go app or an iOS Simulator / Android Emulator
- **Optional CLI:** [Expo CLI](https://docs.expo.dev/more/expo-cli/) and [EAS CLI](https://docs.expo.dev/eas/) (`npm install -g eas-cli`)

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/Abhilash-nallam/NEXORA.git
   cd NEXORA
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

### Running the Mobile App

Start the Expo development server:

```bash
npm run start
```

Target a specific platform:

```bash
# Launch Android Emulator
npm run android

# Launch iOS Simulator (macOS only)
npm run ios

# Launch Web preview
npm run web
```

### Testing, Linting & Type Checking

Run all verification checks:

```bash
# Execute Jest test suite
npm test

# Run TypeScript type verification
npm run typecheck

# Run ESLint analysis
npm run lint

# Comprehensive check (typecheck + lint + test)
npm run check
```

### Building Binaries (EAS Build)

To produce standalone installable APK or iOS IPA files:

```bash
# Configure your EAS project
eas init

# Build Android preview APK
eas build --platform android --profile preview

# Build production app bundle (Google Play / Apple App Store)
eas build --platform all --profile production
```

---

## Database Setup for 2FA Backend

If you are using the Next.js server-side 2FA routes:

1. Open your PostgreSQL instance or [Supabase Dashboard](https://supabase.com).
2. Execute the migration script located at [`db/schema.sql`](./db/schema.sql).
3. Set the required environment variables:
   ```env
   # Server-side 2FA Encryption Key (Must be 32 bytes hex or 64 hex chars)
   TWO_FACTOR_ENCRYPTION_KEY="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

   # Supabase Configuration
   NEXT_PUBLIC_SUPABASE_URL="https://your-project.supabase.co"
   SUPABASE_SERVICE_ROLE_KEY="your-service-role-key"

   # Internal Maintenance Token
   CRON_SECRET="your-high-entropy-cron-secret-token"
   ```

---

## Recent Security Audit & Hardening

The repository has undergone a comprehensive code security audit and regression hardening across client and server components:

1. **Anti-Replay Pending Login Tokens:** Enforced atomic `consumed_at` validation on pending login tokens to eliminate race conditions and prevent burning backup codes against expired sessions.
2. **Case-Insensitive Backup Code Normalization:** Normalized backup codes prior to bcrypt verification across setup, disable, and login routes.
3. **Timing-Safe Cron Maintenance:** Replaced basic string comparisons on `CRON_SECRET` with constant-time `crypto.timingSafeEqual` buffers to prevent timing side-channel attacks.
4. **Origin & Referer CSRF Verification:** Integrated strict origin validation on state-changing API endpoints and guaranteed cookie revocation on logout.
5. **In-Memory Secret Zeroization:** Added immediate React memory state scrubbing on application background events.
6. **Non-Destructive Clipboard Clearing:** Added verification to ensure the clipboard auto-clear timeout only removes the specific OTP passcode copied, without wiping new clipboard entries.
7. **RFC 4648 Base32 Secret Sanitization:** Aligned client-side Base32 regex validation to allow standard keys down to 7 characters.

All 31 test suites across cryptographic modules, authentication pipelines, and state handlers pass with zero regressions.

---

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for full details.
