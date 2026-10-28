import * as Crypto from 'expo-crypto';
import { Linking } from 'react-native';
import * as SecureStore from 'expo-secure-store';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { pbkdf2Async } from '@noble/hashes/pbkdf2.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { savePasswordEntries } from './passwordVault';
import {
  getEncryptedPasswordVaultSnapshot,
  storeRecoveredPasswordVault,
  type PasswordVaultEnvelope,
} from './passwordVault';

const SESSION_ACCESS = 'nexora.google.access-token.v1';
const SESSION_REFRESH = 'nexora.google.refresh-token.v1';
const SESSION_EXPIRY = 'nexora.google.expires-at.v1';
const SESSION_USER = 'nexora.google.user.v1';
const PKCE_VERIFIER = 'nexora.google.pkce-verifier.v1';
const RECOVERY_META = 'nexora.password-vault.recovery-envelope.v1';
const REDIRECT_URI = 'nexora://auth/callback';
const RECOVERY_ITERATIONS = 250_000;

type AuthUser = { id: string; email?: string };
export type GoogleSession = { user: AuthUser; accessToken: string; refreshToken: string; expiresAt: number };
type RecoveryMetadata = { salt: string; nonce: string; wrappedKey: string };
type CloudRow = {
  user_id: string;
  encrypted_vault: PasswordVaultEnvelope;
  recovery_salt: string;
  key_nonce: string;
  wrapped_key: string;
  updated_at: string;
};

function config() {
  const url = process.env.EXPO_PUBLIC_SUPABASE_URL?.replace(/\/$/, '');
  const anonKey = process.env.EXPO_PUBLIC_SUPABASE_ANON_KEY;
  if (!url || !anonKey) {
    throw new Error('Cloud recovery is not configured. Set EXPO_PUBLIC_SUPABASE_URL and EXPO_PUBLIC_SUPABASE_ANON_KEY, then enable Google in Supabase Auth.');
  }
  return { url, anonKey };
}

function base64Url(bytes: Uint8Array): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let output = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const hasB = i + 1 < bytes.length;
    const hasC = i + 2 < bytes.length;
    const b = hasB ? bytes[i + 1] : 0;
    const c = hasC ? bytes[i + 2] : 0;
    output += alphabet[a >> 2];
    output += alphabet[((a & 3) << 4) | (b >> 4)];
    output += hasB ? alphabet[((b & 15) << 2) | (c >> 6)] : '=';
    output += hasC ? alphabet[c & 63] : '=';
  }
  return output.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function parseQuery(url: string): Record<string, string> {
  const question = url.indexOf('?');
  if (question < 0) return {};
  const hash = url.indexOf('#', question);
  const query = url.slice(question + 1, hash < 0 ? undefined : hash);
  return query.split('&').reduce<Record<string, string>>((result, pair) => {
    if (!pair) return result;
    const split = pair.indexOf('=');
    const key = split < 0 ? pair : pair.slice(0, split);
    const value = split < 0 ? '' : pair.slice(split + 1);
    result[decodeURIComponent(key.replace(/\+/g, ' '))] = decodeURIComponent(value.replace(/\+/g, ' '));
    return result;
  }, {});
}

async function storeSession(data: any): Promise<GoogleSession> {
  if (typeof data?.access_token !== 'string' || typeof data?.refresh_token !== 'string' ||
      typeof data?.user?.id !== 'string') {
    throw new Error('Google sign-in returned an incomplete session.');
  }
  const expiresAt = Date.now() + Math.max(0, Number(data.expires_in) || 3600) * 1000;
  await Promise.all([
    SecureStore.setItemAsync(SESSION_ACCESS, data.access_token),
    SecureStore.setItemAsync(SESSION_REFRESH, data.refresh_token),
    SecureStore.setItemAsync(SESSION_EXPIRY, String(expiresAt)),
    SecureStore.setItemAsync(SESSION_USER, JSON.stringify({ id: data.user.id, email: data.user.email || '' })),
  ]);
  return {
    user: { id: data.user.id, email: data.user.email || '' },
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresAt,
  };
}

async function authRequest(path: string, body: Record<string, unknown>) {
  const { url, anonKey } = config();
  const response = await fetch(`${url}/auth/v1/${path}`, {
    method: 'POST',
    headers: { apikey: anonKey, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(typeof data.message === 'string' ? data.message : 'Supabase authentication failed.');
  return data;
}

/** Starts Google OAuth using Supabase Auth PKCE; Google client secrets stay in Supabase, never in the app. */
export async function signInWithGoogle(): Promise<GoogleSession> {
  const { url, anonKey } = config();
  const verifier = bytesToHex(Crypto.getRandomBytes(32));
  const challengeHex = await Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA256, verifier, {
    encoding: Crypto.CryptoEncoding.HEX,
  });
  const challenge = base64Url(hexToBytes(challengeHex));
  const state = bytesToHex(Crypto.getRandomBytes(16));
  const redirect = `${REDIRECT_URI}?state=${state}`;
  await SecureStore.setItemAsync(PKCE_VERIFIER, verifier);

  const authorize = `${url}/auth/v1/authorize?provider=google&redirect_to=${encodeURIComponent(redirect)}&code_challenge=${encodeURIComponent(challenge)}&code_challenge_method=s256`;
  return new Promise<GoogleSession>((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error, session?: GoogleSession) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      subscription.remove();
      if (error) reject(error);
      else if (session) resolve(session);
      else reject(new Error('Google sign-in did not complete.'));
    };
    const subscription = Linking.addEventListener('url', ({ url: callbackUrl }) => {
      if (!callbackUrl.startsWith(REDIRECT_URI)) return;
      void (async () => {
        try {
          const params = parseQuery(callbackUrl);
          if (params.state !== state) throw new Error('Sign-in verification failed. Please try again.');
          if (params.error || params.error_description) {
            throw new Error(params.error_description || params.error || 'Google sign-in was cancelled.');
          }
          if (!params.code) throw new Error('No authorization code was returned.');
          const savedVerifier = await SecureStore.getItemAsync(PKCE_VERIFIER);
          if (!savedVerifier || savedVerifier !== verifier) throw new Error('Sign-in session expired. Please try again.');
          const tokens = await authRequest('token?grant_type=pkce', {
            auth_code: params.code,
            code_verifier: savedVerifier,
          });
          await SecureStore.deleteItemAsync(PKCE_VERIFIER);
          finish(undefined, await storeSession(tokens));
        } catch (error) {
          await SecureStore.deleteItemAsync(PKCE_VERIFIER).catch(() => undefined);
          finish(error instanceof Error ? error : new Error('Google sign-in failed.'));
        }
      })();
    });
    const timeout = setTimeout(() => {
      void SecureStore.deleteItemAsync(PKCE_VERIFIER);
      finish(new Error('Google sign-in timed out. Please try again.'));
    }, 180_000);
    void Linking.openURL(authorize).catch((error) => {
      finish(error instanceof Error ? error : new Error('Could not open Google sign-in.'));
    });
  });
}

export async function getGoogleSession(): Promise<GoogleSession | null> {
  const [accessToken, refreshToken, expiryRaw, userRaw] = await Promise.all([
    SecureStore.getItemAsync(SESSION_ACCESS),
    SecureStore.getItemAsync(SESSION_REFRESH),
    SecureStore.getItemAsync(SESSION_EXPIRY),
    SecureStore.getItemAsync(SESSION_USER),
  ]);
  if (!refreshToken || !userRaw) return null;
  let user: AuthUser;
  try { user = JSON.parse(userRaw) as AuthUser; } catch { return null; }
  if (accessToken && Number(expiryRaw) > Date.now() + 60_000) {
    return { user, accessToken, refreshToken, expiresAt: Number(expiryRaw) };
  }
  const data = await authRequest('token?grant_type=refresh_token', { refresh_token: refreshToken });
  return storeSession(data);
}

export async function signOutGoogle(): Promise<void> {
  const { url, anonKey } = config();
  const accessToken = await SecureStore.getItemAsync(SESSION_ACCESS);
  if (accessToken) {
    await fetch(`${url}/auth/v1/logout`, {
      method: 'POST',
      headers: { apikey: anonKey, Authorization: `Bearer ${accessToken}` },
    }).catch(() => undefined);
  }
  await Promise.all([
    SecureStore.deleteItemAsync(SESSION_ACCESS),
    SecureStore.deleteItemAsync(SESSION_REFRESH),
    SecureStore.deleteItemAsync(SESSION_EXPIRY),
    SecureStore.deleteItemAsync(SESSION_USER),
  ]);
}

type CloudRequestOptions = { method?: string; headers?: Record<string, string>; body?: string };

async function cloudRequest(path: string, init: CloudRequestOptions = {}) {
  const { url, anonKey } = config();
  const session = await getGoogleSession();
  if (!session) throw new Error('Sign in with Google before using cloud recovery.');
  const response = await fetch(`${url}/rest/v1/${path}`, {
    ...init,
    headers: {
      apikey: anonKey,
      Authorization: `Bearer ${session.accessToken}`,
      'Content-Type': 'application/json',
      ...(init.headers || {}),
    },
  });
  const body = await response.text();
  if (!response.ok) throw new Error(body ? `Cloud recovery request failed (${response.status}).` : 'Cloud recovery request failed.');
  return body ? JSON.parse(body) : null;
}

async function getRecoveryMetadata(): Promise<RecoveryMetadata | null> {
  const raw = await AsyncStorage.getItem(RECOVERY_META);
  if (!raw) return null;
  try {
    const value = JSON.parse(raw) as RecoveryMetadata;
    if (typeof value.salt === 'string' && typeof value.nonce === 'string' && typeof value.wrappedKey === 'string') return value;
  } catch { /* invalid local metadata is treated as absent */ }
  return null;
}

export async function hasLocalRecoveryEnabled(): Promise<boolean> {
  return Boolean(await getRecoveryMetadata());
}

export async function enableEncryptedCloudRecovery(vaultKey: Uint8Array): Promise<string> {
  if (vaultKey.length !== 32) throw new Error('The local vault key is invalid.');
  const recoveryCode = bytesToHex(Crypto.getRandomBytes(32));
  const salt = Crypto.getRandomBytes(16);
  const nonce = Crypto.getRandomBytes(24);
  const wrappingKey = await pbkdf2Async(sha256, recoveryCode, salt, { c: RECOVERY_ITERATIONS, dkLen: 32 });
  const wrappedKey = xchacha20poly1305(wrappingKey, nonce).encrypt(vaultKey);
  const metadata: RecoveryMetadata = {
    salt: bytesToHex(salt),
    nonce: bytesToHex(nonce),
    wrappedKey: bytesToHex(wrappedKey),
  };
  await AsyncStorage.setItem(RECOVERY_META, JSON.stringify(metadata));
  try {
    let snapshot = await getEncryptedPasswordVaultSnapshot();
    if (!snapshot) {
      await savePasswordEntries(vaultKey, []);
      snapshot = await getEncryptedPasswordVaultSnapshot();
    }
    if (!snapshot) throw new Error('Could not prepare an encrypted vault snapshot.');
    const session = await getGoogleSession();
    if (!session) throw new Error('Sign in with Google before enabling cloud recovery.');
    await cloudRequest('nexora_password_vaults?on_conflict=user_id', {
      method: 'POST',
      headers: { Prefer: 'resolution=merge-duplicates,return=minimal' },
      body: JSON.stringify({
        user_id: session.user.id,
        encrypted_vault: snapshot,
        recovery_salt: metadata.salt,
        key_nonce: metadata.nonce,
        wrapped_key: metadata.wrappedKey,
        updated_at: new Date().toISOString(),
      }),
    });
    return recoveryCode;
  } catch (error) {
    await AsyncStorage.removeItem(RECOVERY_META);
    throw error;
  }
}

export async function syncEncryptedCloudVault(): Promise<void> {
  const metadata = await getRecoveryMetadata();
  if (!metadata) throw new Error('Enable encrypted cloud recovery first.');
  const snapshot = await getEncryptedPasswordVaultSnapshot();
  if (!snapshot) throw new Error('There is no saved vault snapshot to sync.');
  const session = await getGoogleSession();
  if (!session) throw new Error('Sign in with Google before syncing.');
  await cloudRequest('nexora_password_vaults?on_conflict=user_id', {
    method: 'POST',
    headers: { Prefer: 'resolution=merge-duplicates,return=minimal' },
    body: JSON.stringify({
      user_id: session.user.id,
      encrypted_vault: snapshot,
      recovery_salt: metadata.salt,
      key_nonce: metadata.nonce,
      wrapped_key: metadata.wrappedKey,
      updated_at: new Date().toISOString(),
    }),
  });
}

export async function restoreEncryptedCloudVault(recoveryCodeInput: string): Promise<Uint8Array> {
  const recoveryCode = recoveryCodeInput.replace(/\s/g, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(recoveryCode)) {
    throw new Error('Enter the 64-character recovery key saved when cloud recovery was enabled.');
  }
  const session = await getGoogleSession();
  if (!session) throw new Error('Sign in with Google before restoring.');
  const rows = await cloudRequest(
    `nexora_password_vaults?select=user_id,encrypted_vault,recovery_salt,key_nonce,wrapped_key,updated_at&user_id=eq.${encodeURIComponent(session.user.id)}`,
  ) as CloudRow[];
  if (!Array.isArray(rows) || !rows.length) throw new Error('No encrypted cloud vault was found for this Google account.');
  const row = rows[0];
  try {
    const salt = hexToBytes(row.recovery_salt);
    const nonce = hexToBytes(row.key_nonce);
    const wrappedKey = hexToBytes(row.wrapped_key);
    if (salt.length !== 16 || nonce.length !== 24 || wrappedKey.length !== 48) throw new Error('Invalid recovery envelope.');
    const wrappingKey = await pbkdf2Async(sha256, recoveryCode, salt, { c: RECOVERY_ITERATIONS, dkLen: 32 });
    const vaultKey = xchacha20poly1305(wrappingKey, nonce).decrypt(wrappedKey);
    if (vaultKey.length !== 32) throw new Error('Invalid recovered vault key.');
    await storeRecoveredPasswordVault(vaultKey, row.encrypted_vault);
    await AsyncStorage.setItem(RECOVERY_META, JSON.stringify({
      salt: row.recovery_salt,
      nonce: row.key_nonce,
      wrappedKey: row.wrapped_key,
    }));
    return vaultKey;
  } catch {
    throw new Error('Recovery failed. Check the recovery key; the local vault was not replaced.');
  }
}
