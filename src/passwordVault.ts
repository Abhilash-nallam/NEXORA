import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import * as Crypto from 'expo-crypto';
import * as SecureStore from 'expo-secure-store';
import AsyncStorage from '@react-native-async-storage/async-storage';

const KEY_NAME = 'nexora.password-vault.key.v1';
const DATA_KEY = 'nexora.password-vault.encrypted.v1';
const VERSION = 1;

export type PasswordEntry = {
  id: string;
  title: string;
  username: string;
  password: string;
  website: string;
  notes: string;
  category: string;
  favorite: boolean;
  createdAt: number;
  updatedAt: number;
};

export type PasswordVaultEnvelope = {
  format: 'NEXORA_PASSWORD_VAULT';
  version: number;
  nonce: string;
  ciphertext: string;
};

function randomBytes(length: number): Uint8Array {
  return Crypto.getRandomBytes(length);
}

export async function unlockPasswordVault(): Promise<Uint8Array> {
  const existing = await SecureStore.getItemAsync(KEY_NAME, {
    requireAuthentication: true,
    authenticationPrompt: 'Unlock your NEXORA password vault',
  });
  if (existing) {
    const key = hexToBytes(existing);
    if (key.length !== 32) throw new Error('Vault key is invalid. Do not delete app data; restore from a trusted backup if available.');
    return key;
  }

  const key = randomBytes(32);
  await SecureStore.setItemAsync(KEY_NAME, bytesToHex(key), {
    requireAuthentication: true,
    authenticationPrompt: 'Protect your NEXORA password vault',
    keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  });
  return key;
}

export async function loadPasswordEntries(key: Uint8Array): Promise<PasswordEntry[]> {
  const raw = await AsyncStorage.getItem(DATA_KEY);
  if (!raw) return [];
  let envelope: PasswordVaultEnvelope;
  try {
    envelope = JSON.parse(raw) as PasswordVaultEnvelope;
  } catch {
    throw new Error('The encrypted password vault is damaged.');
  }
  return loadPasswordEntriesFromEnvelope(key, envelope);
}

/** Decrypts and validates an envelope without changing local storage. */
export async function loadPasswordEntriesFromEnvelope(
  key: Uint8Array,
  envelope: PasswordVaultEnvelope,
): Promise<PasswordEntry[]> {
  if (key.length !== 32 || !envelope || envelope.format !== 'NEXORA_PASSWORD_VAULT' || envelope.version !== VERSION) {
    throw new Error('Unsupported password vault format.');
  }
  try {
    const nonce = hexToBytes(envelope.nonce);
    const ciphertext = hexToBytes(envelope.ciphertext);
    if (nonce.length !== 24 || ciphertext.length < 16) throw new Error('Invalid envelope');
    const plaintext = xchacha20poly1305(key, nonce).decrypt(ciphertext);
    const entries: unknown = JSON.parse(new TextDecoder().decode(plaintext));
    if (!Array.isArray(entries)) throw new Error('Invalid vault data');
    return entries.map((entry) => validateEntry(entry));
  } catch {
    throw new Error('Could not decrypt the password vault. Your data has not been overwritten.');
  }
}

/** Returns only the already-encrypted snapshot suitable for cloud storage. */
export async function getEncryptedPasswordVaultSnapshot(): Promise<PasswordVaultEnvelope | null> {
  const raw = await AsyncStorage.getItem(DATA_KEY);
  if (!raw) return null;
  try {
    const envelope = JSON.parse(raw) as PasswordVaultEnvelope;
    if (envelope.format !== 'NEXORA_PASSWORD_VAULT' || envelope.version !== VERSION ||
        typeof envelope.nonce !== 'string' || typeof envelope.ciphertext !== 'string') {
      throw new Error('Invalid envelope');
    }
    if (hexToBytes(envelope.nonce).length !== 24 || hexToBytes(envelope.ciphertext).length < 16) {
      throw new Error('Invalid envelope');
    }
    return envelope;
  } catch {
    throw new Error('The encrypted password vault is damaged; cloud sync was not attempted.');
  }
}

/** Validates remote ciphertext before replacing the device key or local vault. */
export async function storeRecoveredPasswordVault(
  key: Uint8Array,
  envelope: PasswordVaultEnvelope,
): Promise<PasswordEntry[]> {
  const entries = await loadPasswordEntriesFromEnvelope(key, envelope);
  await SecureStore.setItemAsync(KEY_NAME, bytesToHex(key), {
    requireAuthentication: true,
    authenticationPrompt: 'Protect your recovered NEXORA password vault',
    keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  });
  await AsyncStorage.setItem(DATA_KEY, JSON.stringify(envelope));
  return entries;
}

export async function savePasswordEntries(key: Uint8Array, entries: PasswordEntry[]): Promise<void> {
  if (key.length !== 32) throw new Error('Vault key is invalid.');
  const nonce = randomBytes(24);
  const plaintext = new TextEncoder().encode(JSON.stringify(entries.map(validateEntry)));
  const ciphertext = xchacha20poly1305(key, nonce).encrypt(plaintext);
  const envelope: PasswordVaultEnvelope = {
    format: 'NEXORA_PASSWORD_VAULT',
    version: VERSION,
    nonce: bytesToHex(nonce),
    ciphertext: bytesToHex(ciphertext),
  };
  await AsyncStorage.setItem(DATA_KEY, JSON.stringify(envelope));
}

function validateEntry(value: any): PasswordEntry {
  if (!value || typeof value !== 'object') throw new Error('Invalid password entry.');
  const text = (v: unknown, max: number) => {
    if (typeof v !== 'string' || v.length > max) throw new Error('A password entry contains invalid fields.');
    return v;
  };
  const id = text(value.id, 100);
  const title = text(value.title, 160).trim();
  const username = text(value.username, 320);
  const password = text(value.password, 4096);
  const website = text(value.website, 2048);
  const notes = text(value.notes, 8000);
  const category = text(value.category, 80);
  if (!id || !title || !password) throw new Error('Title and password are required.');
  return {
    id, title, username, password, website, notes, category: category || 'General',
    favorite: Boolean(value.favorite),
    createdAt: Number.isFinite(value.createdAt) ? value.createdAt : Date.now(),
    updatedAt: Number.isFinite(value.updatedAt) ? value.updatedAt : Date.now(),
  };
}
