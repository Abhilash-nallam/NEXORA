import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import * as Crypto from 'expo-crypto';
import * as SecureStore from 'expo-secure-store';

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

type Envelope = {
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

  // A device-bound random key avoids a master password. It is protected by the
  // operating system's biometric/device-credential gate and is never synced.
  const key = randomBytes(32);
  await SecureStore.setItemAsync(KEY_NAME, bytesToHex(key), {
    requireAuthentication: true,
    authenticationPrompt: 'Protect your NEXORA password vault',
    keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  });
  return key;
}

export async function loadPasswordEntries(key: Uint8Array): Promise<PasswordEntry[]> {
  const raw = await SecureStore.getItemAsync(DATA_KEY);
  if (!raw) return [];
  let envelope: Envelope;
  try {
    envelope = JSON.parse(raw) as Envelope;
  } catch {
    throw new Error('The encrypted password vault is damaged.');
  }
  if (envelope.format !== 'NEXORA_PASSWORD_VAULT' || envelope.version !== VERSION) {
    throw new Error('Unsupported password vault format.');
  }
  try {
    const plaintext = xchacha20poly1305(key, hexToBytes(envelope.nonce)).decrypt(hexToBytes(envelope.ciphertext));
    const entries = JSON.parse(new TextDecoder().decode(plaintext));
    if (!Array.isArray(entries)) throw new Error('Invalid vault data');
    return entries.map((entry) => validateEntry(entry));
  } catch {
    throw new Error('Could not decrypt the password vault. Your data has not been overwritten.');
  }
}

export async function savePasswordEntries(key: Uint8Array, entries: PasswordEntry[]): Promise<void> {
  const nonce = randomBytes(24);
  const plaintext = new TextEncoder().encode(JSON.stringify(entries.map(validateEntry)));
  const ciphertext = xchacha20poly1305(key, nonce).encrypt(plaintext);
  const envelope: Envelope = {
    format: 'NEXORA_PASSWORD_VAULT',
    version: VERSION,
    nonce: bytesToHex(nonce),
    ciphertext: bytesToHex(ciphertext),
  };
  await SecureStore.setItemAsync(DATA_KEY, JSON.stringify(envelope), {
    keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  });
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
