import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { pbkdf2Async } from '@noble/hashes/pbkdf2.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import * as Crypto from 'expo-crypto';

const ITERATIONS = 200_000;
const VERSION = 1;

type BackupAccount = {
  id: string;
  issuer: string;
  account: string;
  algorithm: string;
  digits: number;
  period: number;
  createdAt: number;
  group?: string;
  favorite?: boolean;
  color?: string;
  notes?: string;
  lastViewed?: number;
  lastCopied?: number;
  secret: string;
};

function randomBytes(n: number) { return Crypto.getRandomBytes(n); }

export async function createBackup(accounts: BackupAccount[], password: string) {
  if (!password || password.length < 10) {
    throw new Error('Use at least 10 characters for the backup password.');
  }

  const salt = randomBytes(16);
  const nonce = randomBytes(24);
  const key = await pbkdf2Async(sha256, password, salt, { c: ITERATIONS, dkLen: 32 });

  const plaintext = new TextEncoder().encode(JSON.stringify({
    version: VERSION,
    createdAt: Date.now(),
    accounts: accounts.map((a) => ({
      id: a.id,
      issuer: a.issuer,
      account: a.account,
      algorithm: a.algorithm,
      digits: a.digits,
      period: a.period,
      createdAt: a.createdAt,
      group: a.group || 'Personal',
      favorite: Boolean(a.favorite),
      color: a.color || '#79AFFF',
      notes: a.notes || '',
      lastViewed: a.lastViewed,
      lastCopied: a.lastCopied,
      secret: a.secret,
    })),
  }));

  const ciphertext = xchacha20poly1305(key, nonce).encrypt(plaintext);

  return JSON.stringify({
    format: 'NEXORA_BACKUP',
    version: VERSION,
    kdf: 'PBKDF2-SHA256',
    iterations: ITERATIONS,
    cipher: 'XCHACHA20-POLY1305',
    salt: bytesToHex(salt),
    nonce: bytesToHex(nonce),
    ciphertext: bytesToHex(ciphertext),
  });
}

export async function restoreBackup(text: string, password: string) {
  let parsed: any;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error('Backup text is not valid JSON.');
  }

  if (parsed?.format !== 'NEXORA_BACKUP' || parsed?.version !== VERSION) {
    throw new Error('Unsupported NEXORA backup format.');
  }
  if (parsed?.kdf !== 'PBKDF2-SHA256' || parsed?.cipher !== 'XCHACHA20-POLY1305') {
    throw new Error('Unsupported backup encryption.');
  }
  if (!Number.isInteger(parsed.iterations) || parsed.iterations < 100_000 || parsed.iterations > 2_000_000) {
    throw new Error('Invalid backup parameters.');
  }
  if (typeof password !== 'string' || password.length < 10) {
    throw new Error('Enter the backup password used when the backup was created.');
  }

  try {
    const salt = hexToBytes(parsed.salt);
    const nonce = hexToBytes(parsed.nonce);
    const ciphertext = hexToBytes(parsed.ciphertext);
    if (salt.length !== 16 || nonce.length !== 24 || ciphertext.length < 17) {
      throw new Error('Invalid backup envelope.');
    }

    const key = await pbkdf2Async(sha256, password, salt, { c: parsed.iterations, dkLen: 32 });
    const plaintext = xchacha20poly1305(key, nonce).decrypt(ciphertext);
    const payload = JSON.parse(new TextDecoder().decode(plaintext));

    if (!Array.isArray(payload.accounts)) {
      throw new Error('Backup contains no accounts.');
    }

    return payload.accounts.map((a: any) => {
      if (!a || typeof a.issuer !== 'string' || typeof a.account !== 'string' || typeof a.secret !== 'string') {
        throw new Error('Backup contains an invalid account.');
      }

      const secret = a.secret.replace(/[\s-]/g, '').toUpperCase();
      if (!/^[A-Z2-7]+=*$/.test(secret) || secret.length < 8) {
        throw new Error('Backup contains an invalid secret.');
      }

      const algorithm = ['SHA1', 'SHA256', 'SHA512'].includes(a.algorithm) ? a.algorithm : 'SHA1';
      const digits = [6, 8].includes(Number(a.digits)) ? Number(a.digits) : 6;
      const period = Number.isInteger(a.period) && a.period >= 15 && a.period <= 120 ? a.period : 30;

      return {
        id: String(a.id || ''),
        issuer: a.issuer.trim() || 'Unknown',
        account: a.account.trim(),
        algorithm,
        digits,
        period,
        createdAt: Number(a.createdAt) || Date.now(),
        group: typeof a.group === 'string' && a.group.trim() ? a.group.trim() : 'Personal',
        favorite: Boolean(a.favorite),
        color: typeof a.color === 'string' ? a.color : '#79AFFF',
        notes: typeof a.notes === 'string' ? a.notes : '',
        lastViewed: Number(a.lastViewed) || undefined,
        lastCopied: Number(a.lastCopied) || undefined,
        secret,
      };
    });
  } catch {
    throw new Error('Could not decrypt this backup. Check the password and backup text.');
  }
}
