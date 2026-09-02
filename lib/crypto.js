/**
 * Encrypts/decrypts the TOTP secret before it touches the database.
 *
 * Why encrypt (not just rely on DB access controls)?
 * A TOTP secret is equivalent to a password — anyone who reads it from
 * a DB dump / backup / leaked credential can generate valid codes forever.
 * Encrypting at the application layer means a raw DB leak isn't enough;
 * the attacker also needs your ENCRYPTION_KEY (kept only in env vars,
 * never in the database).
 */

const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';

function getKey() {
  const keyHex = process.env.TOTP_ENCRYPTION_KEY;
  if (!keyHex) {
    throw new Error(
      'TOTP_ENCRYPTION_KEY env var is not set. Generate one with: ' +
      'node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"'
    );
  }
  const key = Buffer.from(keyHex, 'hex');
  if (key.length !== 32) {
    throw new Error('TOTP_ENCRYPTION_KEY must be a 32-byte (64 hex char) key.');
  }
  return key;
}

/**
 * @param {string} plaintext - the raw TOTP secret (base32 string)
 * @returns {{ ciphertext: string, iv: string, tag: string }} all hex-encoded
 */
function encryptSecret(plaintext) {
  const key = getKey();
  const iv = crypto.randomBytes(12); // 96-bit IV recommended for GCM
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    ciphertext: encrypted.toString('hex'),
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
  };
}

/**
 * @param {string} ciphertextHex
 * @param {string} ivHex
 * @param {string} tagHex
 * @returns {string} the original plaintext secret
 */
function decryptSecret(ciphertextHex, ivHex, tagHex) {
  const key = getKey();
  const decipher = crypto.createDecipheriv(ALGORITHM, key, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(ciphertextHex, 'hex')),
    decipher.final(),
  ]);
  return decrypted.toString('utf8');
}

module.exports = { encryptSecret, decryptSecret };
