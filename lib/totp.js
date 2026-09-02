const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

// Allow 1 step (30s) of clock drift on either side. Keep this small —
// widening it makes brute-forcing codes easier.
authenticator.options = { window: 1 };

/**
 * Generates a new random base32 TOTP secret.
 */
function generateSecret() {
  return authenticator.generateSecret(); // base32 string, ~20 bytes of entropy
}

/**
 * Builds the otpauth:// URI and a QR code (as a data URL) for the user to scan.
 * @param {string} secret - base32 secret (plaintext, not yet encrypted)
 * @param {string} accountName - usually the user's email
 * @param {string} issuer - your app/product name, shown in the authenticator app
 */
async function generateQrCode(secret, accountName, issuer) {
  const otpauthUrl = authenticator.keyuri(accountName, issuer, secret);
  const qrDataUrl = await QRCode.toDataURL(otpauthUrl);
  return { otpauthUrl, qrDataUrl };
}

/**
 * Verifies a 6-digit code against the secret.
 * @returns {boolean}
 */
function verifyToken(token, secret) {
  if (!/^\d{6}$/.test(token)) return false;
  try {
    return authenticator.verify({ token, secret });
  } catch {
    return false;
  }
}

/**
 * Generates a batch of human-friendly backup codes (e.g. "7F3K-9QRT")
 * plus their bcrypt hashes for storage. Return the PLAINTEXT codes to
 * the user exactly once — never store or log them in plaintext.
 */
async function generateBackupCodes(count = 10) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const raw = crypto.randomBytes(5).toString('hex').toUpperCase(); // 10 hex chars
    const formatted = `${raw.slice(0, 5)}-${raw.slice(5, 10)}`;
    codes.push(formatted);
  }
  const hashed = await Promise.all(
    codes.map((code) => bcrypt.hash(code, 10))
  );
  return { plaintextCodes: codes, hashedCodes: hashed };
}

module.exports = {
  generateSecret,
  generateQrCode,
  verifyToken,
  generateBackupCodes,
};
