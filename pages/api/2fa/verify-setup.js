import { requireAuth } from '../../../lib/session';
import { supabase, isRateLimited, recordAttempt } from '../../../lib/db';
import { decryptSecret, encryptSecret } from '../../../lib/crypto';
import { verifyToken, generateBackupCodes } from '../../../lib/totp';

// POST /api/2fa/verify-setup   body: { code: "123456" }
// Confirms the user actually scanned the QR and their app produces valid
// codes, BEFORE we turn 2FA on. This prevents users locking themselves
// out by enabling 2FA with a secret they never actually saved.
export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const user = await requireAuth(req, res);
  if (!user) return;

  const { code } = req.body;
  if (!code) return res.status(400).json({ error: 'Verification code is required.' });

  try {
    // Same code-guessing math applies here as at login: a 6-digit code is
    // only 1,000,000 combinations. Without this, someone with a hijacked
    // session (e.g. XSS) could brute-force their way to an active 2FA
    // secret they never actually scanned.
    if (await isRateLimited(user.id)) {
      return res.status(429).json({
        error: 'Too many failed attempts. Please wait 15 minutes and try again.',
      });
    }

    const { data: row, error: fetchErr } = await supabase
      .from('users')
      .select('two_factor_pending_secret_encrypted, two_factor_pending_secret_iv, two_factor_pending_secret_tag')
      .eq('id', user.id)
      .single();
    if (fetchErr) throw fetchErr;

    if (!row.two_factor_pending_secret_encrypted) {
      return res.status(400).json({ error: 'No 2FA setup in progress. Start setup again.' });
    }

    const secret = decryptSecret(
      row.two_factor_pending_secret_encrypted,
      row.two_factor_pending_secret_iv,
      row.two_factor_pending_secret_tag
    );

    const verified = verifyToken(code, secret);
    await recordAttempt(user.id, verified);

    if (!verified) {
      return res.status(400).json({ error: 'Invalid code. Check your authenticator app and try again.' });
    }

    // Code is valid — promote pending secret to active, generate backup codes.
    const { plaintextCodes, hashedCodes } = await generateBackupCodes(10);

    const { error: updateErr } = await supabase
      .from('users')
      .update({
        two_factor_enabled: true,
        two_factor_secret_encrypted: row.two_factor_pending_secret_encrypted,
        two_factor_secret_iv: row.two_factor_pending_secret_iv,
        two_factor_secret_tag: row.two_factor_pending_secret_tag,
        two_factor_pending_secret_encrypted: null,
        two_factor_pending_secret_iv: null,
        two_factor_pending_secret_tag: null,
        two_factor_confirmed_at: new Date().toISOString(),
      })
      .eq('id', user.id);
    if (updateErr) throw updateErr;

    const { error: insertErr } = await supabase
      .from('backup_codes')
      .insert(hashedCodes.map((hash) => ({ user_id: user.id, code_hash: hash })));
    if (insertErr) throw insertErr;

    // Show these to the user ONCE. Tell them to save them somewhere safe.
    return res.status(200).json({ success: true, backupCodes: plaintextCodes });
  } catch (err) {
    console.error('2FA verify-setup error:', err);
    return res.status(500).json({ error: 'Failed to confirm 2FA setup. Please try again.' });
  }
}
