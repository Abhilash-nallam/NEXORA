import bcrypt from 'bcryptjs';
import { requireAuth } from '../../../lib/session';
import { supabase, isRateLimited, recordAttempt } from '../../../lib/db';
import { decryptSecret } from '../../../lib/crypto';
import { verifyToken } from '../../../lib/totp';
import { tryConsumeBackupCode } from '../../../lib/backupCodes';

// POST /api/2fa/disable   body: { password: "...", code: "123456" }
// Requiring BOTH password and a valid TOTP/backup code prevents an
// attacker who has stolen a logged-in session (e.g. via XSS) from
// silently turning off 2FA.
export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const user = await requireAuth(req, res);
  if (!user) return;

  const { password, code } = req.body;
  if (!password || !code) {
    return res.status(400).json({ error: 'Password and verification code are required.' });
  }

  try {
    // Guard against brute-forcing the code via a hijacked session, same
    // reasoning as login and verify-setup.
    if (await isRateLimited(user.id)) {
      return res.status(429).json({
        error: 'Too many failed attempts. Please wait 15 minutes and try again.',
      });
    }

    const { data: row, error } = await supabase
      .from('users')
      .select('password_hash, two_factor_secret_encrypted, two_factor_secret_iv, two_factor_secret_tag, two_factor_enabled')
      .eq('id', user.id)
      .single();
    if (error) throw error;

    if (!row.two_factor_enabled) {
      return res.status(400).json({ error: '2FA is not currently enabled.' });
    }

    const passwordOk = await bcrypt.compare(password, row.password_hash);
    if (!passwordOk) {
      return res.status(401).json({ error: 'Incorrect password.' });
    }

    // Accept a backup code here too — someone who just lost their phone
    // and is using their last backup code to log in should still be able
    // to turn 2FA off from settings without needing the authenticator.
    const isBackupCodeFormat = /^[A-F0-9]{5}-[A-F0-9]{5}$/i.test(code);
    let verified;
    if (isBackupCodeFormat) {
      verified = await tryConsumeBackupCode(user.id, code);
    } else {
      const secret = decryptSecret(
        row.two_factor_secret_encrypted,
        row.two_factor_secret_iv,
        row.two_factor_secret_tag
      );
      verified = verifyToken(code, secret);
    }

    await recordAttempt(user.id, verified);

    if (!verified) {
      return res.status(400).json({ error: 'Invalid verification code.' });
    }

    const { error: updateErr } = await supabase
      .from('users')
      .update({
        two_factor_enabled: false,
        two_factor_secret_encrypted: null,
        two_factor_secret_iv: null,
        two_factor_secret_tag: null,
        two_factor_confirmed_at: null,
      })
      .eq('id', user.id);
    if (updateErr) throw updateErr;

    // Clean up unused backup codes.
    await supabase.from('backup_codes').delete().eq('user_id', user.id);

    return res.status(200).json({ success: true });
  } catch (err) {
    console.error('2FA disable error:', err);
    return res.status(500).json({ error: 'Failed to disable 2FA. Please try again.' });
  }
}
