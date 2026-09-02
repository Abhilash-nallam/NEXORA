import bcrypt from 'bcryptjs';
import { requireAuth } from '../../../lib/session';
import { supabase, isRateLimited, recordAttempt } from '../../../lib/db';
import { decryptSecret } from '../../../lib/crypto';
import { verifyToken, generateBackupCodes } from '../../../lib/totp';

// POST /api/2fa/regenerate-backup-codes   body: { password, code }
// Invalidates all existing backup codes and issues a fresh set of 10.
// Gated behind password + a valid TOTP code — same reasoning as disabling
// 2FA: this is a security-relevant action, so a hijacked session alone
// (e.g. via XSS) shouldn't be able to trigger it. Deliberately does NOT
// accept a backup code here — if you're regenerating because you're
// running low, you should still have your authenticator app.
export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const user = await requireAuth(req, res);
  if (!user) return;

  const { password, code } = req.body;
  if (!password || !code) {
    return res.status(400).json({ error: 'Password and verification code are required.' });
  }

  try {
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

    const secret = decryptSecret(
      row.two_factor_secret_encrypted,
      row.two_factor_secret_iv,
      row.two_factor_secret_tag
    );
    const verified = verifyToken(code, secret);
    await recordAttempt(user.id, verified);

    if (!verified) {
      return res.status(400).json({ error: 'Invalid verification code.' });
    }

    const { plaintextCodes, hashedCodes } = await generateBackupCodes(10);

    // Invalidate old codes, then insert the fresh batch. Two statements,
    // not a transaction — if the insert fails after the delete succeeds,
    // the user is left with zero backup codes rather than duplicates.
    // That's the safer failure mode: worst case they retry regeneration.
    const { error: deleteErr } = await supabase.from('backup_codes').delete().eq('user_id', user.id);
    if (deleteErr) throw deleteErr;

    const { error: insertErr } = await supabase
      .from('backup_codes')
      .insert(hashedCodes.map((hash) => ({ user_id: user.id, code_hash: hash })));
    if (insertErr) throw insertErr;

    // Show these to the user ONCE, same as initial setup.
    return res.status(200).json({ success: true, backupCodes: plaintextCodes });
  } catch (err) {
    console.error('Regenerate backup codes error:', err);
    return res.status(500).json({ error: 'Failed to regenerate backup codes. Please try again.' });
  }
}
