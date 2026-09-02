import { supabase, isRateLimited, recordAttempt } from '../../../lib/db';
import { decryptSecret } from '../../../lib/crypto';
import { verifyToken } from '../../../lib/totp';
import { createSessionToken, setSessionCookie, getPendingLoginToken, clearPendingLoginCookie } from '../../../lib/session';
import { tryConsumeBackupCode } from '../../../lib/backupCodes';

// POST /api/auth/verify-2fa   body: { pendingToken, code }
// `code` can be either a 6-digit TOTP code OR a backup code like "A1B2C-3D4E5".
export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const pendingToken = getPendingLoginToken(req);
  const { code } = req.body;
  if (!pendingToken || !code) {
    return res.status(400).json({ error: 'Login verification data is incomplete. Please log in again.' });
  }

  try {
    const { data: pending, error: pendingErr } = await supabase
      .from('pending_logins')
      .select('user_id, expires_at')
      .eq('token', pendingToken)
      .single();

    if (pendingErr || !pending) {
      return res.status(401).json({ error: 'Login session expired. Please log in again.' });
    }
    if (new Date(pending.expires_at) < new Date()) {
      await supabase.from('pending_logins').delete().eq('token', pendingToken);
      return res.status(401).json({ error: 'Login session expired. Please log in again.' });
    }

    const userId = pending.user_id;

    if (await isRateLimited(userId)) {
      return res.status(429).json({
        error: 'Too many failed attempts. Please wait 15 minutes and try again.',
      });
    }

    const { data: user, error: userErr } = await supabase
      .from('users')
      .select('id, email, two_factor_secret_encrypted, two_factor_secret_iv, two_factor_secret_tag')
      .eq('id', userId)
      .single();
    if (userErr || !user) throw userErr || new Error('User not found');

    const isBackupCodeFormat = /^[A-F0-9]{5}-[A-F0-9]{5}$/i.test(code);
    let verified = false;

    if (isBackupCodeFormat) {
      verified = await tryConsumeBackupCode(userId, code);
    } else {
      const secret = decryptSecret(
        user.two_factor_secret_encrypted,
        user.two_factor_secret_iv,
        user.two_factor_secret_tag
      );
      verified = verifyToken(code, secret);
    }

    await recordAttempt(userId, verified);

    if (!verified) {
      return res.status(401).json({ error: 'Invalid or expired code.' });
    }

    // Atomically consume the pending login. Only one concurrent request can win.
    const { data: consumed, error: consumeErr } = await supabase
      .from('pending_logins')
      .update({ consumed_at: new Date().toISOString() })
      .eq('token', pendingToken)
      .is('consumed_at', null)
      .gt('expires_at', new Date().toISOString())
      .select('user_id')
      .maybeSingle();
    if (consumeErr) throw consumeErr;
    if (!consumed || consumed.user_id !== userId) {
      clearPendingLoginCookie(res);
      return res.status(401).json({ error: 'Login session expired. Please log in again.' });
    }

    const sessionToken = await createSessionToken(user);
    setSessionCookie(res, sessionToken);
    clearPendingLoginCookie(res);

    return res.status(200).json({ success: true });
  } catch (err) {
    console.error('2FA verify error:', err);
    return res.status(500).json({ error: 'Verification failed. Please try again.' });
  }
}
