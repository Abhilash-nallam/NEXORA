import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { supabase, isLoginRateLimited, recordLoginAttempt } from '../../../lib/db';
import { createSessionToken, setSessionCookie, setPendingLoginCookie } from '../../../lib/session';

const PENDING_LOGIN_TTL_MINUTES = 10;

// POST /api/auth/login   body: { email, password }
export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const identifier = String(email).trim().toLowerCase();

  try {
    // Check BEFORE touching bcrypt so a locked-out attacker can't keep
    // burning CPU on hash comparisons, and gets the same 429 regardless
    // of whether the account exists.
    if (await isLoginRateLimited(identifier)) {
      return res.status(429).json({
        error: 'Too many failed login attempts. Please wait 15 minutes and try again.',
      });
    }

    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, password_hash, two_factor_enabled')
      .eq('email', identifier)
      .single();

    // Always run bcrypt.compare (even against a dummy hash) so that
    // "user not found" and "wrong password" take the same amount of
    // time — otherwise timing differences leak which emails exist.
    const passwordHash = user?.password_hash ?? '$2a$10$invalidsaltinvalidsaltinvalidsalt.......';
    const passwordOk = await bcrypt.compare(password, passwordHash);

    // Record every attempt (success or fail) against the identifier,
    // not the user id — we need this to work even for unknown emails.
    await recordLoginAttempt(identifier, Boolean(user) && passwordOk);

    if (error || !user || !passwordOk) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    if (!user.two_factor_enabled) {
      // No 2FA — log them in immediately, same as before.
      const sessionToken = await createSessionToken(user);
      setSessionCookie(res, sessionToken);
      return res.status(200).json({ requires2fa: false });
    }

    // 2FA is enabled — issue a short-lived pending token instead of a
    // full session. The client must POST this token + a valid 6-digit
    // code to /api/auth/verify-2fa to actually get logged in.
    const pendingToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + PENDING_LOGIN_TTL_MINUTES * 60 * 1000).toISOString();

    const { error: insertErr } = await supabase
      .from('pending_logins')
      .insert({ token: pendingToken, user_id: user.id, expires_at: expiresAt });
    if (insertErr) throw insertErr;

    setPendingLoginCookie(res, pendingToken, PENDING_LOGIN_TTL_MINUTES * 60);
    return res.status(200).json({ requires2fa: true });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Login failed. Please try again.' });
  }
}
