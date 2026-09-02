const { createClient } = require('@supabase/supabase-js');

// Use the SERVICE ROLE key here (server-side only, never exposed to the
// browser) so these API routes can bypass row-level security as needed.
// Set this only in server env vars — never prefix it with NEXT_PUBLIC_.
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const MAX_ATTEMPTS_PER_WINDOW = 5;
const WINDOW_MINUTES = 15;

/**
 * Returns true if the user has too many failed 2FA attempts recently.
 * Prevents brute-forcing the 6-digit code (1,000,000 combinations is
 * feasible to brute force without rate limiting).
 */
async function isRateLimited(userId) {
  const since = new Date(Date.now() - WINDOW_MINUTES * 60 * 1000).toISOString();
  const { count, error } = await supabase
    .from('two_factor_attempts')
    .select('id', { count: 'exact', head: true })
    .eq('user_id', userId)
    .eq('success', false)
    .gte('attempted_at', since);

  if (error) throw error;
  return count >= MAX_ATTEMPTS_PER_WINDOW;
}

async function recordAttempt(userId, success) {
  await supabase.from('two_factor_attempts').insert({ user_id: userId, success });
}

const MAX_LOGIN_ATTEMPTS_PER_WINDOW = 10;
const LOGIN_WINDOW_MINUTES = 15;

/**
 * Rate limits password attempts on /api/auth/login, keyed by email
 * (lowercased) so an attacker can't brute-force a password even for an
 * account they can't yet prove exists. Combine with IP-based limiting at
 * your edge/CDN if you can (Vercel, Cloudflare, etc.) for defense in depth —
 * this DB-level check is what protects you even without one.
 */
async function isLoginRateLimited(identifier) {
  const since = new Date(Date.now() - LOGIN_WINDOW_MINUTES * 60 * 1000).toISOString();
  const { count, error } = await supabase
    .from('login_attempts')
    .select('id', { count: 'exact', head: true })
    .eq('identifier', identifier)
    .eq('success', false)
    .gte('attempted_at', since);

  if (error) throw error;
  return count >= MAX_LOGIN_ATTEMPTS_PER_WINDOW;
}

async function recordLoginAttempt(identifier, success) {
  await supabase.from('login_attempts').insert({ identifier, success });
}

module.exports = {
  supabase,
  isRateLimited,
  recordAttempt,
  WINDOW_MINUTES,
  MAX_ATTEMPTS_PER_WINDOW,
  isLoginRateLimited,
  recordLoginAttempt,
  MAX_LOGIN_ATTEMPTS_PER_WINDOW,
  LOGIN_WINDOW_MINUTES,
};
