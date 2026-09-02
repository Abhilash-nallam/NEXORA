import crypto from 'crypto';
import { supabase } from './db';

const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const SESSION_COOKIE = '__Host-session';
const PENDING_COOKIE = '__Host-pending-login';

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const cookies = {};
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index === -1) continue;
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    try { cookies[key] = decodeURIComponent(value); } catch { cookies[key] = value; }
  }
  return cookies;
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token, 'utf8').digest('hex');
}

function serializeCookie(name, value, options = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (options.maxAge !== undefined) parts.push(`Max-Age=${Math.floor(options.maxAge)}`);
  parts.push(`Path=${options.path || '/'}`);
  if (options.httpOnly !== false) parts.push('HttpOnly');
  if (options.secure !== false) parts.push('Secure');
  parts.push(`SameSite=${options.sameSite || 'Lax'}`);
  return parts.join('; ');
}

function appendSetCookie(res, cookie) {
  const existing = res.getHeader('Set-Cookie');
  const values = Array.isArray(existing) ? existing : existing ? [existing] : [];
  res.setHeader('Set-Cookie', [...values, cookie]);
}

export function setSessionCookie(res, token) {
  appendSetCookie(res, serializeCookie(SESSION_COOKIE, token, { maxAge: SESSION_TTL_SECONDS }));
}

export function clearSessionCookie(res) {
  appendSetCookie(res, serializeCookie(SESSION_COOKIE, '', { maxAge: 0 }));
}

export function setPendingLoginCookie(res, token, maxAgeSeconds = 10 * 60) {
  appendSetCookie(res, serializeCookie(PENDING_COOKIE, token, { maxAge: maxAgeSeconds }));
}

export function clearPendingLoginCookie(res) {
  appendSetCookie(res, serializeCookie(PENDING_COOKIE, '', { maxAge: 0 }));
}

export function getPendingLoginToken(req) {
  return parseCookies(req)[PENDING_COOKIE] || null;
}

/** Issue a random opaque session token. Only its SHA-256 hash is stored in DB. */
export async function createSessionToken(user) {
  const token = crypto.randomBytes(32).toString('base64url');
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + SESSION_TTL_SECONDS * 1000).toISOString();

  const { error } = await supabase.from('sessions').insert({
    token_hash: tokenHash,
    user_id: user.id,
    expires_at: expiresAt,
  });
  if (error) throw error;

  return token;
}

/** Validate the HttpOnly session cookie and return the authenticated user. */
export async function requireAuth(req, res) {
  const token = parseCookies(req)[SESSION_COOKIE];
  if (!token) {
    res.status(401).json({ error: 'Not authenticated.' });
    return null;
  }

  const { data: session, error } = await supabase
    .from('sessions')
    .select('user_id, expires_at, revoked_at')
    .eq('token_hash', hashToken(token))
    .maybeSingle();

  if (error || !session || session.revoked_at || new Date(session.expires_at) <= new Date()) {
    clearSessionCookie(res);
    res.status(401).json({ error: 'Session expired. Please log in again.' });
    return null;
  }

  const { data: user, error: userError } = await supabase
    .from('users')
    .select('id, email')
    .eq('id', session.user_id)
    .single();

  if (userError || !user) {
    clearSessionCookie(res);
    res.status(401).json({ error: 'Not authenticated.' });
    return null;
  }

  return user;
}

export async function revokeCurrentSession(req, res) {
  const token = parseCookies(req)[SESSION_COOKIE];
  if (token) {
    await supabase
      .from('sessions')
      .update({ revoked_at: new Date().toISOString() })
      .eq('token_hash', hashToken(token))
      .is('revoked_at', null);
  }
  clearSessionCookie(res);
}

export { SESSION_COOKIE, PENDING_COOKIE, SESSION_TTL_SECONDS };
