import { supabase } from '../../../lib/db';

// GET /api/cron/cleanup-pending-logins
// Deletes expired pending_logins rows (abandoned mid-2FA-flow logins).
// Wire this up as a Vercel Cron job (see vercel.json in this package) or
// any external scheduler that can hit a URL — e.g. hourly.
//
// Protected by a shared secret so this can't be triggered by randoms
// hammering the URL: set CRON_SECRET in your env vars and configure
// Vercel Cron (or your scheduler) to send it as a Bearer token.
export default async function handler(req, res) {
  const auth = req.headers.authorization;
  if (!process.env.CRON_SECRET) {
    console.error('CRON_SECRET is not set — refusing to run cleanup.');
    return res.status(500).json({ error: 'Server misconfigured.' });
  }
  if (auth !== `Bearer ${process.env.CRON_SECRET}`) {
    return res.status(401).json({ error: 'Unauthorized.' });
  }

  try {
    const { error, count } = await supabase
      .from('pending_logins')
      .delete({ count: 'exact' })
      .lt('expires_at', new Date().toISOString());
    if (error) throw error;

    return res.status(200).json({ deleted: count ?? 0 });
  } catch (err) {
    console.error('Cleanup error:', err);
    return res.status(500).json({ error: 'Cleanup failed.' });
  }
}
