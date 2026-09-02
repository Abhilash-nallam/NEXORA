import { requireAuth } from '../../../lib/session'; // your existing "is logged in" middleware
import { supabase } from '../../../lib/db';
import { encryptSecret } from '../../../lib/crypto';
import { generateSecret, generateQrCode } from '../../../lib/totp';

// POST /api/2fa/setup
// Called when the user clicks "Enable 2FA" in account settings.
// Generates a secret, stores it as PENDING (not active yet), returns a QR code.
export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const user = await requireAuth(req, res); // throws/returns 401 if not logged in
  if (!user) return;

  try {
    const { data: existing, error: fetchErr } = await supabase
      .from('users')
      .select('two_factor_enabled')
      .eq('id', user.id)
      .single();
    if (fetchErr) throw fetchErr;

    if (existing.two_factor_enabled) {
      return res.status(400).json({ error: '2FA is already enabled on this account.' });
    }

    const secret = generateSecret();
    const { ciphertext, iv, tag } = encryptSecret(secret);

    const { error: updateErr } = await supabase
      .from('users')
      .update({
        two_factor_pending_secret_encrypted: ciphertext,
        two_factor_pending_secret_iv: iv,
        two_factor_pending_secret_tag: tag,
      })
      .eq('id', user.id);
    if (updateErr) throw updateErr;

    const { qrDataUrl } = await generateQrCode(secret, user.email, 'YourAppName');

    // Also return the raw secret as text, for users who can't scan a QR
    // (e.g. desktop app, screen reader) and need to type it in manually.
    return res.status(200).json({ qrDataUrl, manualEntryKey: secret });
  } catch (err) {
    console.error('2FA setup error:', err);
    return res.status(500).json({ error: 'Failed to start 2FA setup. Please try again.' });
  }
}
