const bcrypt = require('bcryptjs');
const { supabase } = require('./db');

/**
 * Checks a raw backup code against the user's unused hashed codes and
 * marks it used (single-use) on a match. Shared by /api/auth/verify-2fa
 * and /api/2fa/disable so there's exactly one place that implements
 * "what counts as consuming a backup code."
 * @returns {Promise<boolean>}
 */
async function tryConsumeBackupCode(userId, rawCode) {
  const { data: codes, error } = await supabase
    .from('backup_codes')
    .select('id, code_hash')
    .eq('user_id', userId)
    .is('used_at', null);
  if (error) throw error;

  for (const row of codes) {
    const matches = await bcrypt.compare(rawCode, row.code_hash);
    if (matches) {
      const { data: consumed, error: consumeErr } = await supabase
        .from('backup_codes')
        .update({ used_at: new Date().toISOString() })
        .eq('id', row.id)
        .is('used_at', null)
        .select('id')
        .maybeSingle();
      if (consumeErr) throw consumeErr;
      if (consumed) return true;
      // Another concurrent request consumed this code first.
      return false;
    }
  }
  return false;
}

module.exports = { tryConsumeBackupCode };
