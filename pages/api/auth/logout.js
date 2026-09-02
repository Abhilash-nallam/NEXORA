import { revokeCurrentSession } from '../../../lib/session';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  try {
    await revokeCurrentSession(req, res);
    return res.status(200).json({ success: true });
  } catch (err) {
    console.error('Logout error:', err);
    return res.status(200).json({ success: true });
  }
}
