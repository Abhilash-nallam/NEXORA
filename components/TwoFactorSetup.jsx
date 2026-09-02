import { useState } from 'react';

// Drop this into your account settings page.
// Flow: click Enable -> show QR -> user enters code -> show backup codes once.
export default function TwoFactorSetup() {
  const [step, setStep] = useState('idle'); // idle | showingQr | done
  const [qrDataUrl, setQrDataUrl] = useState(null);
  const [manualKey, setManualKey] = useState(null);
  const [code, setCode] = useState('');
  const [backupCodes, setBackupCodes] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  async function startSetup() {
    setError(null);
    setLoading(true);
    try {
      const res = await fetch('/api/2fa/setup', { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to start setup.');
      setQrDataUrl(data.qrDataUrl);
      setManualKey(data.manualEntryKey);
      setStep('showingQr');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function confirmSetup(e) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await fetch('/api/2fa/verify-setup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Invalid code.');
      setBackupCodes(data.backupCodes);
      setStep('done');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  if (step === 'idle') {
    return (
      <div>
        <p>Add an extra layer of security to your account.</p>
        <button onClick={startSetup} disabled={loading}>
          {loading ? 'Starting...' : 'Enable Two-Factor Authentication'}
        </button>
        {error && <p style={{ color: 'red' }}>{error}</p>}
      </div>
    );
  }

  if (step === 'showingQr') {
    return (
      <div>
        <p>1. Scan this QR code with Google Authenticator, Authy, or similar.</p>
        {qrDataUrl && <img src={qrDataUrl} alt="2FA QR code" width={200} height={200} />}
        <p>Can't scan it? Enter this code manually: <code>{manualKey}</code></p>

        <form onSubmit={confirmSetup}>
          <label>
            2. Enter the 6-digit code from your app:
            <input
              type="text"
              inputMode="numeric"
              pattern="\d{6}"
              maxLength={6}
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
              required
            />
          </label>
          <button type="submit" disabled={loading || code.length !== 6}>
            {loading ? 'Verifying...' : 'Confirm & Enable'}
          </button>
        </form>
        {error && <p style={{ color: 'red' }}>{error}</p>}
      </div>
    );
  }

  if (step === 'done') {
    return (
      <div>
        <p style={{ color: 'green' }}>Two-factor authentication is now enabled.</p>
        <p><strong>Save these backup codes somewhere safe.</strong> Each can be used once if you lose access to your authenticator app. They will not be shown again.</p>
        <ul>
          {backupCodes.map((c) => (
            <li key={c}><code>{c}</code></li>
          ))}
        </ul>
      </div>
    );
  }

  return null;
}
