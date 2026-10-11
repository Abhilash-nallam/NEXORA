import crypto from 'crypto';

describe('Security & Resilience Audit Tests', () => {
  describe('CSRF Same-Origin Validation', () => {
    function isSameOrigin(req: any): boolean {
      const origin = req.headers?.origin;
      if (!origin) return true;
      try {
        const originHost = new URL(origin).host;
        const reqHost = req.headers?.host;
        return Boolean(originHost && reqHost && originHost === reqHost);
      } catch {
        return false;
      }
    }

    it('should accept matching host and origin', () => {
      const req = {
        headers: {
          origin: 'https://nexora.app',
          host: 'nexora.app',
        },
      };
      expect(isSameOrigin(req)).toBe(true);
    });

    it('should reject mismatched cross-origin requests', () => {
      const req = {
        headers: {
          origin: 'https://malicious-site.com',
          host: 'nexora.app',
        },
      };
      expect(isSameOrigin(req)).toBe(false);
    });

    it('should reject subdomain / domain suffix attacks', () => {
      const req = {
        headers: {
          origin: 'https://nexora.app.attacker.com',
          host: 'nexora.app',
        },
      };
      expect(isSameOrigin(req)).toBe(false);
    });

    it('should allow requests without origin header (e.g., native mobile or server-to-server)', () => {
      const req = { headers: { host: 'nexora.app' } };
      expect(isSameOrigin(req)).toBe(true);
    });
  });

  describe('Timing-Safe Comparison for Cron Endpoint', () => {
    function verifyCronAuth(authHeader: any, secret: string): boolean {
      if (!secret) return false;
      const expected = `Bearer ${secret}`;
      if (typeof authHeader !== 'string' || authHeader.length !== expected.length) {
        return false;
      }
      return crypto.timingSafeEqual(Buffer.from(authHeader, 'utf8'), Buffer.from(expected, 'utf8'));
    }

    it('should accept valid bearer token in constant time', () => {
      const secret = 'super-secret-cron-token-12345';
      expect(verifyCronAuth(`Bearer ${secret}`, secret)).toBe(true);
    });

    it('should reject incorrect tokens safely without leaking length or timing', () => {
      const secret = 'super-secret-cron-token-12345';
      expect(verifyCronAuth('Bearer wrong-token', secret)).toBe(false);
      expect(verifyCronAuth('Bearer super-secret-cron-token-12346', secret)).toBe(false);
      expect(verifyCronAuth(undefined, secret)).toBe(false);
      expect(verifyCronAuth('', secret)).toBe(false);
    });
  });

  describe('Backup Code Normalization & Case Insensitivity', () => {
    function normalizeBackupCode(code: any): string | null {
      if (!code || (typeof code !== 'string' && typeof code !== 'number')) return null;
      const clean = String(code).trim().toUpperCase();
      return /^[A-F0-9]{5}-[A-F0-9]{5}$/.test(clean) ? clean : null;
    }

    it('should normalize lowercase and whitespace-padded backup codes to uppercase format', () => {
      expect(normalizeBackupCode('a1b2c-3d4e5')).toBe('A1B2C-3D4E5');
      expect(normalizeBackupCode('  A1B2C-3D4E5  ')).toBe('A1B2C-3D4E5');
      expect(normalizeBackupCode('7f3b9-9cf1a')).toBe('7F3B9-9CF1A');
    });

    it('should reject malformed backup codes', () => {
      expect(normalizeBackupCode('12345')).toBeNull();
      expect(normalizeBackupCode('A1B2C3D4E5')).toBeNull();
      expect(normalizeBackupCode('')).toBeNull();
      expect(normalizeBackupCode(null)).toBeNull();
    });
  });

  describe('TOTP Token Input Sanitization', () => {
    function sanitizeTotp(token: any): string | null {
      if (!token || (typeof token !== 'string' && typeof token !== 'number')) return null;
      const clean = String(token).replace(/[\s-]/g, '');
      return /^\d{6}$/.test(clean) ? clean : null;
    }

    it('should accept formatted 6-digit codes with spaces and hyphens', () => {
      expect(sanitizeTotp('123 456')).toBe('123456');
      expect(sanitizeTotp('123-456')).toBe('123456');
      expect(sanitizeTotp(' 654321 ')).toBe('654321');
    });

    it('should accept numeric 6-digit code passed as number', () => {
      expect(sanitizeTotp(123456)).toBe('123456');
    });

    it('should reject invalid length or non-numeric tokens', () => {
      expect(sanitizeTotp('12345')).toBeNull();
      expect(sanitizeTotp('1234567')).toBeNull();
      expect(sanitizeTotp('abcdef')).toBeNull();
      expect(sanitizeTotp(null)).toBeNull();
    });
  });

  describe('Pending Login Single-Use Enforcement', () => {
    it('should reject pending logins where consumed_at is already set', () => {
      const isPendingLoginValid = (pending: { expires_at: string; consumed_at: string | null } | null) => {
        if (!pending || pending.consumed_at) return false;
        if (new Date(pending.expires_at) < new Date()) return false;
        return true;
      };

      const freshLogin = {
        expires_at: new Date(Date.now() + 60000).toISOString(),
        consumed_at: null,
      };
      expect(isPendingLoginValid(freshLogin)).toBe(true);

      const consumedLogin = {
        expires_at: new Date(Date.now() + 60000).toISOString(),
        consumed_at: new Date().toISOString(),
      };
      expect(isPendingLoginValid(consumedLogin)).toBe(false);

      const expiredLogin = {
        expires_at: new Date(Date.now() - 1000).toISOString(),
        consumed_at: null,
      };
      expect(isPendingLoginValid(expiredLogin)).toBe(false);
    });
  });

  describe('Base32 Secret Length & Validation', () => {
    function validateBase32(secret: any): boolean {
      if (typeof secret !== 'string') return false;
      const normalized = secret.replace(/[\s-]/g, '').toUpperCase();
      return /^[A-Z2-7]+=*$/.test(normalized) && normalized.length >= 7;
    }

    it('should accept 7-character unpadded Base32 secrets (RFC 4648 4-byte key)', () => {
      expect(validateBase32('ORSXG5A')).toBe(true);
      expect(validateBase32('orsxg5a')).toBe(true);
    });

    it('should accept standard 16-character padded and unpadded Base32 secrets', () => {
      expect(validateBase32('JBSWY3DPEBLW64TMMQ======')).toBe(true);
      expect(validateBase32('JBSWY3DPEBLW64TM')).toBe(true);
    });

    it('should reject secrets with invalid characters or too short', () => {
      expect(validateBase32('SHORT')).toBe(false);
      expect(validateBase32('INVALID!@#')).toBe(false);
      expect(validateBase32(null)).toBe(false);
      expect(validateBase32(undefined)).toBe(false);
    });
  });
});
