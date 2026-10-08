// TOTP and Account Validation Tests

function validateBase32(secret: string): boolean {
  return /^[A-Z2-7]+=*$/.test(secret) && secret.length >= 8;
}

function normalizeSecret(input: string): string {
  return input.replace(/[\s-]/g, '').toUpperCase();
}

describe('TOTP Secret Validation', () => {
  it('should accept valid Base32 secrets', () => {
    expect(validateBase32('JBSWY3DPEBLW64TMMQ======')).toBe(true);
    expect(validateBase32('ORSXG5A')).toBe(true);
    expect(validateBase32('JBSWY3DPEBLW64TMMQQ')).toBe(true);
  });

  it('should reject invalid Base32 characters', () => {
    expect(validateBase32('JBSWY3DPEBLW64TMMQ!!!')).toBe(false);
    expect(validateBase32('jbswy3dpeblw64tmmq======')).toBe(false);
  });

  it('should reject short secrets', () => {
    expect(validateBase32('SHORT')).toBe(false);
    expect(validateBase32('ABC')).toBe(false);
  });

  it('should normalize secrets with spaces and hyphens', () => {
    expect(normalizeSecret('JBSWY3DP EBLW64TM MQ======')).toBe(
      'JBSWY3DPEBLW64TMMQ======'
    );
    expect(normalizeSecret('JBSWY3DP-EBLW64TM-MQ=======')).toBe(
      'JBSWY3DPEBLW64TMMQ======='
    );
  });

  it('should handle mixed case input', () => {
    expect(normalizeSecret('jbswy3dp eblw64tm')).toBe('JBSWY3DPEBLW64TM');
  });
});

describe('Account Validation', () => {
  it('should validate required fields', () => {
    const isValidAccount = (account: any) =>
      account.issuer?.trim() &&
      account.account?.trim() &&
      validateBase32(account.secret) &&
      [6, 8].includes(account.digits) &&
      ['SHA1', 'SHA256', 'SHA512'].includes(account.algorithm) &&
      account.period >= 15 &&
      account.period <= 120;

    expect(
      isValidAccount({
        issuer: 'GitHub',
        account: 'user@example.com',
        secret: 'JBSWY3DPEBLW64TMMQ======',
        digits: 6,
        algorithm: 'SHA1',
        period: 30,
      })
    ).toBe(true);

    expect(
      isValidAccount({
        issuer: '',
        account: 'user@example.com',
        secret: 'JBSWY3DPEBLW64TMMQ======',
        digits: 6,
        algorithm: 'SHA1',
        period: 30,
      })
    ).toBe(false);

    expect(
      isValidAccount({
        issuer: 'GitHub',
        account: 'user@example.com',
        secret: 'SHORT',
        digits: 6,
        algorithm: 'SHA1',
        period: 30,
      })
    ).toBe(false);
  });

  it('should reject invalid digit counts', () => {
    const isValidDigits = (digits: number) => [6, 8].includes(digits);
    expect(isValidDigits(6)).toBe(true);
    expect(isValidDigits(8)).toBe(true);
    expect(isValidDigits(7)).toBe(false);
    expect(isValidDigits(4)).toBe(false);
  });

  it('should reject invalid algorithms', () => {
    const isValidAlgorithm = (algo: string) =>
      ['SHA1', 'SHA256', 'SHA512'].includes(algo);
    expect(isValidAlgorithm('SHA1')).toBe(true);
    expect(isValidAlgorithm('SHA256')).toBe(true);
    expect(isValidAlgorithm('MD5')).toBe(false);
  });

  it('should validate period range (15-120 seconds)', () => {
    const isValidPeriod = (period: number) => period >= 15 && period <= 120;
    expect(isValidPeriod(30)).toBe(true);
    expect(isValidPeriod(60)).toBe(true);
    expect(isValidPeriod(15)).toBe(true);
    expect(isValidPeriod(120)).toBe(true);
    expect(isValidPeriod(10)).toBe(false);
    expect(isValidPeriod(130)).toBe(false);
  });
});
