import { createBackup, restoreBackup } from '../src/backup';

const mockAccounts = [
  {
    id: 'test-1',
    issuer: 'GitHub',
    account: 'user@example.com',
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    createdAt: Date.now(),
    group: 'Personal',
    favorite: false,
    color: '#79AFFF',
    notes: '',
    secret: 'JBSWY3DPEBLW64TMMQ======',
  },
];

describe('Backup & Restore', () => {
  it('should create a valid encrypted backup', async () => {
    const backup = await createBackup(mockAccounts, 'secure-password-123');
    const parsed = JSON.parse(backup);

    expect(parsed.format).toBe('NEXORA_BACKUP');
    expect(parsed.version).toBe(1);
    expect(parsed.kdf).toBe('PBKDF2-SHA256');
    expect(parsed.cipher).toBe('XCHACHA20-POLY1305');
    expect(parsed.salt).toBeDefined();
    expect(parsed.nonce).toBeDefined();
    expect(parsed.ciphertext).toBeDefined();
  });

  it('should reject short passwords', async () => {
    await expect(createBackup(mockAccounts, 'short')).rejects.toThrow(
      'Use at least 10 characters'
    );
  });

  it('should restore backup with correct password', async () => {
    const backup = await createBackup(mockAccounts, 'secure-password-123');
    const restored = await restoreBackup(backup, 'secure-password-123');

    expect(restored).toHaveLength(1);
    expect(restored[0].issuer).toBe('GitHub');
    expect(restored[0].account).toBe('user@example.com');
    expect(restored[0].secret).toBe('JBSWY3DPEBLW64TMMQ======');
  });

  it('should reject invalid password during restore', async () => {
    const backup = await createBackup(mockAccounts, 'secure-password-123');
    await expect(restoreBackup(backup, 'wrong-password')).rejects.toThrow(
      'Could not decrypt'
    );
  });

  it('should reject malformed backup JSON', async () => {
    await expect(restoreBackup('not valid json', 'password')).rejects.toThrow(
      'not valid JSON'
    );
  });

  it('should validate backup format and version', async () => {
    const invalidBackup = JSON.stringify({
      format: 'INVALID',
      version: 99,
    });
    await expect(restoreBackup(invalidBackup, 'password')).rejects.toThrow(
      'Unsupported NEXORA backup format'
    );
  });

  it('should normalize secrets on restore', async () => {
    const accountsWithSpaces = [
      { ...mockAccounts[0], secret: 'JBSWY3DP EBLW64TM MQ======' },
    ];
    const backup = await createBackup(accountsWithSpaces, 'secure-password-123');
    const restored = await restoreBackup(backup, 'secure-password-123');

    expect(restored[0].secret).toBe('JBSWY3DPEBLW64TMMQ======');
  });
});
