import { loadPasswordEntries, savePasswordEntries, unlockPasswordVault } from '../src/passwordVault';

const secureValues = new Map<string, string>();
const asyncValues = new Map<string, string>();

jest.mock('expo-secure-store', () => ({
  getItemAsync: jest.fn(async (key: string) => secureValues.get(key) ?? null),
  setItemAsync: jest.fn(async (key: string, value: string) => { secureValues.set(key, value); }),
}));

jest.mock('@react-native-async-storage/async-storage', () => ({
  __esModule: true,
  default: {
    getItem: jest.fn(async (key: string) => asyncValues.get(key) ?? null),
    setItem: jest.fn(async (key: string, value: string) => { asyncValues.set(key, value); }),
  },
}));

describe('encrypted password vault', () => {
  beforeEach(() => {
    secureValues.clear();
    asyncValues.clear();
    jest.clearAllMocks();
  });

  it('encrypts entries and round-trips valid fields', async () => {
    const key = await unlockPasswordVault();
    const entry = {
      id: 'entry-1', title: 'GitHub', username: 'user@example.com',
      password: 'very-secret-value', website: 'https://github.com',
      notes: 'private note', category: 'Work', favorite: false,
      createdAt: 100, updatedAt: 200,
    };
    await savePasswordEntries(key, [entry]);

    const persisted = [...asyncValues.values()][0];
    expect(persisted).not.toContain('very-secret-value');
    expect(persisted).not.toContain('user@example.com');
    await expect(loadPasswordEntries(key)).resolves.toEqual([entry]);
  });

  it('does not return data when the encrypted envelope is corrupted', async () => {
    const key = await unlockPasswordVault();
    await savePasswordEntries(key, [{
      id: 'entry-2', title: 'Mail', username: '', password: 'secret',
      website: '', notes: '', category: 'General', favorite: false,
      createdAt: 1, updatedAt: 1,
    }]);
    const storedKey = [...asyncValues.keys()][0];
    asyncValues.set(storedKey, JSON.stringify({
      format: 'NEXORA_PASSWORD_VAULT', version: 1, nonce: '00', ciphertext: '00',
    }));
    await expect(loadPasswordEntries(key)).rejects.toThrow('Could not decrypt the password vault');
  });
});
