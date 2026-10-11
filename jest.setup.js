// Minimal Jest setup - basic mocks only
global.__DEV__ = true;
global.alert = jest.fn();
global.console = {
  ...console,
  error: jest.fn(),
  warn: jest.fn(),
};

jest.mock('expo-crypto', () => {
  const nodeCrypto = require('crypto');
  return {
    getRandomBytes: (n) => new Uint8Array(nodeCrypto.randomBytes(n)),
    randomUUID: () => nodeCrypto.randomUUID(),
  };
});
