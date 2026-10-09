// Minimal Jest setup - basic mocks only
global.alert = jest.fn();
global.console = {
  ...console,
  error: jest.fn(),
  warn: jest.fn(),
};
