module.exports = {
  preset: 'jest-expo/ios',
  testEnvironment: 'node',
  transform: {
    '^.+\\.tsx?$': ['babel-jest', { presets: ['babel-preset-expo'] }],
  },
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/$1',
  },
  setupFilesAfterEnv: ['<rootDir>/jest.setup.js'],
  testPathIgnorePatterns: ['/node_modules/', '/dist/'],
  collectCoverageFrom: [\n    'src/**/*.{ts,tsx}',\n    'lib/**/*.{js,ts}',\n    '!**/*.d.ts',\n    '!**/node_modules/**',\n    '!**/__tests__/**',\n  ],\n  testMatch: [\n    '**/__tests__/**/*.(test|spec).(ts|tsx|js)',\n    '**/*.(test|spec).(ts|tsx|js)',\n  ],\n  globals: {\n    'ts-jest': {\n      tsconfig: {\n        jsx: 'react-native',\n      },\n    },\n  },\n};\n