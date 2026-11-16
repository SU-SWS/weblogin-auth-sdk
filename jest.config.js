// iron-session v9 and its dependencies are ESM-only. Transpile them to
// CommonJS so tests run on Node versions without Jest require(esm) support.
const esmPackages = ['iron-session', 'iron-webcrypto', 'uint8array-extras', 'cookie'].join('|');

/** @type {import('jest').Config} */
export default {
  preset: 'ts-jest/presets/default',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: 'tsconfig.jest.json'
    }],
    [`^.+/node_modules/(${esmPackages})/.+\\.js$`]: ['ts-jest', {
      tsconfig: 'tsconfig.jest.json'
    }],
  },
  transformIgnorePatterns: [
    `/node_modules/(?!(${esmPackages})/)`,
  ],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/index.ts', // Exclude barrel exports
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
  moduleFileExtensions: ['ts', 'js', 'json'],
  resolver: '<rootDir>/jest.resolver.cjs',
  verbose: true,
};
