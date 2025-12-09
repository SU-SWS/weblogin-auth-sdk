import { WebLoginNext } from '../src/next';
import type { WebLoginNextConfig } from '../src/types';

// Mock next/headers
jest.mock('next/headers', () => ({
  cookies: jest.fn(),
}));

// Mock next/navigation
jest.mock('next/navigation', () => ({
  redirect: jest.fn(),
}));

describe('WebLoginNext Metadata', () => {
  const validConfig: WebLoginNextConfig = {
    saml: {
      issuer: 'test-issuer',
      idpCert: 'test-certificate',
      returnToOrigin: 'https://app.example.com',
      privateKey: 'test-private-key',
      cert: 'test-public-cert',
    },
    session: {
      name: 'test-session',
      secret: 'test-secret-must-be-at-least-32-chars-long',
    },
  };

  test('should expose getMetadata method', () => {
    const auth = new WebLoginNext(validConfig);

    // Mock the underlying samlProvider's getMetadata
    const mockGetMetadata = jest.fn().mockReturnValue('<EntityDescriptor>...</EntityDescriptor>');
    (auth as any).samlProvider = {
      getMetadata: mockGetMetadata,
    };

    const metadata = auth.getMetadata();

    expect(metadata).toBe('<EntityDescriptor>...</EntityDescriptor>');
    expect(mockGetMetadata).toHaveBeenCalledWith(undefined, undefined);
  });

  test('should pass certificates to getMetadata', () => {
    const auth = new WebLoginNext(validConfig);

    const mockGetMetadata = jest.fn().mockReturnValue('<EntityDescriptor>...</EntityDescriptor>');
    (auth as any).samlProvider = {
      getMetadata: mockGetMetadata,
    };

    const decryptionCert = 'decryption-cert';
    const signingCert = 'signing-cert';

    const metadata = auth.getMetadata(decryptionCert, signingCert);

    expect(metadata).toBe('<EntityDescriptor>...</EntityDescriptor>');
    expect(mockGetMetadata).toHaveBeenCalledWith(decryptionCert, signingCert);
  });

  test('should throw error if called in browser environment', () => {
    const auth = new WebLoginNext(validConfig);

    // Simulate browser environment
    const originalWindow = global.window;
    global.window = {} as any;

    expect(() => {
      auth.getMetadata();
    }).toThrow('WebLoginNext.getMetadata() should not be called in a browser environment');

    // Restore environment
    global.window = originalWindow;
  });
});
