/* eslint-disable @typescript-eslint/no-explicit-any */
import { SAMLProvider } from '../src/saml';
import { DefaultLogger } from '../src/logger';
import type { SamlConfig } from '../src/types';

describe('SAMLProvider Metadata', () => {
  const validConfig: SamlConfig = {
    issuer: 'test-issuer',
    idpCert: 'test-certificate',
    returnToOrigin: 'https://app.example.com',
    entryPoint: 'https://idp.example.com/sso',
    returnToPath: '/auth/callback',
  };

  const logger = new DefaultLogger();

  test('should generate metadata', () => {
    const provider = new SAMLProvider(validConfig, logger);

    // Mock the underlying provider's generateServiceProviderMetadata
    const mockGenerateMetadata = jest.fn().mockReturnValue('<EntityDescriptor>...</EntityDescriptor>');
    (provider as any).provider = {
      generateServiceProviderMetadata: mockGenerateMetadata,
    };

    const metadata = provider.getMetadata();

    expect(metadata).toMatch(/<EntityDescriptor validUntil="[^"]+">...<\/EntityDescriptor>/);
    expect(mockGenerateMetadata).toHaveBeenCalledWith(null, null);
  });

  test('should generate metadata with certificates', () => {
    const provider = new SAMLProvider(validConfig, logger);

    const mockGenerateMetadata = jest.fn().mockReturnValue('<EntityDescriptor>...</EntityDescriptor>');
    (provider as any).provider = {
      generateServiceProviderMetadata: mockGenerateMetadata,
    };

    const decryptionCert = 'decryption-cert';
    const signingCert = 'signing-cert';

    const metadata = provider.getMetadata(decryptionCert, signingCert);

    expect(metadata).toMatch(/<EntityDescriptor validUntil="[^"]+">...<\/EntityDescriptor>/);
    expect(mockGenerateMetadata).toHaveBeenCalledWith(decryptionCert, signingCert);
  });
});
