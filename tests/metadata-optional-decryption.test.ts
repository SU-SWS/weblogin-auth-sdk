
import { SAMLProvider } from '../src/saml';
import { DefaultLogger } from '../src/logger';
import { SamlConfig } from '../src/types';

describe('SAMLProvider Metadata Generation', () => {
  const validConfig: SamlConfig = {
    issuer: 'test-issuer',
    idpCert: 'test-certificate',
    returnToOrigin: 'https://app.example.com',
    entryPoint: 'https://idp.example.com/sso',
    returnToPath: '/auth/callback',
    privateKey: 'test-private-key',
    cert: 'test-public-cert',
  };
  const logger = new DefaultLogger();

  test('should call generateServiceProviderMetadata with null decryption cert when not provided', () => {
    const provider = new SAMLProvider(validConfig, logger);
    const mockGenerateMetadata = jest.fn().mockReturnValue('<EntityDescriptor />');
    (provider as any).provider = {
      generateServiceProviderMetadata: mockGenerateMetadata,
    };

    provider.getMetadata();

    expect(mockGenerateMetadata).toHaveBeenCalledWith(null, 'test-public-cert');
  });

  test('should call generateServiceProviderMetadata with decryption cert when provided in config', () => {
    const configWithDecryption = {
      ...validConfig,
      decryptionCert: 'test-decryption-cert',
    };
    const provider = new SAMLProvider(configWithDecryption, logger);
    const mockGenerateMetadata = jest.fn().mockReturnValue('<EntityDescriptor />');
    (provider as any).provider = {
      generateServiceProviderMetadata: mockGenerateMetadata,
    };

    provider.getMetadata();

    expect(mockGenerateMetadata).toHaveBeenCalledWith('test-decryption-cert', 'test-public-cert');
  });

  test('should call generateServiceProviderMetadata with decryption cert when provided as argument', () => {
    const provider = new SAMLProvider(validConfig, logger);
    const mockGenerateMetadata = jest.fn().mockReturnValue('<EntityDescriptor />');
    (provider as any).provider = {
      generateServiceProviderMetadata: mockGenerateMetadata,
    };

    provider.getMetadata('arg-decryption-cert');

    expect(mockGenerateMetadata).toHaveBeenCalledWith('arg-decryption-cert', 'test-public-cert');
  });
});
