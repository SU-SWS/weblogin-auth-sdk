import { SAMLProvider } from '../src/saml';
import { DefaultLogger } from '../src/logger';
import type { SamlConfig } from '../src/types';

describe('SAMLProvider Skip ACS URL Validation', () => {
  const validConfig: SamlConfig = {
    issuer: 'test-issuer',
    idpCert: 'test-certificate',
    returnToOrigin: 'https://app.example.com',
    entryPoint: 'https://idp.example.com/sso',
    returnToPath: '/auth/callback',
  };

  const logger = new DefaultLogger();

  test('should pass disableRequestAcsUrl to node-saml when skipRequestAcsUrl is true', () => {
    const config = {
      ...validConfig,
      skipRequestAcsUrl: true,
    };
    const provider = new SAMLProvider(config, logger);

    // Access private provider instance to check config
    // @ts-expect-error this is testing private method.
    expect(provider.provider.options.disableRequestAcsUrl).toBe(true);
  });

  test('should not pass disableRequestAcsUrl to node-saml when skipRequestAcsUrl is false', () => {
    const config = {
      ...validConfig,
      skipRequestAcsUrl: false,
    };
    const provider = new SAMLProvider(config, logger);

    // @ts-expect-error this is testing private method.
    expect(provider.provider.options.disableRequestAcsUrl).toBe(false);
  });

  test('should default skipRequestAcsUrl to false', () => {
    const provider = new SAMLProvider(validConfig, logger);

    // @ts-expect-error this is testing private method.
    expect(provider.provider.options.disableRequestAcsUrl).toBe(false);
  });
});
