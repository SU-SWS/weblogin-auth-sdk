import { AuthUtils } from '../src/utils';
import { SAMLProvider } from '../src/saml';
import { SamlConfig } from '../src/types';

describe('Key Formatting', () => {
  describe('AuthUtils.formatKey', () => {
    it('should remove headers and footers from private key', () => {
      const key = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDZ
-----END PRIVATE KEY-----`;
      const expected = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDZ';
      expect(AuthUtils.formatKey(key)).toBe(expected);
    });

    it('should remove headers and footers from certificate', () => {
      const cert = `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAL
-----END CERTIFICATE-----`;
      const expected = 'MIIDXTCCAkWgAwIBAgIJAL';
      expect(AuthUtils.formatKey(cert)).toBe(expected);
    });

    it('should remove whitespace', () => {
      const key = `  MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDZ  `;
      const expected = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDZ';
      expect(AuthUtils.formatKey(key)).toBe(expected);
    });

    it('should handle empty string', () => {
      expect(AuthUtils.formatKey('')).toBe('');
    });

    it('should remove newlines from key content', () => {
      const key = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDZ
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDZ
-----END PRIVATE KEY-----`;
      const expected = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDZMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDZ';
      expect(AuthUtils.formatKey(key)).toBe(expected);
    });
  });

  describe('SAMLProvider Key Processing', () => {
    const validConfig: SamlConfig = {
      issuer: 'test-issuer',
      idpCert: 'test-certificate',
      returnToOrigin: 'https://app.example.com',
      entryPoint: 'https://idp.example.com/sso',
    };

    it('should clean idpCert in config', () => {
      const config = {
        ...validConfig,
        idpCert: `-----BEGIN CERTIFICATE-----
CLEAN_ME
-----END CERTIFICATE-----`
      };
      const provider = new SAMLProvider(config);
      // Access private provider instance to check config
      // @ts-expect-error this is testing private method.
      expect(provider.provider.options.idpCert).toBe('CLEAN_ME');
    });

    it('should clean privateKey in config', () => {
      const config = {
        ...validConfig,
        privateKey: `-----BEGIN PRIVATE KEY-----
CLEAN_ME_KEY
-----END PRIVATE KEY-----`
      };
      const provider = new SAMLProvider(config);
      // @ts-expect-error this is testing private method.
      expect(provider.provider.options.privateKey).toBe('CLEAN_ME_KEY');
    });

    it('should clean decryptionPvk in config', () => {
      const config = {
        ...validConfig,
        decryptionPvk: `-----BEGIN PRIVATE KEY-----
CLEAN_ME_DECRYPT
-----END PRIVATE KEY-----`
      };
      const provider = new SAMLProvider(config);
      // @ts-expect-error this is testing private method.
      expect(provider.provider.options.decryptionPvk).toBe('CLEAN_ME_DECRYPT');
    });

    it('should clean idpCert array in config', () => {
      const config = {
        ...validConfig,
        idpCert: [
          `-----BEGIN CERTIFICATE-----
CLEAN_ME_1
-----END CERTIFICATE-----`,
          `-----BEGIN CERTIFICATE-----
CLEAN_ME_2
-----END CERTIFICATE-----`
        ]
      };
      const provider = new SAMLProvider(config);
      // @ts-expect-error this is testing private method.
      expect(provider.provider.options.idpCert).toEqual(['CLEAN_ME_1', 'CLEAN_ME_2']);
    });
  });
});
