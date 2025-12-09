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

  describe('AuthUtils.formatPrivateKey', () => {
    it('should wrap raw base64 key in PEM headers', () => {
      const rawKey = 'MIIEvQIBADANBgkqhkiG9w0BAQEF';
      const result = AuthUtils.formatPrivateKey(rawKey);
      expect(result).toBe('-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEF\n-----END PRIVATE KEY-----');
    });

    it('should normalize PEM key with existing headers', () => {
      const key = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEF
-----END PRIVATE KEY-----`;
      const result = AuthUtils.formatPrivateKey(key);
      expect(result).toBe('-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEF\n-----END PRIVATE KEY-----');
    });

    it('should add line breaks every 64 characters', () => {
      const longKey = 'A'.repeat(128);
      const result = AuthUtils.formatPrivateKey(longKey);
      const lines = result.split('\n');
      expect(lines[0]).toBe('-----BEGIN PRIVATE KEY-----');
      expect(lines[1]).toBe('A'.repeat(64));
      expect(lines[2]).toBe('A'.repeat(64));
      expect(lines[3]).toBe('-----END PRIVATE KEY-----');
    });

    it('should handle empty string', () => {
      expect(AuthUtils.formatPrivateKey('')).toBe('');
    });

    it('should handle RSA PRIVATE KEY headers', () => {
      const key = `-----BEGIN RSA PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEF
-----END RSA PRIVATE KEY-----`;
      const result = AuthUtils.formatPrivateKey(key);
      // Should normalize to standard PRIVATE KEY header
      expect(result).toBe('-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEF\n-----END PRIVATE KEY-----');
    });
  });

  describe('AuthUtils.formatCertificate', () => {
    it('should wrap raw base64 cert in PEM headers', () => {
      const rawCert = 'MIIDXTCCAkWgAwIBAgIJAL';
      const result = AuthUtils.formatCertificate(rawCert);
      expect(result).toBe('-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAL\n-----END CERTIFICATE-----');
    });

    it('should normalize PEM cert with existing headers', () => {
      const cert = `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAL
-----END CERTIFICATE-----`;
      const result = AuthUtils.formatCertificate(cert);
      expect(result).toBe('-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAL\n-----END CERTIFICATE-----');
    });

    it('should handle empty string', () => {
      expect(AuthUtils.formatCertificate('')).toBe('');
    });
  });

  describe('SAMLProvider Key Processing', () => {
    const validConfig: SamlConfig = {
      issuer: 'test-issuer',
      idpCert: 'test-certificate',
      returnToOrigin: 'https://app.example.com',
      entryPoint: 'https://idp.example.com/sso',
      privateKey: 'test-private-key',
      cert: 'test-public-cert',
      decryptionPvk: 'test-decryption-key',
      decryptionCert: 'test-decryption-cert',
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

    it('should normalize privateKey to PEM format', () => {
      const config = {
        ...validConfig,
        privateKey: `-----BEGIN PRIVATE KEY-----
CLEAN_ME_KEY
-----END PRIVATE KEY-----`
      };
      const provider = new SAMLProvider(config);
      // @ts-expect-error this is testing private method.
      // privateKey must be in PEM format for node-saml signing operations
      expect(provider.provider.options.privateKey).toBe('-----BEGIN PRIVATE KEY-----\nCLEAN_ME_KEY\n-----END PRIVATE KEY-----');
    });

    it('should normalize decryptionPvk to PEM format', () => {
      const config = {
        ...validConfig,
        decryptionPvk: `-----BEGIN PRIVATE KEY-----
CLEAN_ME_DECRYPT
-----END PRIVATE KEY-----`
      };
      const provider = new SAMLProvider(config);
      // @ts-expect-error this is testing private method.
      // decryptionPvk must be in PEM format for node-saml decryption
      expect(provider.provider.options.decryptionPvk).toBe('-----BEGIN PRIVATE KEY-----\nCLEAN_ME_DECRYPT\n-----END PRIVATE KEY-----');
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
