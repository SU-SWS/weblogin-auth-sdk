import { SAMLProvider } from '../src/saml';
import { SamlConfig } from '../src/types';

describe('SAMLProvider Metadata Certificates', () => {
  const mockCert = '-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----';
  const mockDecryptionCert = '-----BEGIN CERTIFICATE-----\nMIIE...\n-----END CERTIFICATE-----';

  const baseConfig: SamlConfig = {
    issuer: 'test-issuer',
    idpCert: 'idp-cert',
    returnToOrigin: 'https://example.com',
    privateKey: 'test-private-key',
    cert: mockCert,
    decryptionCert: mockDecryptionCert,
  };

  it('should use configured certificates in metadata when not provided as arguments', () => {
    const provider = new SAMLProvider(baseConfig);
    const metadata = provider.getMetadata();

    // Check if the metadata contains the certificates
    // node-saml strips headers/footers, so we check for the body content or just the presence
    // Since we passed dummy strings, node-saml might just put them in.
    // However, node-saml might try to clean them.
    // Let's just check if the metadata string contains parts of our mock certs.

    // Note: node-saml generateServiceProviderMetadata puts the cert in <ds:X509Certificate>
    // It might strip the headers.

    expect(metadata).toContain('MIID...');
    expect(metadata).toContain('MIIE...');
  });

  it('should prioritize arguments over configured certificates', () => {
    const provider = new SAMLProvider(baseConfig);
    const argCert = '-----BEGIN CERTIFICATE-----\nARG_SIGNING...\n-----END CERTIFICATE-----';
    const argDecryptionCert = '-----BEGIN CERTIFICATE-----\nARG_DECRYPT...\n-----END CERTIFICATE-----';

    const metadata = provider.getMetadata(argDecryptionCert, argCert);

    expect(metadata).toContain('ARG_SIGNING...');
    expect(metadata).toContain('ARG_DECRYPT...');
    expect(metadata).not.toContain('MIID...');
    expect(metadata).not.toContain('MIIE...');
  });
});
