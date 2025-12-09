import { SAMLProvider } from '../src/saml';
import { SamlConfig } from '../src/types';

describe('SAMLProvider Configuration Options', () => {
  const baseConfig: SamlConfig = {
    issuer: 'test-issuer',
    idpCert: 'test-cert',
    returnToOrigin: 'https://example.com',
    privateKey: 'test-private-key',
    cert: 'test-public-cert',
  };

  it('should pass all configuration options to node-saml', () => {
    const fullConfig: SamlConfig = {
      ...baseConfig,
      signatureAlgorithm: 'sha512',
      digestAlgorithm: 'sha512',
      xmlSignatureTransforms: ['transform1'],
      identifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      allowCreate: true,
      spNameQualifier: 'sp-name',
      wantAssertionsSigned: false,
      wantAuthnResponseSigned: false,
      acceptedClockSkewMs: 1234,
      maxAssertionAgeMs: 5678,
      attributeConsumingServiceIndex: '1',
      disableRequestedAuthnContext: true,
      authnContext: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
      racComparison: 'minimum',
      forceAuthn: true,
      passive: true,
      providerName: 'provider-name',
      skipRequestCompression: true,
      authnRequestBinding: 'HTTP-POST',
      generateUniqueId: () => 'unique-id',
      scoping: { idpList: [] },
      signMetadata: true,
      validateInResponseTo: 'always',
      requestIdExpirationPeriodMs: 9999,
      idpIssuer: 'idp-issuer',
      logoutUrl: 'https://idp.example.com/logout',
      logoutCallbackUrl: 'https://example.com/logout/callback',
      samlAuthnRequestExtensions: { ext: 'val' },
      samlLogoutRequestExtensions: { ext: 'val' },
      metadataContactPerson: [{ contactType: 'technical' }],
      metadataOrganization: { name: 'org' },
      additionalParams: { param1: 'value1' },
      additionalAuthorizeParams: { authParam1: 'value1' },
      additionalLogoutParams: { logoutParam1: 'value1' },
      cert: 'public-cert',
    };

    const provider = new SAMLProvider(fullConfig);

    // Access private provider property to check config
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const nodeSamlInstance = (provider as any).provider;
    const options = nodeSamlInstance.options;

    expect(options.publicCert).toBe('public-cert');
    expect(options.signatureAlgorithm).toBe('sha512');
    expect(options.digestAlgorithm).toBe('sha512');
    expect(options.xmlSignatureTransforms).toEqual(['transform1']);
    expect(options.identifierFormat).toBe('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress');
    expect(options.allowCreate).toBe(true);
    expect(options.spNameQualifier).toBe('sp-name');
    expect(options.wantAssertionsSigned).toBe(false);
    expect(options.wantAuthnResponseSigned).toBe(false);
    expect(options.acceptedClockSkewMs).toBe(1234);
    expect(options.maxAssertionAgeMs).toBe(5678);
    expect(options.attributeConsumingServiceIndex).toBe('1');
    expect(options.disableRequestedAuthnContext).toBe(true);
    expect(options.authnContext).toBe('urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport');
    expect(options.racComparison).toBe('minimum');
    expect(options.forceAuthn).toBe(true);
    expect(options.passive).toBe(true);
    expect(options.providerName).toBe('provider-name');
    expect(options.skipRequestCompression).toBe(true);
    expect(options.authnRequestBinding).toBe('HTTP-POST');
    expect(options.generateUniqueId()).toBe('unique-id');
    expect(options.scoping).toEqual({ idpList: [] });
    expect(options.signMetadata).toBe(true);
    expect(options.validateInResponseTo).toBe('always');
    expect(options.requestIdExpirationPeriodMs).toBe(9999);
    expect(options.idpIssuer).toBe('idp-issuer');
    expect(options.logoutUrl).toBe('https://idp.example.com/logout');
    expect(options.logoutCallbackUrl).toBe('https://example.com/logout/callback');
    expect(options.samlAuthnRequestExtensions).toEqual({ ext: 'val' });
    expect(options.samlLogoutRequestExtensions).toEqual({ ext: 'val' });
    expect(options.metadataContactPerson).toEqual([{ contactType: 'technical' }]);
    expect(options.metadataOrganization).toEqual({ name: 'org' });
    expect(options.additionalParams).toEqual({ param1: 'value1' });
    expect(options.additionalAuthorizeParams).toEqual({ authParam1: 'value1' });
    expect(options.additionalLogoutParams).toEqual({ logoutParam1: 'value1' });
  });
});
