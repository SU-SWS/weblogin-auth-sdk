/* eslint-disable @typescript-eslint/no-explicit-any */
import { SAMLProvider } from '../src/saml';
import { AuthError, MFA } from '../src/types';
import { DefaultLogger } from '../src/logger';
import type { SAMLProfile, SamlConfig, AuthenticateOptions } from '../src/types';

// Mock Web API Request
global.Request = jest.fn().mockImplementation((input, init) => ({
  text: jest.fn(),
  ...init,
}));

interface MockRequest {
  text: () => Promise<string>;
}

describe('SAMLProvider', () => {
  const validConfig: SamlConfig = {
    issuer: 'test-issuer',
    idpCert: 'test-certificate',
    returnToOrigin: 'https://app.example.com',
    entryPoint: 'https://idp.example.com/sso',
    returnToPath: '/auth/callback',
    privateKey: 'test-private-key',
    cert: 'test-public-cert',
    decryptionPvk: 'test-decryption-key',
    decryptionCert: 'test-decryption-cert',
  };

  const logger = new DefaultLogger();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('constructor', () => {
    test('should create SAMLProvider with valid config', () => {
      const provider = new SAMLProvider(validConfig, logger);
      expect(provider).toBeInstanceOf(SAMLProvider);
    });

    test('should throw AuthError for missing required config when no env vars', () => {
      const originalIssuer = process.env.WEBLOGIN_AUTH_ISSUER;
      const originalCert = process.env.WEBLOGIN_AUTH_SAML_CERT;
      const originalOrigin = process.env.WEBLOGIN_AUTH_ACS_URL_ORIGIN;

      delete process.env.WEBLOGIN_AUTH_ISSUER;
      delete process.env.WEBLOGIN_AUTH_SAML_CERT;
      delete process.env.WEBLOGIN_AUTH_ACS_URL_ORIGIN;

      expect(() => {
        new SAMLProvider({} as SamlConfig, logger);
      }).toThrow(AuthError);

      if (originalIssuer) process.env.WEBLOGIN_AUTH_ISSUER = originalIssuer;
      if (originalCert) process.env.WEBLOGIN_AUTH_SAML_CERT = originalCert;
      if (originalOrigin) process.env.WEBLOGIN_AUTH_ACS_URL_ORIGIN = originalOrigin;
    });

    test('should throw AuthError for missing issuer when no env vars', () => {
      const originalIssuer = process.env.WEBLOGIN_AUTH_ISSUER;
      delete process.env.WEBLOGIN_AUTH_ISSUER;

      const invalidConfig = { ...validConfig };
      delete (invalidConfig as Partial<SamlConfig>).issuer;

      expect(() => {
        new SAMLProvider(invalidConfig, logger);
      }).toThrow(AuthError);

      if (originalIssuer) process.env.WEBLOGIN_AUTH_ISSUER = originalIssuer;
    });

    test('should throw AuthError for missing idpCert when no env vars', () => {
      const originalCert = process.env.WEBLOGIN_AUTH_SAML_CERT;
      delete process.env.WEBLOGIN_AUTH_SAML_CERT;

      const invalidConfig = { ...validConfig };
      delete (invalidConfig as Partial<SamlConfig>).idpCert;

      expect(() => {
        new SAMLProvider(invalidConfig, logger);
      }).toThrow(AuthError);

      if (originalCert) process.env.WEBLOGIN_AUTH_SAML_CERT = originalCert;
    });
  });

  describe('configuration options', () => {
    test('should default skipRequestAcsUrl to true', () => {
      const provider = new SAMLProvider(validConfig, logger);
      // @ts-expect-error accessing private property for testing
      expect(provider.provider.options.disableRequestAcsUrl).toBe(true);
    });

    test('should pass disableRequestAcsUrl when skipRequestAcsUrl is true', () => {
      const config = { ...validConfig, skipRequestAcsUrl: true };
      const provider = new SAMLProvider(config, logger);
      // @ts-expect-error accessing private property for testing
      expect(provider.provider.options.disableRequestAcsUrl).toBe(true);
    });

    test('should not pass disableRequestAcsUrl when skipRequestAcsUrl is false', () => {
      const config = { ...validConfig, skipRequestAcsUrl: false };
      const provider = new SAMLProvider(config, logger);
      // @ts-expect-error accessing private property for testing
      expect(provider.provider.options.disableRequestAcsUrl).toBe(false);
    });

    test('should pass all configuration options to node-saml', () => {
      const fullConfig: SamlConfig = {
        ...validConfig,
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
      };

      const provider = new SAMLProvider(fullConfig);
      // @ts-expect-error accessing private property for testing
      const options = provider.provider.options;

      // Certificates and keys are now in PEM format
      expect(options.publicCert).toContain('test-public-cert');
      expect(options.publicCert).toContain('-----BEGIN CERTIFICATE-----');
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

    test('should clean idpCert headers/footers', () => {
      const config = {
        ...validConfig,
        idpCert: `-----BEGIN CERTIFICATE-----
CLEAN_ME
-----END CERTIFICATE-----`
      };
      const provider = new SAMLProvider(config);
      // @ts-expect-error accessing private property for testing
      expect(provider.provider.options.idpCert).toBe('CLEAN_ME');
    });

    test('should normalize privateKey to PEM format', () => {
      const config = {
        ...validConfig,
        privateKey: `-----BEGIN PRIVATE KEY-----
CLEAN_ME_KEY
-----END PRIVATE KEY-----`
      };
      const provider = new SAMLProvider(config);
      // @ts-expect-error accessing private property for testing
      // privateKey must be in PEM format for node-saml signing operations
      expect(provider.provider.options.privateKey).toBe('-----BEGIN PRIVATE KEY-----\nCLEAN_ME_KEY\n-----END PRIVATE KEY-----');
    });

    test('should normalize decryptionPvk to PEM format', () => {
      const config = {
        ...validConfig,
        decryptionPvk: `-----BEGIN PRIVATE KEY-----
CLEAN_ME_DECRYPT
-----END PRIVATE KEY-----`
      };
      const provider = new SAMLProvider(config);
      // @ts-expect-error accessing private property for testing
      // decryptionPvk must be in PEM format for node-saml decryption
      expect(provider.provider.options.decryptionPvk).toBe('-----BEGIN PRIVATE KEY-----\nCLEAN_ME_DECRYPT\n-----END PRIVATE KEY-----');
    });

    test('should clean idpCert array headers/footers', () => {
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
      // @ts-expect-error accessing private property for testing
      expect(provider.provider.options.idpCert).toEqual(['CLEAN_ME_1', 'CLEAN_ME_2']);
    });
  });

  describe('getLoginUrl', () => {
    test('should generate login URL with returnTo', async () => {
      const provider = new SAMLProvider(validConfig, logger);
      const mockGetAuthorizeUrlAsync = jest.fn().mockResolvedValue('https://idp.example.com/sso?SAMLRequest=xyz&RelayState=abc');
      (provider as any).provider = {
        getAuthorizeUrlAsync: mockGetAuthorizeUrlAsync,
      };

      const result = await provider.getLoginUrl({ returnTo: 'https://app.example.com/dashboard' });

      expect(result).toContain('https://idp.example.com/sso');
      expect(mockGetAuthorizeUrlAsync).toHaveBeenCalledWith(
        expect.stringContaining('"return_to":"https://app.example.com/dashboard"'),
        undefined,
        expect.any(Object)
      );
    });

    test('should generate login URL without returnTo', async () => {
      const provider = new SAMLProvider(validConfig, logger);
      const mockGetAuthorizeUrlAsync = jest.fn().mockResolvedValue('https://idp.example.com/sso?SAMLRequest=xyz');
      (provider as any).provider = {
        getAuthorizeUrlAsync: mockGetAuthorizeUrlAsync,
      };

      await provider.getLoginUrl();

      expect(mockGetAuthorizeUrlAsync).toHaveBeenCalledWith(
        expect.stringContaining('"return_to":"/"'),
        undefined,
        expect.any(Object)
      );
    });

    test('should include custom additional params', async () => {
      const provider = new SAMLProvider(validConfig, logger);
      const mockGetAuthorizeUrlAsync = jest.fn().mockResolvedValue('https://idp.example.com/sso?SAMLRequest=xyz');
      (provider as any).provider = {
        getAuthorizeUrlAsync: mockGetAuthorizeUrlAsync,
      };

      await provider.getLoginUrl({
        returnTo: '/dashboard',
        customParam: 'value'
      });

      expect(mockGetAuthorizeUrlAsync).toHaveBeenCalledWith(
        expect.any(String),
        undefined,
        expect.objectContaining({ customParam: 'value' })
      );
    });

    test('should pass forceAuthn to node-saml', async () => {
      const provider = new SAMLProvider(validConfig, logger);
      const mockGetAuthorizeUrlAsync = jest.fn().mockResolvedValue('https://idp.example.com/sso');
      (provider as any).provider = {
        getAuthorizeUrlAsync: mockGetAuthorizeUrlAsync,
      };

      await provider.getLoginUrl({ forceAuthn: true });

      expect(mockGetAuthorizeUrlAsync).toHaveBeenCalledWith(
        expect.any(String),
        undefined,
        expect.objectContaining({ forceAuthn: true })
      );
    });

    test('should pass MFA context to node-saml', async () => {
      const provider = new SAMLProvider(validConfig, logger);
      const mockGetAuthorizeUrlAsync = jest.fn().mockResolvedValue('https://idp.example.com/sso');
      (provider as any).provider = {
        getAuthorizeUrlAsync: mockGetAuthorizeUrlAsync,
      };

      await provider.getLoginUrl({ mfa: MFA.REFEDS });

      expect(mockGetAuthorizeUrlAsync).toHaveBeenCalledWith(
        expect.any(String),
        undefined,
        expect.objectContaining({
          authnContext: [MFA.REFEDS]
        })
      );
    });

    test('should handle both forceAuthn and MFA', async () => {
      const provider = new SAMLProvider(validConfig, logger);
      const mockGetAuthorizeUrlAsync = jest.fn().mockResolvedValue('https://idp.example.com/sso');
      (provider as any).provider = {
        getAuthorizeUrlAsync: mockGetAuthorizeUrlAsync,
      };

      await provider.getLoginUrl({ forceAuthn: true, mfa: MFA.CARDINAL_KEY });

      expect(mockGetAuthorizeUrlAsync).toHaveBeenCalledWith(
        expect.any(String),
        undefined,
        expect.objectContaining({
          forceAuthn: true,
          authnContext: [MFA.CARDINAL_KEY]
        })
      );
    });

    test('should use dynamic origin for ACS URL when skipRequestAcsUrl is false', async () => {
      const config = { ...validConfig, skipRequestAcsUrl: false, returnToPath: '/api/auth/callback' };
      const provider = new SAMLProvider(config, logger);
      const mockGetAuthorizeUrlAsync = jest.fn().mockResolvedValue('https://idp.example.com/sso');
      (provider as any).provider = {
        getAuthorizeUrlAsync: mockGetAuthorizeUrlAsync,
      };

      await provider.getLoginUrl({
        origin: 'https://localhost:3000',
        returnTo: '/dashboard'
      });

      expect(mockGetAuthorizeUrlAsync).toHaveBeenCalledWith(
        expect.any(String),
        undefined,
        expect.objectContaining({
          callbackUrl: 'https://localhost:3000/api/auth/callback'
        })
      );
    });

    test('should not use dynamic origin when skipRequestAcsUrl is true', async () => {
      const config = { ...validConfig, skipRequestAcsUrl: true };
      const provider = new SAMLProvider(config, logger);
      const mockGetAuthorizeUrlAsync = jest.fn().mockResolvedValue('https://idp.example.com/sso');
      (provider as any).provider = {
        getAuthorizeUrlAsync: mockGetAuthorizeUrlAsync,
      };

      await provider.getLoginUrl({
        origin: 'https://localhost:3000',
        returnTo: '/dashboard'
      });

      // Should NOT include callbackUrl since skipRequestAcsUrl is true
      expect(mockGetAuthorizeUrlAsync).toHaveBeenCalledWith(
        expect.any(String),
        undefined,
        expect.not.objectContaining({
          callbackUrl: expect.any(String)
        })
      );
    });

    test('should not include origin in additionalParams', async () => {
      const config = { ...validConfig, skipRequestAcsUrl: false };
      const provider = new SAMLProvider(config, logger);
      const mockGetAuthorizeUrlAsync = jest.fn().mockResolvedValue('https://idp.example.com/sso');
      (provider as any).provider = {
        getAuthorizeUrlAsync: mockGetAuthorizeUrlAsync,
      };

      await provider.getLoginUrl({
        origin: 'https://localhost:3000',
        returnTo: '/dashboard',
        customParam: 'value'
      });

      // origin should not be passed through to node-saml
      const callArgs = mockGetAuthorizeUrlAsync.mock.calls[0][2];
      expect(callArgs.origin).toBeUndefined();
      expect(callArgs.customParam).toBe('value');
    });
  });

  describe('authenticate', () => {
    test('should authenticate valid SAML response', async () => {
      const mockProfile: SAMLProfile = {
        issuer: 'test-issuer',
        sessionIndex: 'session-123',
        nameID: 'user@example.com',
        nameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        'oracle:cloud:identity:sessionid': 'session-123',
        encodedSUID: 'encoded-suid-123',
        'oracle:cloud:identity:url': 'https://oracle.stanford.edu',
        userName: 'testuser',
        firstName: 'John',
        lastName: 'Doe',
      };

      const mockValidateResponse = jest.fn().mockResolvedValue({
        profile: mockProfile,
      });

      const provider = new SAMLProvider(validConfig, logger);
      (provider as any).provider = {
        validatePostResponseAsync: mockValidateResponse,
      };

      const mockReq = {
        text: jest.fn().mockResolvedValue('SAMLResponse=encoded-response&RelayState=relay-state')
      } as MockRequest;
      Object.setPrototypeOf(mockReq, Request.prototype);

      const options: AuthenticateOptions = {
        req: mockReq as any,
      };

      const result = await provider.authenticate(options);

      expect(mockValidateResponse).toHaveBeenCalledWith({
        SAMLResponse: 'encoded-response',
      });
      expect(result.profile).toEqual(mockProfile);
      expect(result.user).toEqual({
        id: mockProfile.encodedSUID,
        email: `${mockProfile.userName}@stanford.edu`,
        name: `${mockProfile.firstName} ${mockProfile.lastName}`,
        encodedSUID: mockProfile.encodedSUID,
        userName: mockProfile.userName,
        firstName: mockProfile.firstName,
        lastName: mockProfile.lastName,
        issuer: mockProfile.issuer,
        sessionIndex: mockProfile.sessionIndex,
        nameID: mockProfile.nameID,
        nameIDFormat: mockProfile.nameIDFormat,
        'oracle:cloud:identity:sessionid': mockProfile['oracle:cloud:identity:sessionid'],
        'oracle:cloud:identity:url': mockProfile['oracle:cloud:identity:url'],
      });
    });

    test('should handle authentication errors', async () => {
      const mockValidateResponse = jest.fn().mockRejectedValue(new Error('Invalid SAML response'));

      const provider = new SAMLProvider(validConfig, logger);
      (provider as any).provider = {
        validatePostResponseAsync: mockValidateResponse,
      };

      const mockReq = {
        text: jest.fn().mockResolvedValue('SAMLResponse=invalid-response')
      } as MockRequest;
      Object.setPrototypeOf(mockReq, Request.prototype);

      const options: AuthenticateOptions = {
        req: mockReq as any,
      };

      await expect(provider.authenticate(options)).rejects.toThrow(AuthError);
    });

    test('should handle missing SAML response', async () => {
      const provider = new SAMLProvider(validConfig, logger);

      const mockReq = {
        text: jest.fn().mockResolvedValue('')
      } as MockRequest;
      Object.setPrototypeOf(mockReq, Request.prototype);

      const options: AuthenticateOptions = {
        req: mockReq as any,
      };

      await expect(provider.authenticate(options)).rejects.toThrow(AuthError);
    });

    test('should handle missing profile in response', async () => {
      const mockValidateResponse = jest.fn().mockResolvedValue({
        profile: null,
      });

      const provider = new SAMLProvider(validConfig, logger);
      (provider as any).provider = {
        validatePostResponseAsync: mockValidateResponse,
      };

      const mockReq = {
        text: jest.fn().mockResolvedValue('SAMLResponse=encoded-response')
      } as MockRequest;
      Object.setPrototypeOf(mockReq, Request.prototype);

      const options: AuthenticateOptions = {
        req: mockReq as any,
      };

      await expect(provider.authenticate(options)).rejects.toThrow(AuthError);
    });

    test('should map OID attributes to friendly names', async () => {
      const mockProfile: SAMLProfile = {
        issuer: 'test-issuer',
        sessionIndex: 'session-123',
        nameID: 'user@example.com',
        nameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        'oracle:cloud:identity:sessionid': 'session-123',
        encodedSUID: 'encoded-suid-123',
        'oracle:cloud:identity:url': 'https://oracle.stanford.edu',
        userName: 'testuser',
        'urn:oid:0.9.2342.19200300.100.1.3': 'oid-email@example.com',
        'urn:oid:2.5.4.42': 'OIDGivenName',
        'urn:oid:2.5.4.4': 'OIDSurname',
        'urn:oid:2.16.840.1.113730.3.1.241': 'OID Display Name',
      };

      const mockValidateResponse = jest.fn().mockResolvedValue({
        profile: mockProfile,
      });

      const provider = new SAMLProvider(validConfig, logger);
      (provider as any).provider = {
        validatePostResponseAsync: mockValidateResponse,
      };

      const mockReq = {
        text: jest.fn().mockResolvedValue('SAMLResponse=encoded-response&RelayState=relay-state')
      } as MockRequest;
      Object.setPrototypeOf(mockReq, Request.prototype);

      const options: AuthenticateOptions = {
        req: mockReq as any,
      };

      const result = await provider.authenticate(options);

      expect(result.user).toMatchObject({
        mail: 'oid-email@example.com',
        givenName: 'OIDGivenName',
        sn: 'OIDSurname',
        displayName: 'OID Display Name',
      });
      expect(result.user.name).toBe('OID Display Name');
    });

    test('should use mapped OID attributes for user fields when standard attributes are missing', async () => {
      const mockProfile: SAMLProfile = {
        issuer: 'test-issuer',
        sessionIndex: 'session-123',
        nameID: 'user@example.com',
        nameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        'oracle:cloud:identity:sessionid': 'session-123',
        encodedSUID: 'encoded-suid-123',
        'oracle:cloud:identity:url': 'https://oracle.stanford.edu',
        userName: 'testuser',
        'urn:oid:0.9.2342.19200300.100.1.3': 'oid-email@example.com',
        'urn:oid:2.5.4.42': 'OIDGivenName',
        'urn:oid:2.5.4.4': 'OIDSurname',
      };

      const mockValidateResponse = jest.fn().mockResolvedValue({
        profile: mockProfile,
      });

      const provider = new SAMLProvider(validConfig, logger);
      (provider as any).provider = {
        validatePostResponseAsync: mockValidateResponse,
      };

      const mockReq = {
        text: jest.fn().mockResolvedValue('SAMLResponse=encoded-response&RelayState=relay-state')
      } as MockRequest;
      Object.setPrototypeOf(mockReq, Request.prototype);

      const options: AuthenticateOptions = {
        req: mockReq as any,
      };

      const result = await provider.authenticate(options);

      expect(result.user.email).toBe('oid-email@example.com');
      expect(result.user.name).toBe('OIDGivenName OIDSurname');
    });

    test('should map Stanford-specific attributes correctly', async () => {
      const mockProfile = {
        issuer: 'idp',
        sessionIndex: '123',
        nameID: 'user',
        'oracle:cloud:identity:sessionid': 'session-123',
        encodedSUID: 'encoded-suid-123',
        'oracle:cloud:identity:url': 'https://oracle.stanford.edu',
        userName: 'testuser',
        attributes: {
          'urn:oid:1.3.6.1.4.1.5923.1.1.1.16': '0000-0000-0000-0000',
          'urn:oasis:names:tc:SAML:attribute:subject-id': 'user@stanford.edu',
          'urn:oasis:names:tc:SAML:attribute:pairwise-id': 'pairwise-id-value',
        }
      };

      const mockValidateResponse = jest.fn().mockResolvedValue({ profile: mockProfile });

      const provider = new SAMLProvider(validConfig, logger);
      (provider as any).provider = {
        validatePostResponseAsync: mockValidateResponse,
      };

      const mockReq = {
        text: jest.fn().mockResolvedValue('SAMLResponse=encoded-response')
      } as MockRequest;
      Object.setPrototypeOf(mockReq, Request.prototype);

      const { user } = await provider.authenticate({ req: mockReq as any });

      expect(user).toMatchObject({
        eduPersonOrcid: '0000-0000-0000-0000',
        'subject-id': 'user@stanford.edu',
        'pairwise-id': 'pairwise-id-value',
      });
    });
  });

  describe('login', () => {
    test('should return redirect response', async () => {
      const provider = new SAMLProvider(validConfig, logger);
      const mockGetAuthorizeUrlAsync = jest.fn().mockResolvedValue('https://idp.example.com/sso');
      (provider as any).provider = {
        getAuthorizeUrlAsync: mockGetAuthorizeUrlAsync,
      };

      const response = await provider.login();
      expect(response).toBeInstanceOf(Response);
      expect(response.status).toBe(302);
      expect(response.headers.get('Location')).toBe('https://idp.example.com/sso');
    });
  });

  describe('getMetadata', () => {
    test('should generate metadata with validUntil attribute', () => {
      const provider = new SAMLProvider(validConfig, logger);
      const mockGenerateMetadata = jest.fn().mockReturnValue('<EntityDescriptor entityID="test">...</EntityDescriptor>');
      (provider as any).provider = {
        generateServiceProviderMetadata: mockGenerateMetadata,
      };

      const metadata = provider.getMetadata();

      expect(metadata).toContain('validUntil="');
      expect(metadata).toMatch(/validUntil="\d{4}-\d{2}-\d{2}T/);
    });

    test('should use decryption cert from config', () => {
      const provider = new SAMLProvider(validConfig, logger);
      const mockGenerateMetadata = jest.fn().mockReturnValue('<EntityDescriptor />');
      (provider as any).provider = {
        generateServiceProviderMetadata: mockGenerateMetadata,
      };

      provider.getMetadata();

      // Certs are now in PEM format
      expect(mockGenerateMetadata).toHaveBeenCalledWith(
        expect.stringContaining('test-decryption-cert'),
        expect.stringContaining('test-public-cert')
      );
    });

    test('should use decryption cert from config when provided', () => {
      const configWithDecryption = {
        ...validConfig,
        decryptionCert: 'custom-decryption-cert',
      };
      const provider = new SAMLProvider(configWithDecryption, logger);
      const mockGenerateMetadata = jest.fn().mockReturnValue('<EntityDescriptor />');
      (provider as any).provider = {
        generateServiceProviderMetadata: mockGenerateMetadata,
      };

      provider.getMetadata();

      // Certs are now in PEM format
      expect(mockGenerateMetadata).toHaveBeenCalledWith(
        expect.stringContaining('custom-decryption-cert'),
        expect.stringContaining('test-public-cert')
      );
    });

    test('should use decryption cert from argument when provided', () => {
      const provider = new SAMLProvider(validConfig, logger);
      const mockGenerateMetadata = jest.fn().mockReturnValue('<EntityDescriptor />');
      (provider as any).provider = {
        generateServiceProviderMetadata: mockGenerateMetadata,
      };

      provider.getMetadata('arg-decryption-cert');

      // Argument certs are passed as-is, config certs are in PEM format
      expect(mockGenerateMetadata).toHaveBeenCalledWith(
        'arg-decryption-cert',
        expect.stringContaining('test-public-cert')
      );
    });

    test('should prioritize argument certs over configured certs', () => {
      const configWithCerts = {
        ...validConfig,
        cert: 'configured-signing-cert',
        decryptionCert: 'configured-decryption-cert',
      };
      const provider = new SAMLProvider(configWithCerts, logger);
      const mockGenerateMetadata = jest.fn().mockReturnValue('<EntityDescriptor />');
      (provider as any).provider = {
        generateServiceProviderMetadata: mockGenerateMetadata,
      };

      provider.getMetadata('arg-decryption-cert', 'arg-signing-cert');

      expect(mockGenerateMetadata).toHaveBeenCalledWith('arg-decryption-cert', 'arg-signing-cert');
    });

    test('should use configured certs when no arguments provided', () => {
      const configWithCerts = {
        ...validConfig,
        cert: 'configured-signing-cert',
        decryptionCert: 'configured-decryption-cert',
      };
      const provider = new SAMLProvider(configWithCerts, logger);
      const mockGenerateMetadata = jest.fn().mockReturnValue('<EntityDescriptor />');
      (provider as any).provider = {
        generateServiceProviderMetadata: mockGenerateMetadata,
      };

      provider.getMetadata();

      // Certs are now in PEM format
      expect(mockGenerateMetadata).toHaveBeenCalledWith(
        expect.stringContaining('configured-decryption-cert'),
        expect.stringContaining('configured-signing-cert')
      );
    });

    test('should always include AssertionConsumerService elements (required by SAML 2.0 schema)', () => {
      const provider = new SAMLProvider(validConfig, logger);
      const metadataWithAcs = `<EntityDescriptor entityID="test">
        <SPSSODescriptor>
          <KeyDescriptor use="signing"/>
          <AssertionConsumerService index="1" isDefault="true" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.com/acs"/>
          <AssertionConsumerService index="2" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://example.com/acs2"/>
        </SPSSODescriptor>
      </EntityDescriptor>`;
      const mockGenerateMetadata = jest.fn().mockReturnValue(metadataWithAcs);
      (provider as any).provider = {
        generateServiceProviderMetadata: mockGenerateMetadata,
      };

      const metadata = provider.getMetadata();

      // SAML 2.0 schema requires AssertionConsumerService elements
      expect(metadata).toContain('AssertionConsumerService');
      expect(metadata).toContain('KeyDescriptor');
      expect(metadata).toContain('SPSSODescriptor');
    });
  });
});
