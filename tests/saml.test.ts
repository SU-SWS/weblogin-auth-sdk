/* eslint-disable @typescript-eslint/no-explicit-any */
import { SAMLProvider } from '../src/saml';
import { AuthError } from '../src/types';
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
      // Clear environment variables
      const originalIssuer = process.env.WEBLOGIN_AUTH_ISSUER;
      const originalCert = process.env.WEBLOGIN_AUTH_SAML_CERT;
      const originalOrigin = process.env.WEBLOGIN_AUTH_ACS_URL_ORIGIN;

      delete process.env.WEBLOGIN_AUTH_ISSUER;
      delete process.env.WEBLOGIN_AUTH_SAML_CERT;
      delete process.env.WEBLOGIN_AUTH_ACS_URL_ORIGIN;

      expect(() => {
        new SAMLProvider({} as SamlConfig, logger);
      }).toThrow(AuthError);

      // Restore environment variables
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

  describe('getLoginUrl', () => {
    test('should generate login URL with returnTo', async () => {
      const provider = new SAMLProvider(validConfig, logger);

      // Mock the underlying provider's getAuthorizeUrlAsync
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

      // Mock the SAML provider's validatePostResponseAsync method
      const mockValidateResponse = jest.fn().mockResolvedValue({
        profile: mockProfile,
      });

      const provider = new SAMLProvider(validConfig, logger);
      // Replace the provider's validatePostResponseAsync method
      (provider as any).provider = {
        validatePostResponseAsync: mockValidateResponse,
      };

      // Mock request with proper Request interface
      const mockReq = {
        text: jest.fn().mockResolvedValue('SAMLResponse=encoded-response&RelayState=relay-state')
      } as MockRequest;

      // Add instanceof check support
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
        imageUrl: undefined,
        suid: mockProfile.suid,
        encodedSUID: mockProfile.encodedSUID,
        userName: mockProfile.userName,
        firstName: mockProfile.firstName,
        lastName: mockProfile.lastName,
        sessionId: mockProfile['oracle:cloud:identity:sessionid'],
        // Extra fields passed through from profile
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
        // OID attributes
        'urn:oid:0.9.2342.19200300.100.1.3': 'oid-email@example.com', // mail
        'urn:oid:2.5.4.42': 'OIDGivenName', // givenName
        'urn:oid:2.5.4.4': 'OIDSurname', // sn
        'urn:oid:2.16.840.1.113730.3.1.241': 'OID Display Name', // displayName
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

      // Check if OID attributes are mapped
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
        // OID attributes only
        'urn:oid:0.9.2342.19200300.100.1.3': 'oid-email@example.com', // mail
        'urn:oid:2.5.4.42': 'OIDGivenName', // givenName
        'urn:oid:2.5.4.4': 'OIDSurname', // sn
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
});
