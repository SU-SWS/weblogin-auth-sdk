import { SAMLProvider } from '../src/saml';
import { MFA } from '../src/types';
import { SAML } from '@node-saml/node-saml';

// Mock node-saml
jest.mock('@node-saml/node-saml');

describe('Stanford Specific Features', () => {
  let provider: SAMLProvider;
  const mockGetAuthorizeUrlAsync = jest.fn();
  const mockValidatePostResponseAsync = jest.fn();
  const mockGenerateServiceProviderMetadata = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
    (SAML as jest.Mock).mockImplementation(() => ({
      getAuthorizeUrlAsync: mockGetAuthorizeUrlAsync,
      validatePostResponseAsync: mockValidatePostResponseAsync,
      generateServiceProviderMetadata: mockGenerateServiceProviderMetadata,
    }));

    provider = new SAMLProvider({
      issuer: 'test-entity',
      idpCert: 'test-cert',
      returnToOrigin: 'https://test.com',
    });
  });

  describe('MFA and forceAuthn', () => {
    it('should pass forceAuthn to node-saml', async () => {
      mockGetAuthorizeUrlAsync.mockResolvedValue('https://idp.com/login');

      await provider.getLoginUrl({ forceAuthn: true });

      expect(mockGetAuthorizeUrlAsync).toHaveBeenCalledWith(
        expect.any(String),
        undefined,
        expect.objectContaining({ forceAuthn: true })
      );
    });

    it('should pass MFA context to node-saml', async () => {
      mockGetAuthorizeUrlAsync.mockResolvedValue('https://idp.com/login');

      await provider.getLoginUrl({ mfa: MFA.REFEDS });

      expect(mockGetAuthorizeUrlAsync).toHaveBeenCalledWith(
        expect.any(String),
        undefined,
        expect.objectContaining({
          authnContext: [MFA.REFEDS]
        })
      );
    });

    it('should handle both forceAuthn and MFA', async () => {
      mockGetAuthorizeUrlAsync.mockResolvedValue('https://idp.com/login');

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
  });

  describe('Metadata Enhancements', () => {
    it('should inject validUntil into metadata', () => {
      mockGenerateServiceProviderMetadata.mockReturnValue('<EntityDescriptor entityID="test">...</EntityDescriptor>');

      const metadata = provider.getMetadata();

      expect(metadata).toContain('validUntil="');
      expect(metadata).toMatch(/validUntil="\d{4}-\d{2}-\d{2}T/);
    });
  });

  describe('Attribute Mapping', () => {
    it('should map new attributes correctly', async () => {
      const mockProfile = {
        issuer: 'idp',
        sessionIndex: '123',
        nameID: 'user',
        attributes: {
          'urn:oid:1.3.6.1.4.1.5923.1.1.1.16': '0000-0000-0000-0000', // eduPersonOrcid
          'urn:oasis:names:tc:SAML:attribute:subject-id': 'user@stanford.edu', // subject-id
          'urn:oasis:names:tc:SAML:attribute:pairwise-id': 'pairwise-id-value', // pairwise-id
        }
      };

      mockValidatePostResponseAsync.mockResolvedValue({ profile: mockProfile });

      const req = new Request('https://test.com/callback', {
        method: 'POST',
        body: new URLSearchParams({ SAMLResponse: 'dummy' })
      });

      const { user } = await provider.authenticate({ req });

      expect(user).toMatchObject({
        eduPersonOrcid: '0000-0000-0000-0000',
        'subject-id': 'user@stanford.edu',
        'pairwise-id': 'pairwise-id-value',
      });
    });
  });
});
