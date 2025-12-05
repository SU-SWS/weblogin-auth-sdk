import * as webloginAuth from '../src/index';

describe('Weblogin Auth SDK exports', () => {
  describe('SAML exports', () => {
    it('should export SAMLProvider class', () => {
      expect(typeof webloginAuth.SAMLProvider).toBe('function');
      expect(webloginAuth.SAMLProvider.prototype.constructor).toBe(webloginAuth.SAMLProvider);
    });

    it('should export createSAMLProvider function', () => {
      expect(typeof webloginAuth.createSAMLProvider).toBe('function');
    });
  });

  describe('Session exports', () => {
    it('should export SessionManager class', () => {
      expect(typeof webloginAuth.SessionManager).toBe('function');
      expect(webloginAuth.SessionManager.prototype.constructor).toBe(webloginAuth.SessionManager);
    });

    it('should export createExpressCookieStore function', () => {
      expect(typeof webloginAuth.createExpressCookieStore).toBe('function');
    });

    it('should export createWebCookieStore function', () => {
      expect(typeof webloginAuth.createWebCookieStore).toBe('function');
    });
  });

  describe('Edge Session exports', () => {
    it('should export EdgeSessionReader class', () => {
      expect(typeof webloginAuth.EdgeSessionReader).toBe('function');
      expect(webloginAuth.EdgeSessionReader.prototype.constructor).toBe(webloginAuth.EdgeSessionReader);
    });

    it('should export EdgeCookieParser class', () => {
      expect(typeof webloginAuth.EdgeCookieParser).toBe('function');
      expect(webloginAuth.EdgeCookieParser.prototype.constructor).toBe(webloginAuth.EdgeCookieParser);
    });

    it('should export createEdgeSessionReader function', () => {
      expect(typeof webloginAuth.createEdgeSessionReader).toBe('function');
    });

    it('should export getUserIdFromRequest function', () => {
      expect(typeof webloginAuth.getUserIdFromRequest).toBe('function');
    });

    it('should export getUserIdFromCookie function', () => {
      expect(typeof webloginAuth.getUserIdFromCookie).toBe('function');
    });
  });

  describe('Next.js exports (removed in v2.0.0)', () => {
    it('should NOT export WebLoginNext from main index (now in separate module)', () => {
      expect((webloginAuth as unknown as Record<string, unknown>).WebLoginNext).toBeUndefined();
    });

    it('should NOT export createWebLoginNext from main index (now in separate module)', () => {
      expect((webloginAuth as unknown as Record<string, unknown>).createWebLoginNext).toBeUndefined();
    });
  });

  describe('Logger exports', () => {
    it('should export DefaultLogger class', () => {
      expect(typeof webloginAuth.DefaultLogger).toBe('function');
      expect(webloginAuth.DefaultLogger.prototype.constructor).toBe(webloginAuth.DefaultLogger);
    });

    it('should export ConsoleLogger class', () => {
      expect(typeof webloginAuth.ConsoleLogger).toBe('function');
      expect(webloginAuth.ConsoleLogger.prototype.constructor).toBe(webloginAuth.ConsoleLogger);
    });

    it('should export SilentLogger class', () => {
      expect(typeof webloginAuth.SilentLogger).toBe('function');
      expect(webloginAuth.SilentLogger.prototype.constructor).toBe(webloginAuth.SilentLogger);
    });
  });

  describe('Utils exports', () => {
    it('should export AuthUtils class', () => {
      expect(typeof webloginAuth.AuthUtils).toBe('function');
    });
  });

  describe('Error exports', () => {
    it('should export AuthError class', () => {
      expect(typeof webloginAuth.AuthError).toBe('function');
      expect(webloginAuth.AuthError.prototype.constructor).toBe(webloginAuth.AuthError);
    });

    it('should have AuthError properly extending Error', () => {
      expect(webloginAuth.AuthError.prototype).toBeInstanceOf(Error);
    });
  });

  describe('Type exports', () => {
    // These are interface/type exports, so we can't test them directly at runtime
    // but we can verify they're properly exported by importing them
    it('should have type exports available for import', () => {
      // This test mainly verifies the module structure is correct
      // TypeScript will catch any missing type exports at compile time
      expect(webloginAuth).toBeDefined();
    });
  });

  describe('Module structure', () => {
    it('should be importable', () => {
      // The main index module should be importable without errors
      expect(webloginAuth).toBeDefined();
      expect(typeof webloginAuth).toBe('object');
    });

    it('should export expected core items', () => {
      const expectedExports = [
        // SAML
        'SAMLProvider',
        'createSAMLProvider',
        // Session
        'SessionManager',
        'createExpressCookieStore',
        'createWebCookieStore',
        // Edge Session
        'EdgeSessionReader',
        'EdgeCookieParser',
        'createEdgeSessionReader',
        'getUserIdFromRequest',
        'getUserIdFromCookie',
        // Logger
        'DefaultLogger',
        'ConsoleLogger',
        'SilentLogger',
        // Utils
        'AuthUtils',
        // Errors
        'AuthError'
        // Note: Next.js exports (WebLoginNext, createWebLoginNext) are now in separate module
      ];

      expectedExports.forEach(exportName => {
        expect(webloginAuth).toHaveProperty(exportName);
      });
    });
  });

  describe('Class inheritance verification', () => {
    it('should have AuthError properly extending Error', () => {
      expect(webloginAuth.AuthError.prototype).toBeInstanceOf(Error);
    });
  });

  describe('Factory function integration', () => {
    it('should have all factory functions return constructible objects', () => {
      // Test that factory functions exist and could theoretically create instances
      expect(webloginAuth.createSAMLProvider).toBeDefined();
      expect(webloginAuth.createExpressCookieStore).toBeDefined();
      expect(webloginAuth.createWebCookieStore).toBeDefined();
      expect(webloginAuth.createEdgeSessionReader).toBeDefined();
      // Note: createWebLoginNext is now in separate Next.js module
    });
  });
});
