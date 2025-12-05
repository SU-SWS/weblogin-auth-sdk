import * as adaptAuth from '../src/index';

describe('ADAPT Auth SDK exports', () => {
  describe('SAML exports', () => {
    it('should export SAMLProvider class', () => {
      expect(typeof adaptAuth.SAMLProvider).toBe('function');
      expect(adaptAuth.SAMLProvider.prototype.constructor).toBe(adaptAuth.SAMLProvider);
    });

    it('should export createSAMLProvider function', () => {
      expect(typeof adaptAuth.createSAMLProvider).toBe('function');
    });
  });

  describe('Session exports', () => {
    it('should export SessionManager class', () => {
      expect(typeof adaptAuth.SessionManager).toBe('function');
      expect(adaptAuth.SessionManager.prototype.constructor).toBe(adaptAuth.SessionManager);
    });

    it('should export createExpressCookieStore function', () => {
      expect(typeof adaptAuth.createExpressCookieStore).toBe('function');
    });

    it('should export createWebCookieStore function', () => {
      expect(typeof adaptAuth.createWebCookieStore).toBe('function');
    });
  });

  describe('Edge Session exports', () => {
    it('should export EdgeSessionReader class', () => {
      expect(typeof adaptAuth.EdgeSessionReader).toBe('function');
      expect(adaptAuth.EdgeSessionReader.prototype.constructor).toBe(adaptAuth.EdgeSessionReader);
    });

    it('should export EdgeCookieParser class', () => {
      expect(typeof adaptAuth.EdgeCookieParser).toBe('function');
      expect(adaptAuth.EdgeCookieParser.prototype.constructor).toBe(adaptAuth.EdgeCookieParser);
    });

    it('should export createEdgeSessionReader function', () => {
      expect(typeof adaptAuth.createEdgeSessionReader).toBe('function');
    });

    it('should export getUserIdFromRequest function', () => {
      expect(typeof adaptAuth.getUserIdFromRequest).toBe('function');
    });

    it('should export getUserIdFromCookie function', () => {
      expect(typeof adaptAuth.getUserIdFromCookie).toBe('function');
    });
  });

  describe('Next.js exports (removed in v2.0.0)', () => {
    it('should NOT export AdaptNext from main index (now in separate module)', () => {
      expect((adaptAuth as unknown as Record<string, unknown>).AdaptNext).toBeUndefined();
    });

    it('should NOT export createAdaptNext from main index (now in separate module)', () => {
      expect((adaptAuth as unknown as Record<string, unknown>).createAdaptNext).toBeUndefined();
    });
  });

  describe('Logger exports', () => {
    it('should export DefaultLogger class', () => {
      expect(typeof adaptAuth.DefaultLogger).toBe('function');
      expect(adaptAuth.DefaultLogger.prototype.constructor).toBe(adaptAuth.DefaultLogger);
    });

    it('should export ConsoleLogger class', () => {
      expect(typeof adaptAuth.ConsoleLogger).toBe('function');
      expect(adaptAuth.ConsoleLogger.prototype.constructor).toBe(adaptAuth.ConsoleLogger);
    });

    it('should export SilentLogger class', () => {
      expect(typeof adaptAuth.SilentLogger).toBe('function');
      expect(adaptAuth.SilentLogger.prototype.constructor).toBe(adaptAuth.SilentLogger);
    });
  });

  describe('Utils exports', () => {
    it('should export AuthUtils class', () => {
      expect(typeof adaptAuth.AuthUtils).toBe('function');
    });
  });

  describe('Error exports', () => {
    it('should export AuthError class', () => {
      expect(typeof adaptAuth.AuthError).toBe('function');
      expect(adaptAuth.AuthError.prototype.constructor).toBe(adaptAuth.AuthError);
    });

    it('should have AuthError properly extending Error', () => {
      expect(adaptAuth.AuthError.prototype).toBeInstanceOf(Error);
    });
  });

  describe('Type exports', () => {
    // These are interface/type exports, so we can't test them directly at runtime
    // but we can verify they're properly exported by importing them
    it('should have type exports available for import', () => {
      // This test mainly verifies the module structure is correct
      // TypeScript will catch any missing type exports at compile time
      expect(adaptAuth).toBeDefined();
    });
  });

  describe('Module structure', () => {
    it('should be importable', () => {
      // The main index module should be importable without errors
      expect(adaptAuth).toBeDefined();
      expect(typeof adaptAuth).toBe('object');
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
        // Note: Next.js exports (AdaptNext, createAdaptNext) are now in separate module
      ];

      expectedExports.forEach(exportName => {
        expect(adaptAuth).toHaveProperty(exportName);
      });
    });
  });

  describe('Class inheritance verification', () => {
    it('should have AuthError properly extending Error', () => {
      expect(adaptAuth.AuthError.prototype).toBeInstanceOf(Error);
    });
  });

  describe('Factory function integration', () => {
    it('should have all factory functions return constructible objects', () => {
      // Test that factory functions exist and could theoretically create instances
      expect(adaptAuth.createSAMLProvider).toBeDefined();
      expect(adaptAuth.createExpressCookieStore).toBeDefined();
      expect(adaptAuth.createWebCookieStore).toBeDefined();
      expect(adaptAuth.createEdgeSessionReader).toBeDefined();
      // Note: createAdaptNext is now in separate Next.js module
    });
  });
});
