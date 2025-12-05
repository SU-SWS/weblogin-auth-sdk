/**
 * Test the separate Next.js module exports
 * These tests verify that the Next.js functionality is correctly isolated
 * in its own module and importable via 'weblogin-auth-sdk/next'
 */

import fs from 'fs';
import path from 'path';

describe('Next.js Module Exports', () => {
  it('should be importable via separate path', async () => {
    // Since we can't import next/headers in this test environment,
    // we'll just verify the module structure exists

    // Check that the built files exist
    const esmNextPath = path.resolve(__dirname, '../dist/esm/next.js');
    const cjsNextPath = path.resolve(__dirname, '../dist/cjs/next.cjs');

    expect(fs.existsSync(esmNextPath)).toBe(true);
    expect(fs.existsSync(cjsNextPath)).toBe(true);
  });

  it('should have correct package.json export path', () => {
    const packageJsonPath = path.resolve(__dirname, '../package.json');
    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));

    // Check that exports object exists and has the next path
    expect(packageJson.exports).toBeDefined();
    expect(packageJson.exports['./next']).toBeDefined();

    const nextExport = packageJson.exports['./next'];

    // Check the structure
    expect(nextExport.import).toBeDefined();
    expect(nextExport.require).toBeDefined();

    // Check the actual paths
    expect(nextExport.import.default).toBe('./dist/esm/next.js');
    expect(nextExport.require.default).toBe('./dist/cjs/next.cjs');

    // Check that types are also properly configured
    expect(nextExport.import.types).toBe('./dist/esm/next.d.ts');
    expect(nextExport.require.types).toBe('./dist/cjs/next.d.ts');
  });

  it('should have Next.js as optional dependency', () => {
    const packageJsonPath = path.resolve(__dirname, '../package.json');
    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));

    expect(packageJson.optionalDependencies).toHaveProperty('next');
    expect(packageJson.optionalDependencies.next).toBe('>=14');
  });

  describe('Documentation and examples', () => {
    it('should have Next.js separate import documentation', () => {
      const docPath = path.resolve(__dirname, '../docs/examples/nextjs-separate-import.md');

      expect(fs.existsSync(docPath)).toBe(true);

      const docContent = fs.readFileSync(docPath, 'utf8');
      expect(docContent).toContain('weblogin-auth-sdk/next');
      expect(docContent).toContain('createWebLoginNext');
    });

    it('should have updated main Next.js example', () => {
      const docPath = path.resolve(__dirname, '../docs/examples/nextjs-app-router.md');

      if (fs.existsSync(docPath)) {
        const docContent = fs.readFileSync(docPath, 'utf8');
        expect(docContent).toContain('weblogin-auth-sdk/next');
      }
    });

    it('should have updated README with separate import pattern', () => {
      const readmePath = path.resolve(__dirname, '../README.md');

      const readmeContent = fs.readFileSync(readmePath, 'utf8');
      expect(readmeContent).toContain('weblogin-auth-sdk/next');
      expect(readmeContent).toContain('Framework-Agnostic');
    });
  });

  describe('Build outputs', () => {
    it('should have clean ESM output without virtual modules', () => {
      const esmDir = path.resolve(__dirname, '../dist/esm');

      if (fs.existsSync(esmDir)) {
        const files = fs.readdirSync(esmDir, { recursive: true });
        const virtualFiles = files.filter((file: string | Buffer) =>
          typeof file === 'string' && file.includes('_virtual')
        );
        expect(virtualFiles).toHaveLength(0);
      }
    });

    it('should have clean CJS output without virtual modules', () => {
      const cjsDir = path.resolve(__dirname, '../dist/cjs');

      if (fs.existsSync(cjsDir)) {
        const files = fs.readdirSync(cjsDir, { recursive: true });
        const virtualFiles = files.filter((file: string | Buffer) =>
          typeof file === 'string' && file.includes('_virtual')
        );
        expect(virtualFiles).toHaveLength(0);
      }
    });
  });
});