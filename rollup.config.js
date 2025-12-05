import typescript from '@rollup/plugin-typescript';
import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import dts from 'rollup-plugin-dts';
import fs from 'fs';

// Read package.json to get external dependencies
const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
const external = [
  ...Object.keys(pkg.dependencies || {}),
  ...Object.keys(pkg.optionalDependencies || {}),
  'node:crypto',
  'node:util',
  'url',
  'crypto',
  'next/headers' // Treat Next.js headers as external dependency
];

// Get all source files for individual exports
const srcDir = 'src';
const sourceFiles = fs.readdirSync(srcDir)
  .filter(file => file.endsWith('.ts') && file !== 'index.ts')
  .map(file => file.replace('.ts', ''));

// Create input object for multiple entry points
const input = {
  index: 'src/index.ts',
  ...Object.fromEntries(sourceFiles.map(name => [name, `src/${name}.ts`]))
};

// Custom external function that handles dynamic imports
const isExternal = (id) => {
  // Handle dynamic imports of external packages
  if (external.some(ext => id === ext || id.startsWith(ext + '/'))) {
    return true;
  }
  return false;
};

// ESM Build Configuration
const esmConfig = {
  input,
  external: isExternal,
  output: {
    dir: 'dist/esm',
    format: 'es',
    entryFileNames: '[name].js',
    preserveModules: true,
    preserveModulesRoot: 'src',
    exports: 'named',
    generatedCode: 'es2015'
  },
  plugins: [
    resolve({
      preferBuiltins: true,
      exportConditions: ['node'],
      browser: false
    }),
    commonjs({
      sourceMap: false
    }),
    typescript({
      tsconfig: './tsconfig.json',
      outDir: 'dist/esm',
      declaration: true,
      declarationDir: 'dist/esm',
      sourceMap: false
    }),
    // Custom plugin to create package.json
    {
      name: 'create-esm-package',
      generateBundle() {
        this.emitFile({
          type: 'asset',
          fileName: 'package.json',
          source: JSON.stringify({ type: 'module' }, null, 2)
        });
      }
    }
  ]
};

// CommonJS Build Configuration
const cjsConfig = {
  input,
  external: isExternal,
  output: {
    dir: 'dist/cjs',
    format: 'cjs',
    entryFileNames: '[name].cjs',
    preserveModules: true,
    preserveModulesRoot: 'src',
    exports: 'named',
    generatedCode: 'es5'
  },
  plugins: [
    resolve({
      preferBuiltins: true,
      exportConditions: ['node'],
      browser: false
    }),
    commonjs({
      sourceMap: false
    }),
    typescript({
      tsconfig: './tsconfig.json',
      outDir: 'dist/cjs',
      declaration: true,
      declarationDir: 'dist/cjs',
      sourceMap: false
    }),
    // Custom plugin to create package.json files
    {
      name: 'create-package-json',
      generateBundle() {
        // Create package.json for CommonJS
        this.emitFile({
          type: 'asset',
          fileName: 'package.json',
          source: JSON.stringify({ type: 'commonjs' }, null, 2)
        });
      }
    }
  ]
};

// Type definitions for CommonJS (copy from ESM and adjust extensions)
const dtsConfig = {
  input: {
    index: 'dist/esm/index.d.ts',
    ...Object.fromEntries(sourceFiles.map(name => [name, `dist/esm/${name}.d.ts`]))
  },
  output: {
    dir: 'dist/cjs',
    format: 'es',
    entryFileNames: '[name].d.ts'
  },
  plugins: [
    dts(),
    // Custom plugin to update import paths in CommonJS type definitions
    {
      name: 'update-cjs-dts',
      generateBundle(options, bundle) {
        // Update import paths in type definitions to use .cjs extension
        Object.keys(bundle).forEach(fileName => {
          if (fileName.endsWith('.d.ts')) {
            const file = bundle[fileName];
            if (file.type === 'chunk') {
              file.code = file.code.replace(/from\s+['"](\.\/[^'"]*?)\.js['"]/g, "from '$1.cjs'");
              file.code = file.code.replace(/import\(['"](\.\/[^'"]*?)\.js['"]\)/g, "import('$1.cjs')");
            }
          }
        });
      }
    }
  ]
};

export default [esmConfig, cjsConfig, dtsConfig];
