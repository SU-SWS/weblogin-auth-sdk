/**
 * Custom Jest resolver to handle .js extension imports pointing to .ts files
 * This is needed because our source files use .js extensions for ESM compatibility
 * but Jest needs to resolve them to .ts files during testing.
 */
module.exports = (path, options) => {
  // If it's a relative import ending with .js, try to resolve to .ts
  if ((path.startsWith('./') || path.startsWith('../')) && path.endsWith('.js')) {
    const tsPath = path.replace(/\.js$/, '.ts');
    try {
      return options.defaultResolver(tsPath, options);
    } catch {
      // If .ts version doesn't exist, fall through to default behavior
    }
  }

  // Use the default resolver
  return options.defaultResolver(path, options);
};