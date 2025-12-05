# Next.js Integration

The `weblogin-auth-sdk` provides a dedicated entry point for Next.js applications to ensure optimal bundle size and compatibility with the App Router.

## Import Pattern

For Next.js applications, import from `weblogin-auth-sdk/next`:

```typescript
import { createWebLoginNext } from 'weblogin-auth-sdk/next';
```

This separate import ensures that Next.js-specific code is only included when needed.
