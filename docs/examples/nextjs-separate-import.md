# Next.js Integration

The `adapt-auth-sdk` provides a dedicated entry point for Next.js applications to ensure optimal bundle size and compatibility with the App Router.

## Import Pattern

For Next.js applications, import from `adapt-auth-sdk/next`:

```typescript
import { createAdaptNext } from 'adapt-auth-sdk/next';
```

This separate import ensures that Next.js-specific code is only included when needed.
