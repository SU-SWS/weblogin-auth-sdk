# Weblogin Auth SDK

**Version 3**

A framework-agnostic TypeScript authentication library for Stanford Weblogin integration. 
Designed for serverless, stateless environments with security-first defaults and cookie-only sessions.

## Features

- **Framework Agnostic**: Works with Next.js, Express.js, and any Web API framework
- **TypeScript First**: Complete TypeScript implementation with strict typing
- **Security Focused**: Encrypted sessions, CSRF protection
- **Serverless Ready**: Cookie-only sessions, no server-side storage required
- **Edge Compatible**: Session validation in edge functions for ultra-fast performance
- **Developer Friendly**: Simple API inspired by Auth.js patterns

## Documentation

📚 **[Getting Started](./docs/getting-started.md)** - Installation and basic setup for Next.js and Express.js

⚙️ **[Configuration](./docs/configuration.md)** - Complete configuration reference and environment variables

🔒 **[Security](./docs/security.md)** - Security features, best practices, and threat protection

⚡ **[Edge Functions](./docs/edge-functions.md)** - Ultra-fast session validation in edge environments

🚀 **[Advanced Usage](./docs/advanced-usage.md)** - Custom implementations, performance optimization, and advanced patterns

📖 **[API Reference](./docs/api-reference.md)** - Complete API documentation with examples

🔄 **[Migration Guide](./docs/migration.md)** - Upgrading between major versions (v1 through v4)

## Key Features

### Security First
- SAML 2.0 signature validation
- Encrypted cookie sessions
- CSRF protection

### Developer Experience
- TypeScript-first with strict typing
- Framework-agnostic design
- Simple, intuitive API
- Comprehensive error handling
- Detailed logging with automatic PII redaction

### Production Ready
- Serverless/stateless architecture
- Cookie-only sessions (no server storage)
- Comprehensive test coverage

## License

GNU Version 3 License - see [LICENSE](./LICENSE) for details.

## Contributing

Contributions are welcome! Please submit pull requests to our GitHub repository.

## Security

Security issues should be reported privately. Please do not open public GitHub issues for security vulnerabilities.

## Support

- 📖 [Documentation](./docs/)
- 🐛 [Issues](https://github.com/su-sws/weblogin-auth-sdk/issues)
