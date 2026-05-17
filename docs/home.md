---
title: ArtisanPack UI Security Documentation
---

# ArtisanPack UI Security

The **core** Laravel security toolkit in the ArtisanPack UI ecosystem. Focused on input sanitization, output escaping, KSES filtering, security headers, XSS protection, basic rate limiting, and Content Security Policy.

> **Security 2.0 — core-only.** Authentication, 2FA, RBAC, file uploads, analytics, and compliance have moved to dedicated sibling packages. See [UPGRADE.md](../UPGRADE.md) for migrating from 1.x.

## What's in this package

- **Sanitization** — `sanitizeEmail`, `sanitizeUrl`, `sanitizeText`, `sanitizeInt`, `sanitizeArray`, …
- **Escaping** — `escHtml`, `escAttr`, `escUrl`, `escJs`, `escCss` (Laminas Escaper-backed)
- **KSES filtering** — `kses()` WordPress-style allowed-tag filtering
- **Validation rules** — `NoHtml`, `SecureUrl`
- **Middleware** — `csp`, `security.headers`, `xss.protection`, `api.security`, `api.rate_limit`
- **Content Security Policy** — nonce generator, policy builder, presets (Strict / Relaxed / Livewire), violation reporting endpoint, optional CSP dashboard Livewire component, Artisan commands (`csp:test`, `csp:stats`, `csp:prune`, `csp:generate`)
- **Security audit + testing toolkit** — OWASP / configuration scanners, penetration testing helpers, performance benchmarks, report generators (JSON, HTML, JUnit, SARIF, Markdown), CI/CD integration, Artisan commands (`security:audit`, `security:scan`, `security:baseline`, `security:benchmark`, `security:check-config`, `security:test-headers`, `security:scan-deps`)

## What's NOT in this package (sibling packages)

| Capability | Package |
|---|---|
| Authentication, 2FA, password complexity, account lockout, advanced sessions | [`artisanpack-ui/security-auth`](https://github.com/ArtisanPack-UI/security-auth) |
| WebAuthn / FIDO2, SSO (SAML/OIDC), social auth, biometrics, device fingerprinting | [`artisanpack-ui/security-advanced-auth`](https://github.com/ArtisanPack-UI/security-advanced-auth) |
| Roles, permissions, Gate integration, Blade directives, Artisan commands | [`artisanpack-ui/rbac`](https://github.com/ArtisanPack-UI/rbac) |
| Secure uploads, malware scanning, signed-URL serving | [`artisanpack-ui/secure-uploads`](https://github.com/ArtisanPack-UI/secure-uploads) |
| Security event logging, anomaly detection, SIEM export, dashboards | [`artisanpack-ui/security-analytics`](https://github.com/ArtisanPack-UI/security-analytics) |
| GDPR / CCPA / LGPD compliance | `artisanpack-ui/compliance` (future) |

## Documentation map

- [Getting Started](getting-started.md) — install + first sanitize / escape call
- [Installation](installation.md) — requirements, configuration, environment variables, migration management
- [Usage](usage.md) — sanitization, escaping, KSES, validation rules, middleware, CSP, headers, rate limiting, session security, API security, Artisan commands
- [API Reference](api.md) — public API surface
- [Advanced](advanced.md) — security testing toolkit, checklist, guidelines, AI assistant guidelines, video tutorials, implementation guide, migration guides
- [FAQ](faq.md)
- [Troubleshooting](troubleshooting.md)
- [Upgrading from 1.x](../UPGRADE.md)
- [Changelog](../CHANGELOG.md)
