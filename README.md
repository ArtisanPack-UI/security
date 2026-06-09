# ArtisanPack UI Security

[![Latest Version on Packagist](https://img.shields.io/packagist/v/artisanpack-ui/security.svg?style=flat-square)](https://packagist.org/packages/artisanpack-ui/security)

The **core** Laravel security toolkit in the ArtisanPack UI ecosystem. Focused on input sanitization, output escaping, KSES filtering, security headers, XSS protection, basic rate limiting, and Content Security Policy.

> **Security 2.0 — core-only.** Authentication, 2FA, RBAC, file uploads, analytics, and compliance have moved to dedicated sibling packages. See **[UPGRADE.md](UPGRADE.md)** for migrating from 1.x.

## What's in this package

- **Sanitization** — `sanitizeEmail`, `sanitizeUrl`, `sanitizeText`, `sanitizeInt`, `sanitizeArray`, …
- **Escaping** — `escHtml`, `escAttr`, `escUrl`, `escJs`, `escCss` (Laminas Escaper backed)
- **KSES filtering** — `kses()` WordPress-style allowed-tag filtering
- **Validation rules** — `NoHtml`, `SecureUrl`
- **Middleware** — `csp`, `security.headers`, `xss.protection`, `api.security`, `api.rate_limit`
- **Content Security Policy** — nonce generator, policy builder, presets, violation reporting endpoint, CSP dashboard Livewire component (optional — requires `livewire/livewire`), Artisan commands (`csp:test`, `csp:stats`, `csp:prune`, `security:generate-csp`)
- **Security audit commands** — `security:audit`, `security:scan`, `security:baseline`, `security:benchmark`, `security:check-config`, `security:test-headers`, `security:scan-deps`
- **Testing infrastructure** — OWASP scanner, configuration scanner, penetration testing helpers, performance benchmarks, report generators

## What's NOT in this package (sibling packages)

| Capability | Package |
|---|---|
| Authentication, 2FA, password complexity, breach checking, account lockout, advanced sessions | `artisanpack-ui/security-auth` |
| WebAuthn / FIDO2, SSO (SAML/OIDC), social auth, biometrics, device fingerprinting | `artisanpack-ui/security-advanced-auth` |
| Roles + permissions (Blade directives, Gate integration, Artisan commands) | `artisanpack-ui/rbac` |
| Secure uploads, malware scanning (ClamAV / VirusTotal), upload rate limiting | `artisanpack-ui/secure-uploads` |
| Security event logging, anomaly detection, threat intel, SIEM export, dashboards | `artisanpack-ui/security-analytics` |
| GDPR / CCPA / LGPD — consent, DSR, DPIA, data minimization, retention | `artisanpack-ui/compliance` |

## Installation

```bash
composer require artisanpack-ui/security
```

Publish the config:

```bash
php artisan vendor:publish --tag=security-config
```

## Quick Start

```php
use ArtisanPackUI\Security\Facades\Security;

$cleanEmail = Security::sanitizeEmail($userEmail);
echo Security::escHtml($userContent);
```

Or use the global helpers:

```php
$cleanEmail = sanitizeEmail($userEmail);
echo escHtml($userContent);
```

### Middleware

```php
Route::middleware(['csp', 'security.headers', 'xss.protection'])->group(function () {
    // ...
});

Route::middleware('api.rate_limit:api')->group(function () {
    // ...
});
```

### CSP nonces in Blade

```blade
<script @csp_nonce>
    // ...
</script>
```

## Documentation

- [Getting Started](docs/getting-started.md)
- [API Reference](docs/api-reference.md)
- [Security Guidelines](docs/security-guidelines.md)
- [Upgrading from 1.x → 2.0](UPGRADE.md)
- [Changelog](CHANGELOG.md)

## Requirements

- PHP 8.2+
- Laravel 10 / 11 / 12 / 13 (Laravel 13 requires PHP 8.3+)

## Sibling packages

| Package | Scope |
|---|---|
| [`artisanpack-ui/security-full`](https://github.com/ArtisanPack-UI/security-full) | Meta-package — pulls in the full security suite (all six packages below) in a single require |
| [`artisanpack-ui/rbac`](https://github.com/ArtisanPack-UI/rbac) | Roles, permissions, hierarchy, Blade directives, Gate integration |
| [`artisanpack-ui/security-auth`](https://github.com/ArtisanPack-UI/security-auth) | 2FA, password complexity, account lockout, sessions |
| [`artisanpack-ui/security-advanced-auth`](https://github.com/ArtisanPack-UI/security-advanced-auth) | WebAuthn, SSO, social login, biometric, device fingerprinting |
| [`artisanpack-ui/secure-uploads`](https://github.com/ArtisanPack-UI/secure-uploads) | File validation, malware scanning, signed-URL serving |
| [`artisanpack-ui/security-analytics`](https://github.com/ArtisanPack-UI/security-analytics) | Event logging, anomaly detection, SIEM, dashboards |
| [`artisanpack-ui/compliance`](https://github.com/ArtisanPack-UI/compliance) | GDPR / CCPA / LGPD consent, data subject rights, DPIA, retention, monitoring |

## License

MIT — see [LICENSE](LICENSE).
