# ArtisanPack UI Security

[![Latest Version on Packagist](https://img.shields.io/packagist/v/artisanpackui/security.svg?style=flat-square)](https://packagist.org/packages/artisanpackui/security)
[![Total Downloads](https://img.shields.io/packagist/dt/artisanpackui/security.svg?style=flat-square)](https://packagist.org/packages/artisanpackui/security)

> **IMPORTANT**: This is the **2.0 core-only** version of ArtisanPack Security. 
> For the full package with all features, see [artisanpackui/security-full](https://packagist.org/packages/artisanpackui/security-full).

A lightweight, focused security package for Laravel applications providing essential core security utilities: input sanitization, output escaping, KSES HTML filtering, CSP headers, and security headers middleware.

## What's New in 2.0

Version 2.0 focuses on core security utilities only. Some features have been moved to separate packages:

| Feature | New Package |
|---------|-------------|
| Two-Factor Authentication | `artisanpackui/2fa` |
| Role-Based Access Control | `artisanpackui/rbac` |
| File Upload Security | `artisanpackui/file-upload` |
| Security Analytics | `artisanpackui/analytics` |
| Compliance Tools | `artisanpackui/compliance` |
| Advanced Auth | `artisanpackui/advanced-auth` |

Want everything? Install the [meta-package](https://packagist.org/packages/artisanpackui/security-full):

```bash
composer require artisanpackui/security-full
```

## Core Features

- **Input Sanitization**: Clean user input (emails, URLs, text, integers, arrays)
- **Context-Aware Escaping**: HTML, attributes, URLs, JavaScript, and CSS
- **KSES HTML Filtering**: WordPress-style HTML filtering with `kses()`
- **Security Headers**: CSP, X-Frame-Options, X-Content-Type-Options, and more

## Installation

```bash
composer require artisanpackui/security
```

## Quick Start

```php
use ArtisanPackUI\Security\Facades\Security;

// Sanitize input
$cleanEmail = Security::sanitizeEmail($userEmail);

// Escape output
echo Security::escHtml($userContent);

// KSES HTML filtering (allow safe tags)
$filtered = Security::kses($userHtml, $allowedTags);

// Set security headers
Security::setContentSecurityPolicy();
```

## Available Core Functions

### Sanitization
- `sanitizeEmail()` - Clean email addresses
- `sanitizeUrl()` - Sanitize URLs  
- `sanitizeText()` - Remove HTML and clean text
- `sanitizeInt()` - Convert to safe integers
- `sanitizeArray()` - Recursively clean arrays

### Escaping
- `escHtml()` - HTML context escaping
- `escAttr()` - HTML attribute escaping
- `escUrl()` - URL escaping
- `escJs()` - JavaScript context escaping
- `escCss()` - CSS context escaping

### HTML Filtering
- `kses()` - WordPress-style HTML filtering

### Security Headers
- `setContentSecurityPolicy()` - CSP headers
- `setXFrameOptions()` - Clickjacking protection
- `setXContentTypeOptions()` - MIME sniffing protection
- `setStrictTransportSecurity()` - HSTS headers

## Migration from 1.x

See the [Migration Guide](docs/migration-1x-to-2x.md) for upgrading from version 1.x.

## Documentation

📚 **[Complete Documentation](docs/home.md)**

- **[Getting Started](docs/getting-started.md)** - Installation and setup
- **[API Reference](docs/api-reference.md)** - Function reference
- **[Security Guidelines](docs/security-guidelines.md)** - Best practices
- **[Migration Guide](docs/migration-1x-to-2x.md)** - Upgrade from 1.x

## Related Packages

- [security-full](https://packagist.org/packages/artisanpackui/security-full) - Meta-package with all features
- [2fa](https://packagist.org/packages/artisanpackui/2fa) - Two-Factor Authentication
- [rbac](https://packagist.org/packages/artisanpackui/rbac) - Role-Based Access Control

## Security

If you discover security vulnerabilities, please follow our [security reporting guidelines](docs/contributing.md#security-contributions). Do not open public issues.

## License

MIT license.
