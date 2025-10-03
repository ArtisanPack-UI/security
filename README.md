# ArtisanPack UI Security

[![Latest Version on Packagist](https://img.shields.io/packagist/v/artisanpackui/security.svg?style=flat-square)](https://packagist.org/packages/artisanpackui/security)
[![Total Downloads](https://img.shields.io/packagist/dt/artisanpackui/security.svg?style=flat-square)](https://packagist.org/packages/artisanpackui/security)

A comprehensive security package for Laravel applications, specifically designed for the Digital Shopfront CMS. This package provides essential data sanitization and output escaping functions to protect against common web vulnerabilities like XSS attacks, SQL injection, and data corruption, plus robust two-factor authentication (2FA) capabilities.

## Features

- **Comprehensive Sanitization**: Clean user input with specialized functions for emails, URLs, text, dates, and more
- **Context-Aware Escaping**: Safely escape output for HTML, attributes, URLs, JavaScript, and CSS contexts
- **HTML Filtering**: WordPress-style HTML filtering with `kses()` function
- **Two-Factor Authentication**: Email-based and Google Authenticator/TOTP support with extensible provider system
- **Laravel Integration**: Facade and global helper functions for easy usage
- **Battle-Tested**: Built on proven libraries like Laminas Escaper and Google2FA
- **Full Test Coverage**: Extensively tested for reliability

## Quick Start

### Installation

Install the package via Composer:

```bash
composer require ArtisanPackUI/security
```

### Basic Usage

Use the Security facade:
```php
use ArtisanPackUI\Security\Facades\Security;

// Sanitize input
$cleanEmail = Security::sanitizeEmail($userEmail);

// Escape output
echo Security::escHtml($userContent);
```

Or use global helper functions:
```php
// Sanitize input
$cleanEmail = sanitizeEmail($userEmail);

// Escape output
echo escHtml($userContent);
```

### Two-Factor Authentication

Enable 2FA for your users with minimal setup:

```php
use ArtisanPackUI\Security\Facades\TwoFactor;

// Generate and send a 2FA challenge (email code)
TwoFactor::generateChallenge($user);

// Verify the user's code
if (TwoFactor::verify($user, $userProvidedCode)) {
    // User is authenticated
}
```

**⚠️ Developer Responsibilities:**
- **Create verification route**: You must create a route named `two-factor.challenge` where users enter their 2FA code
- **Create verification view**: Design and implement the 2FA code input form
- **Add database columns**: Your User model needs `two_factor_secret`, `two_factor_recovery_codes`, and `two_factor_enabled_at` columns
- **Use the trait**: Add `TwoFactorAuthenticatable` trait to your User model
- **Handle the flow**: Integrate 2FA challenges into your authentication process

## Documentation

📚 **[Complete Documentation](docs/home.md)**

- **[Getting Started](docs/getting-started.md)** - Installation, setup, and basic usage
- **[Two-Factor Authentication](docs/two-factor-authentication.md)** - Complete 2FA setup and implementation guide
- **[API Reference](docs/api-reference.md)** - Complete function reference with examples
- **[Security Guidelines](docs/security-guidelines.md)** - Best practices and security considerations
- **[AI Guidelines](docs/ai-guidelines.md)** - Guidelines for AI code generation
- **[Contributing](docs/contributing.md)** - How to contribute to this project
- **[Changelog](docs/changelog.md)** - Version history and changes

## Available Functions

### Sanitization Functions
- `sanitizeEmail()` - Clean email addresses
- `sanitizeUrl()` - Sanitize URLs
- `sanitizeText()` - Remove HTML and clean text
- `sanitizeInt()` - Convert to safe integers
- `sanitizeArray()` - Recursively clean arrays
- And more...

### Escaping Functions
- `escHtml()` - HTML context escaping
- `escAttr()` - HTML attribute escaping
- `escUrl()` - URL escaping
- `escJs()` - JavaScript context escaping
- `escCss()` - CSS context escaping

### HTML Filtering
- `kses()` - WordPress-style HTML filtering

## Security

If you discover any security vulnerabilities, please follow our [security reporting guidelines](docs/contributing.md#security-contributions). Do not open public issues for security vulnerabilities.

## Contributing

We welcome contributions! Please see our [Contributing Guide](docs/contributing.md) for details on how to contribute to this project.

## About Digital Shopfront CMS

This package is part of the ArtisanPack UI ecosystem for [Digital Shopfront CMS](https://gitlab.com/jacob-martella-web-design/digital-shopfront/digital-shopfront-core/digital-shopfront). Learn more about the full CMS in our [main documentation](https://gitlab.com/jacob-martella-web-design/digital-shopfront/digital-shopfront-core/digital-shopfront/-/wikis/home).

## License

This project is open-sourced software licensed under the [MIT license](LICENSE).
