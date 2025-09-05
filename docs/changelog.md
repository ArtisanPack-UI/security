---
title: Changelog
---

# Changelog

All notable changes to the ArtisanPack UI Security package are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.3] - 2025-05-14

### Changed
- Changed the vendor name to ArtisanPack UI

### Documentation
- Updated package branding and naming throughout
- Improved consistency with ArtisanPack UI ecosystem

## [1.0.2] - 2025-04-21

### Fixed
- Fixed an issue with running the `kses()` function
- Resolved HTML filtering functionality

### Added
- Added comprehensive tests for all security functions
- Implemented GitLab CI/CD pipeline for automated testing
- Enhanced test coverage for sanitization and escaping functions

### Development
- Improved development workflow with automated testing
- Added continuous integration for quality assurance

## [1.0.1] - 2025-04-20

### Removed
- Removed unnecessary files from the published package
- Cleaned up package distribution

### Improved
- Optimized package size for faster installation
- Streamlined package contents

## [1.0.0] - 2025-04-17

### Added
- Initial release of ArtisanPack UI Security package
- Core sanitization functions:
  - `sanitizeEmail()` - Email address sanitization
  - `sanitizeUrl()` - URL sanitization
  - `sanitizeFilename()` - Filename sanitization
  - `sanitizePassword()` - Password sanitization
  - `sanitizeInt()` - Integer sanitization
  - `sanitizeDate()` - Date normalization
  - `sanitizeDatetime()` - Datetime normalization
  - `sanitizeFloat()` - Float sanitization
  - `sanitizeArray()` - Recursive array sanitization
  - `sanitizeText()` - Text content sanitization

- Core escaping functions:
  - `escHtml()` - HTML context escaping
  - `escAttr()` - HTML attribute escaping
  - `escUrl()` - URL escaping
  - `escJs()` - JavaScript context escaping
  - `escCss()` - CSS context escaping

- HTML filtering:
  - `kses()` - WordPress-style HTML filtering

- Laravel integration:
  - Security facade for easy access
  - Global helper functions
  - Service provider for Laravel auto-discovery
  - Full Laravel framework compatibility

### Security Features
- Comprehensive XSS prevention
- Input sanitization for common data types
- Context-aware output escaping
- HTML filtering with allowlist approach
- Built on proven security libraries (Laminas Escaper)

### Developer Experience
- Simple facade and helper function APIs
- Extensive documentation and examples
- Full test coverage
- Laravel-style naming conventions

---

## Release Types

- **Major versions** (X.0.0) - Breaking changes, major feature additions
- **Minor versions** (X.Y.0) - New features, backwards-compatible
- **Patch versions** (X.Y.Z) - Bug fixes, security updates

## Security Updates

Security vulnerabilities are addressed as quickly as possible. If you discover a security issue, please report it responsibly by following our [security reporting guidelines](contributing#security-contributions).

## Upgrade Guides

### Upgrading to 1.0.3
No breaking changes. Simply update your composer dependencies:

```bash
composer update artisanpackui/security
```

### Upgrading to 1.0.2
No breaking changes. The `kses()` function has been fixed and should work correctly now.

### Upgrading to 1.0.1
No breaking changes. This release only removes unnecessary files from the package.

## Future Plans

Planned features for future releases:
- Additional sanitization functions for specific use cases
- Enhanced HTML filtering with custom tag configurations
- Performance optimizations
- Additional Laravel integrations

## Contributing

See our [Contributing Guide](contributing) for information on how to contribute to this changelog and the project overall.