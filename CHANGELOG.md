# ArtisanPack UI Security Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.2] - 2026-06-09

### Added

- Laravel 13 support. Widened the `illuminate/support` constraint to `^10.0|^11.0|^12.0|^13.0`. Existing Laravel 10/11/12 users are unaffected; Laravel 13 is only selectable on PHP 8.3+ per its own framework constraint.

### Changed

- Widened `orchestra/testbench` dev requirement to `^10.2|^11.0` so package tests can install against Laravel 13.
- Swept the package through Laravel Pint to bring it back in line with the configured code style (no behavioral changes).

## [2.0.1] - 2026-05-21

### Fixed

- Restore the `csp:test` command (`CspTest`) to the distributed package. An over-broad `export-ignore` rule (`/src/**/*Test.php`) stripped it from the release tarball, so `SecurityServiceProvider` registered a class that wasn't shipped — causing `Target class [ArtisanPackUI\Security\Console\Commands\CspTest] does not exist` during package discovery for every consumer.

## [2.0.0] - 2026-05-18

### Changed

- Promotes the `2.0.0-alpha.1` feature surface to the stable `2.0.0` release. No code changes from the alpha — see the alpha entry below for the complete 2.0 changelog.

## [2.0.0-alpha.1] - 2026-05-09

### Changed

- **BREAKING**: Repackaged from monolithic security toolkit into a focused core package plus sibling packages. Authentication, 2FA, RBAC, secure uploads, security analytics, and compliance now live in their own packages. See [UPGRADE.md](UPGRADE.md) for the full migration guide.

### Added

- Content Security Policy subsystem: nonce generator, policy service, policy builder, three presets (`Strict`, `Relaxed`, `Livewire`), violation reporting endpoint, `csp-dashboard` Livewire component, and Artisan commands (`csp:test`, `csp:stats`, `csp:prune`, `csp:generate`).
- Security testing toolkit: OWASP / header / dependency / configuration scanners, penetration attack simulator (SQL, XSS, CSRF, path traversal, auth bypass, injection), report generators (JSON, HTML, JUnit, SARIF, Markdown), benchmark suite, security gate, and GitHub Actions integration.
- Security audit Artisan commands: `security:audit`, `security:scan`, `security:baseline`, `security:benchmark`, `security:check-config`, `security:test-headers`, `security:scan-deps`, `security:clear-rate-limits`.
- `Csp` Facade alongside the existing `Security` Facade.
- `@csp_nonce` Blade directive and `<x-csp-nonce>` component.
- Named rate limiters driven from config (`web`, `api`, `login`, `password_reset`).

### Removed

- Authentication, 2FA, password complexity, account lockout, advanced sessions → moved to `artisanpack-ui/security-auth`.
- WebAuthn / FIDO2, SSO, social auth, biometric, device fingerprinting → moved to `artisanpack-ui/security-advanced-auth`.
- Roles, permissions, Blade directives, Gate integration → moved to `artisanpack-ui/rbac`.
- Secure file uploads, validation, malware scanning → moved to `artisanpack-ui/secure-uploads`.
- Security event logging, anomaly detection, SIEM export, incident response → moved to `artisanpack-ui/security-analytics`.
- GDPR / CCPA / LGPD compliance toolkit → moved to `artisanpack-ui/compliance`.

## [1.0.3] - 2025-05-14

### Changed

- Renamed vendor to ArtisanPack UI.

## [1.0.2] - 2025-04-21

### Fixed

- Issue with the `kses()` function.

### Added

- Tests and a GitLab pipeline.

## [1.0.1] - 2025-04-20

### Removed

- Unnecessary files from the published package.

## [1.0.0] - 2025-04-17

### Added

- Initial release.
