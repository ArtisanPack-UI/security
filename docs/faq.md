---
title: Frequently Asked Questions
---

# Frequently Asked Questions

Common questions about the ArtisanPack Security package.

## General

### What Laravel versions are supported?

The package supports Laravel 10.x and 11.x. PHP 8.1 or higher is required.

### Can I use this package with Jetstream/Breeze?

Yes, the package is designed to work alongside Laravel Jetstream and Breeze. However, some features may overlap (like 2FA in Jetstream). You can disable specific features in the configuration to avoid conflicts.

### Does this package replace Laravel's built-in authentication?

No, it extends and enhances Laravel's authentication system. It uses Laravel's authentication guards and providers as the foundation.

### Is this package production-ready?

Yes, the package is designed for production use with comprehensive security features, testing, and documentation.

---

## Authentication

### How do I require 2FA for all users?

Set the enforcement mode to `required`:

```php
'twoFactor' => [
    'enforcement' => [
        'mode' => 'required',
        'grace_period_days' => 7,  // Give users time to set up
    ],
],
```

### Can I use multiple 2FA methods simultaneously?

Yes, users can have TOTP and backup methods (email, SMS) enabled. The primary method is TOTP, with backups available if the user's authenticator app is unavailable.

### How do I integrate with existing social login?

If you already use Laravel Socialite, you can configure the package to use your existing provider setup:

```php
'social' => [
    'enabled' => true,
    'link_existing_accounts' => true,  // Link social to existing email accounts
],
```

### What happens if a user loses access to their 2FA device?

Users can use recovery codes. If those are also lost, an administrator can disable 2FA:

```bash
php artisan 2fa:disable user@example.com --force
```

### Can I use hardware security keys (WebAuthn)?

Yes, WebAuthn/Passkeys are supported. Enable in configuration:

```php
'webauthn' => [
    'enabled' => true,
    'relying_party_id' => 'yourdomain.com',
],
```

---

## Sessions

### How many concurrent sessions should I allow?

It depends on your use case:
- **High security apps**: 1-2 sessions
- **Standard apps**: 3-5 sessions
- **Consumer apps**: 5-10 sessions

### Why are my users getting logged out unexpectedly?

Common causes:
1. Session timeout too short
2. IP binding too strict for mobile users
3. Session driver issues

See [Troubleshooting Guide](troubleshooting.md#session-issues) for solutions.

### Does session binding work with mobile apps?

For mobile apps, consider relaxing IP binding:

```php
'binding' => [
    'ip_address' => [
        'strictness' => 'none',  // Mobile IPs change frequently
    ],
],
```

---

## API Security

### What's the difference between abilities and permissions?

- **Abilities**: Token-level scopes that limit what an API token can do
- **Permissions**: User-level access control via RBAC

A token can only access what both the token abilities AND user permissions allow.

### How long should API tokens last?

It depends on use case:
- **User-facing apps**: 30-90 days
- **Server-to-server**: 365 days or longer
- **Temporary access**: 1-7 days

### Can I revoke all tokens for a user?

Yes:

```php
$user->tokens()->delete();
```

Or via CLI:

```bash
php artisan token:revoke-all user@example.com
```

### How do I implement API key authentication instead of tokens?

The package uses bearer tokens. For API key style authentication, create a token and use it as an API key in the `Authorization` header.

---

## RBAC

### What's the difference between roles and permissions?

- **Roles**: Groups of permissions assigned to users (e.g., "admin", "editor")
- **Permissions**: Specific actions users can perform (e.g., "edit-posts", "delete-users")

### Can a user have multiple roles?

Yes, users can have multiple roles, and their permissions are the union of all role permissions.

### How do I create a super admin that bypasses all checks?

Configure the super admin role:

```php
'rbac' => [
    'super_admin_role' => 'super-admin',
],
```

Users with this role bypass all permission checks.

### How do I check permissions in Blade templates?

```blade
@permission('edit-posts')
    <button>Edit</button>
@endpermission

@role('admin')
    <a href="/admin">Admin Panel</a>
@endrole
```

---

## CSP

### Why are my scripts being blocked?

CSP blocks inline scripts by default. Add a nonce:

```blade
<script nonce="{{ cspNonce() }}">
    // Your code
</script>
```

### Should I use report-only mode in production?

Start with report-only in production to identify issues, then switch to enforcement once you've resolved violations.

### How do I allow Google Analytics?

Add Google's domains to your CSP:

```php
'script-src' => ["'self'", "'nonce'", 'https://www.google-analytics.com'],
```

See [CSP Framework Guide](csp-framework.md) for complete configurations.

### Is unsafe-inline ever acceptable?

Avoid `unsafe-inline` when possible. Use nonces instead. The only common exception is for CSS in some frameworks that generate inline styles dynamically.

---

## File Uploads

### What file types should I allow?

Only allow what your application actually needs. A common safe set:

- Images: JPEG, PNG, GIF, WebP
- Documents: PDF
- Data: CSV, TXT

Avoid executable types (PHP, JS, etc.) unless absolutely necessary.

### Do I need malware scanning?

For user-uploaded content that will be served to other users, malware scanning is strongly recommended. For internal use only, it may be optional.

### How do I scan files without ClamAV?

Use the VirusTotal driver for cloud-based scanning:

```php
'malwareScanning' => [
    'driver' => 'virustotal',
    'virustotal' => [
        'apiKey' => env('VIRUSTOTAL_API_KEY'),
    ],
],
```

Note: VirusTotal has API rate limits.

### Why are SVG files blocked by default?

SVG files can contain embedded JavaScript, making them a potential XSS vector. If you need SVG support, sanitize them before serving.

---

## Compliance

### Does this package make me GDPR compliant?

The package provides tools to help with GDPR compliance (data export, consent management, right to erasure), but compliance depends on how you use them and your overall data practices. Consult with a legal professional.

### How long should I retain audit logs?

Common recommendations:
- Security logs: 90 days minimum
- Audit logs: 1-7 years depending on regulations
- User activity: 30-90 days

Check your industry regulations for specific requirements.

### How do I handle data deletion requests?

Use the GDPR erasure feature:

```php
use ArtisanPackUI\Security\Services\GdprService;

$gdpr = app(GdprService::class);
$gdpr->processErasureRequest($user);
```

This handles cascading deletion across related data.

---

## Performance

### Will this package slow down my application?

The package is optimized for minimal performance impact. Key optimizations:
- Caching for roles/permissions
- Async malware scanning option
- Efficient database queries

### How do I optimize for high-traffic applications?

1. Enable caching for RBAC
2. Use Redis for sessions
3. Use async file scanning
4. Reduce logging verbosity in production

### Should I disable features I don't use?

Yes, disable unused features to reduce overhead:

```php
'social' => ['enabled' => false],
'webauthn' => ['enabled' => false],
'malwareScanning' => ['enabled' => false],
```

---

## Security

### Is password hashing secure?

The package uses Laravel's built-in hashing, which uses bcrypt by default. You can configure Argon2id for additional security:

```php
// config/hashing.php
'driver' => 'argon2id',
```

### How does Have I Been Pwned integration work?

The package uses k-anonymity to check passwords against the HIBP database. Only the first 5 characters of the password hash are sent to the API, ensuring the full password is never transmitted.

### What happens if the HIBP service is unavailable?

By default, passwords are allowed if the service is unavailable (`failOpen` = true). For higher security, set `failOpen` = false to reject passwords when the service is unavailable.

### How do I report a security vulnerability?

Do not report security vulnerabilities through public GitHub issues. Contact the maintainers directly through the security contact method specified in the repository.

---

## Development

### How do I test security features?

The package provides test helpers and traits. See [Security Testing Guide](security-testing.md) for comprehensive testing documentation.

### Can I extend the package's classes?

Yes, most classes are designed for extension. Bind your custom implementations in a service provider:

```php
$this->app->bind(
    \ArtisanPackUI\Security\Contracts\TwoFactorInterface::class,
    \App\Security\CustomTwoFactor::class
);
```

### How do I add custom authentication methods?

Implement the appropriate interface and register with the package:

```php
use ArtisanPackUI\Security\Contracts\AuthenticationMethodInterface;

class BiometricAuthentication implements AuthenticationMethodInterface
{
    // Implementation
}
```

### Can I use this with Livewire?

Yes, the package includes Livewire components for common features. Import and use them in your views:

```blade
<livewire:security-dashboard />
<livewire:session-manager />
<livewire:two-factor-setup />
```

---

## Upgrading

### How do I upgrade to a new version?

1. Update via Composer:

```bash
composer update artisanpackui/security
```

2. Check the changelog for breaking changes
3. Run new migrations:

```bash
php artisan migrate
```

4. Clear caches:

```bash
php artisan config:clear
php artisan cache:clear
php artisan security:clear-cache --all
```

### Will upgrades break my customizations?

Published configuration files won't be overwritten. Check the changelog for any configuration changes and merge them manually.

---

## Related Documentation

- [Troubleshooting Guide](troubleshooting.md)
- [Implementation Guide](implementation-guide.md)
- [Configuration Reference](configuration-reference.md)
