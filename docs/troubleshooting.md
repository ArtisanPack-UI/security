---
title: Troubleshooting Guide
---

# Troubleshooting Guide

Solutions to common issues when using the ArtisanPack Security package.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Authentication Issues](#authentication-issues)
- [Two-Factor Authentication Issues](#two-factor-authentication-issues)
- [Session Issues](#session-issues)
- [API Token Issues](#api-token-issues)
- [RBAC Issues](#rbac-issues)
- [CSP Issues](#csp-issues)
- [File Upload Issues](#file-upload-issues)
- [Performance Issues](#performance-issues)
- [Migration Issues](#migration-issues)

---

## Installation Issues

### Package not found

**Problem**: `Package artisanpackui/security not found`

**Solution**:

1. Check your `composer.json` has the correct repository configured
2. Clear composer cache:

```bash
composer clear-cache
composer update
```

3. Verify you have access to the package repository

---

### Configuration not published

**Problem**: Config file not found at `config/artisanpack/security.php`

**Solution**:

```bash
php artisan vendor:publish --provider="ArtisanPackUI\Security\SecurityServiceProvider" --tag="config"
```

If already published but missing, check:

```bash
php artisan vendor:publish --provider="ArtisanPackUI\Security\SecurityServiceProvider" --tag="config" --force
```

---

### Migrations fail

**Problem**: Migration errors when running `php artisan migrate`

**Solution**:

1. Check for table conflicts:

```bash
php artisan migrate:status
```

2. If tables already exist, you may need to:

```bash
# Reset and re-run (DEVELOPMENT ONLY)
php artisan migrate:fresh

# Or publish migrations to customize
php artisan vendor:publish --provider="ArtisanPackUI\Security\SecurityServiceProvider" --tag="migrations"
```

3. Check database connection and permissions

---

## Authentication Issues

### Login always fails

**Problem**: Valid credentials are rejected

**Possible Causes & Solutions**:

1. **Password hashing mismatch**:

```php
// Verify password hash
$user = User::where('email', 'test@example.com')->first();
var_dump(Hash::check('password', $user->password));
```

2. **Account is locked**:

```bash
php artisan user:unlock test@example.com
```

3. **Rate limiting**:

```php
// Clear rate limiting
RateLimiter::clear('login:' . request()->ip());
```

4. **Missing authentication guard**:

Check `config/auth.php` has correct guard configuration.

---

### "Account locked" message

**Problem**: User sees account locked message but shouldn't be locked

**Solution**:

1. Check lockout status:

```bash
php artisan security:check-user user@example.com
```

2. Manually unlock:

```bash
php artisan user:unlock user@example.com
```

3. Verify lockout configuration:

```php
// config/artisanpack/security.php
'lockout' => [
    'threshold' => 5,           // Increase if too sensitive
    'duration_minutes' => 30,
],
```

---

### Social login redirect fails

**Problem**: OAuth redirect returns error

**Solutions**:

1. Verify callback URL matches provider configuration:

```env
# .env
GOOGLE_CALLBACK_URL=https://yourapp.com/auth/google/callback
```

2. Check provider credentials:

```bash
php artisan tinker
>>> config('services.google')
```

3. Ensure HTTPS in production (required by most providers)

4. Clear config cache:

```bash
php artisan config:clear
```

---

### SSO/SAML issues

**Problem**: SAML authentication fails

**Solutions**:

1. Verify certificates are correct:

```bash
# Check certificate validity
openssl x509 -in /path/to/cert.pem -text -noout
```

2. Check SAML metadata matches IDP configuration

3. Enable SAML debugging:

```php
'saml' => [
    'debug' => true,
],
```

4. Verify clock sync between SP and IDP

---

## Two-Factor Authentication Issues

### QR code not displaying

**Problem**: 2FA setup shows broken image

**Solutions**:

1. Install required library:

```bash
composer require bacon/bacon-qr-code
```

2. Check GD or Imagick extension is enabled:

```bash
php -m | grep -E 'gd|imagick'
```

3. Verify the route returns correct content type

---

### TOTP codes not accepted

**Problem**: Valid TOTP codes are rejected

**Solutions**:

1. **Server time sync**:

```bash
# Check server time
date

# Sync with NTP
sudo ntpdate -s time.nist.gov
```

2. **Increase time window**:

```php
'totp' => [
    'window' => 2,  // Allow codes from adjacent periods
],
```

3. **Check secret key**:

```php
// Verify stored secret
$user->two_factor_secret  // Should be base32 encoded
```

---

### Recovery codes exhausted

**Problem**: User has no recovery codes left

**Solution**:

```bash
# Regenerate recovery codes
php artisan 2fa:regenerate-recovery user@example.com --show
```

Or programmatically:

```php
use ArtisanPackUI\Security\Facades\TwoFactor;

$codes = TwoFactor::regenerateRecoveryCodes($user);
```

---

### 2FA enforced unexpectedly

**Problem**: Users required to set up 2FA when they shouldn't be

**Solution**:

Check enforcement configuration:

```php
'enforcement' => [
    'mode' => 'optional',           // Not 'required'
    'required_roles' => ['admin'],  // Check user's role
],
```

---

## Session Issues

### Sessions expiring too quickly

**Problem**: Users logged out unexpectedly

**Solutions**:

1. Check session configuration:

```php
// config/session.php
'lifetime' => 120,  // Minutes

// config/artisanpack/security.php
'timeouts' => [
    'idle_minutes' => 30,
    'absolute_minutes' => 480,
    'extend_on_activity' => true,
],
```

2. Ensure AJAX requests include session cookies

3. Check session driver:

```env
SESSION_DRIVER=database  # More reliable than file
```

---

### Session binding violations

**Problem**: Legitimate users getting logged out with "Session invalid" errors

**Solutions**:

1. **Mobile users with changing IPs**:

```php
'binding' => [
    'ip_address' => [
        'strictness' => 'none',  // Or 'subnet'
    ],
],
```

2. **Users behind load balancers**:

Ensure `X-Forwarded-For` header is trusted:

```php
// In TrustProxies middleware
protected $proxies = '*';
```

3. **Browser updates changing user agent**:

```php
'user_agent' => [
    'strictness' => 'browser_only',  // Not 'exact'
],
```

---

### Too many sessions terminated

**Problem**: Users constantly logging out other devices

**Solution**:

Increase concurrent session limit:

```php
'concurrent_sessions' => [
    'max_sessions' => 10,  // Increase from default
],
```

---

## API Token Issues

### Token not authenticating

**Problem**: API requests return 401 Unauthorized

**Solutions**:

1. Verify token format in header:

```bash
curl -H "Authorization: Bearer YOUR_TOKEN_HERE" https://api.example.com/user
```

2. Check token hasn't expired:

```php
$token = PersonalAccessToken::findToken('your-token');
$token->expires_at;  // Check expiration
```

3. Verify token abilities match route requirements:

```php
Route::middleware('token.ability:read')->get('/posts', ...);
```

---

### Token abilities not working

**Problem**: Token can access routes it shouldn't

**Solutions**:

1. Ensure middleware is applied:

```php
Route::middleware(['auth:sanctum', 'token.ability:write'])->...
```

2. Check token was created with correct abilities:

```php
$token = $user->createApiToken('name', ['read']);  // Only read ability
```

---

## RBAC Issues

### Permissions not updating

**Problem**: User has new role but old permissions

**Solution**:

Clear the RBAC cache:

```bash
php artisan security:clear-cache --roles
```

Or programmatically:

```php
use ArtisanPackUI\Security\Facades\RBAC;

RBAC::clearCache();
```

---

### hasPermission always returns false

**Problem**: `$user->hasPermission('something')` always returns false

**Solutions**:

1. Verify permission exists:

```bash
php artisan permission:list
```

2. Check permission is assigned to role:

```bash
php artisan role:list --with-permissions
```

3. Verify user has the role:

```php
$user->roles->pluck('name');
```

4. Check permission name spelling (case-sensitive)

---

### Super admin not bypassing permissions

**Problem**: Super admin still denied access

**Solution**:

Verify super admin role is configured:

```php
'rbac' => [
    'super_admin_role' => 'super-admin',  // Check this matches
],
```

And user has this exact role:

```php
$user->hasRole('super-admin');  // Must match exactly
```

---

## CSP Issues

### Scripts/styles blocked

**Problem**: Console shows CSP violations, functionality broken

**Solutions**:

1. **Add nonce to inline scripts**:

```blade
<script nonce="{{ cspNonce() }}">
    // Your code
</script>
```

2. **Add external domains to CSP**:

```php
'directives' => [
    'script-src' => ["'self'", "'nonce'", 'https://cdn.example.com'],
],
```

3. **Use report-only mode to debug**:

```php
'csp' => [
    'report_only' => true,
],
```

---

### CSP breaking third-party widgets

**Problem**: Google Analytics, Stripe, etc. not working

**Solution**:

Add required sources. See [CSP Framework Guide](csp-framework.md) for common configurations.

Example for Google Analytics:

```php
'script-src' => [
    "'self'", "'nonce'",
    'https://www.google-analytics.com',
    'https://www.googletagmanager.com',
],
```

---

### Livewire not working with CSP

**Problem**: Livewire components fail with CSP enabled

**Solution**:

Ensure nonces are applied to Livewire scripts:

```php
// Livewire v3 handles this automatically with nonces
// For v2, you may need:
'script-src' => ["'self'", "'nonce'", "'unsafe-eval'"],  // unsafe-eval for Alpine
```

---

## File Upload Issues

### All uploads rejected

**Problem**: Every file upload fails validation

**Solutions**:

1. Check allowed MIME types:

```php
'allowedMimeTypes' => [
    'image/jpeg', 'image/png',  // Ensure your types are here
],
```

2. Check file size limits:

```php
'maxFileSize' => 10 * 1024 * 1024,  // 10MB
```

3. Also check PHP limits:

```ini
; php.ini
upload_max_filesize = 10M
post_max_size = 10M
```

---

### False positive malware detection

**Problem**: Clean files flagged as malware

**Solutions**:

1. Check scanner configuration
2. Use async scanning with manual review:

```php
'malwareScanning' => [
    'async' => true,
    'quarantinePath' => storage_path('app/quarantine'),
],
```

3. Review and release from quarantine:

```bash
php artisan files:scan-quarantine --list
php artisan files:scan-quarantine --release=file_id
```

---

### Signed URLs not working

**Problem**: File download URLs return 403

**Solutions**:

1. Check URL hasn't expired:

```php
'serving' => [
    'signedUrlExpiration' => 60,  // Increase if needed
],
```

2. Verify route is configured correctly

3. Check file exists in storage

---

## Performance Issues

### Slow page loads

**Problem**: Pages load slowly after adding security middleware

**Solutions**:

1. **Enable caching**:

```php
'rbac' => [
    'cache' => true,
    'cache_ttl' => 3600,
],
```

2. **Reduce logging verbosity**:

```php
'logging' => [
    'events' => [
        'authentication' => true,
        'authorization' => false,  // Disable verbose logging
    ],
],
```

3. **Use async scanning for files**:

```php
'malwareScanning' => [
    'async' => true,
],
```

---

### High memory usage

**Problem**: Memory exhaustion with security features

**Solutions**:

1. **Reduce metrics retention**:

```php
'metrics' => [
    'retention_days' => 30,  // Reduce from 90
],
```

2. **Run cleanup regularly**:

```bash
php artisan security:metrics-cleanup --days=30
php artisan compliance:cleanup
```

3. **Use Redis for sessions/cache**:

```env
SESSION_DRIVER=redis
CACHE_DRIVER=redis
```

---

## Migration Issues

### Upgrading from older version

**Problem**: Errors after package upgrade

**Solutions**:

1. Clear all caches:

```bash
php artisan cache:clear
php artisan config:clear
php artisan route:clear
php artisan view:clear
php artisan security:clear-cache --all
```

2. Run new migrations:

```bash
php artisan migrate
```

3. Re-publish configuration (backup first):

```bash
cp config/artisanpack/security.php config/artisanpack/security.php.bak
php artisan vendor:publish --tag="config" --force
```

4. Merge your customizations back into new config

---

## Debugging Tips

### Enable debug mode

For development only:

```php
// config/artisanpack/security.php
'debug' => env('SECURITY_DEBUG', false),
```

```env
SECURITY_DEBUG=true
```

### Check logs

```bash
tail -f storage/logs/security.log
```

### Run diagnostics

```bash
php artisan security:check-config
php artisan security:audit --check=config
```

### Test in isolation

```php
// Temporarily disable middleware
Route::withoutMiddleware(['csp', 'security.headers'])->group(...);
```

---

## Getting Help

If you can't resolve an issue:

1. Check the [FAQ](faq.md)
2. Search existing issues on GitHub
3. Create a new issue with:
   - Laravel version
   - Package version
   - PHP version
   - Steps to reproduce
   - Error messages/logs

---

## Related Documentation

- [Configuration Reference](configuration-reference.md)
- [FAQ](faq.md)
- [Implementation Guide](implementation-guide.md)
