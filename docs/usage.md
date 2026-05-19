---
title: Usage
---

# Usage

The package exposes its functionality through five layers — sanitization helpers, escaping helpers, validation rules, middleware, and Content Security Policy — plus a set of Artisan commands for auditing and CSP management.

## Topics

- [Input validation + sanitization](usage/input-validation.md) — `sanitizeEmail`, `sanitizeText`, `sanitizeInt`, `sanitizeArray`, `kses()`, `NoHtml` / `SecureUrl` rules
- [Security headers](usage/security-headers.md) — `security.headers` middleware, configured headers, custom headers
- [Content Security Policy (CSP)](usage/csp.md) — nonce generator, policy builder, presets, violation reporting, dashboard
- [Rate limiting](usage/rate-limiting.md) — named limiters, per-route `api.rate_limit`
- [Session security](usage/session-security.md) — encrypted sessions, validation, hijacking detection
- [API security](usage/api-security.md) — `api.security` middleware, token validation, API-specific headers
- [Artisan commands](usage/artisan-commands.md) — full command reference (security:* and csp:*)

## Quick reference

```php
use ArtisanPackUI\Security\Facades\Security;

// Sanitize (input)
$email = Security::sanitizeEmail($request->input('email'));
$body = Security::kses($request->input('body'));

// Or use the helper functions
$email = sanitizeEmail($request->input('email'));
$body = kses($request->input('body'));

// Escape (output)
echo escHtml($user->bio);
echo escAttr($formAction);
echo escJs($payload);
```

```blade
{{-- CSP nonce on inline scripts --}}
<script @csp_nonce>
    // ...
</script>

{{-- Validation rules --}}
'comment' => ['required', new NoHtml],
'website' => ['nullable', new SecureUrl],
```

```php
// Middleware
Route::middleware(['csp', 'security.headers', 'xss.protection'])->group(...);
Route::middleware('api.rate_limit:api')->group(...);
```

```bash
# Artisan
php artisan security:audit
php artisan security:scan
php artisan security:test-headers
php artisan csp:generate
```
