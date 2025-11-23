# Plan: Implement Security Headers Middleware

This document outlines the step-by-step plan to create and integrate a `SecurityHeadersMiddleware` into the ArtisanPack UI Security package.

## 1. Configuration

The security header policies will be configurable. The main configuration file is the ideal place for these settings.

**File:** `config/security.php`

**Action:** Add a new `security-headers` key to the main configuration array. This key will hold an array of headers and their default values.

```php
// In config/security.php

return [
    // ... existing configuration ...

    /*
    |--------------------------------------------------------------------------
    | Security Headers
    |--------------------------------------------------------------------------
    |
    | Here you may define the security headers that will be applied to all
    | responses. You can override these values in your application's
    | config/artisanpack/security.php file.
    |
    */
    'security-headers' => [
        'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
        'X-Frame-Options' => 'SAMEORIGIN',
        'X-Content-Type-Options' => 'nosniff',
        'X-XSS-Protection' => '1; mode=block',
        'Referrer-Policy' => 'no-referrer-when-downgrade',
        'Content-Security-Policy' => "default-src 'self'",
    ],
];
```

## 2. Middleware Implementation

A new middleware class will be created to handle the logic of adding the headers to the response.

**Location:** `src/Http/Middleware/`
**New File:** `SecurityHeadersMiddleware.php`

**Action:** Create the new middleware file. It will read the configuration and apply the headers to the outgoing response.

```php
// In src/Http/Middleware/SecurityHeadersMiddleware.php

namespace ArtisanPackUI\Security\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

class SecurityHeadersMiddleware
{
    public function handle(Request $request, Closure $next): Response
    {
        /** @var Response $response */
        $response = $next($request);

        $headers = config('artisanpack.security.security-headers', []);

        foreach ($headers as $key => $value) {
            if ($value !== null && $value !== '') {
                $response->headers->set($key, $value);
            }
        }

        return $response;
    }
}
```

## 3. Service Provider Registration

The new middleware must be registered with the Laravel Kernel to be executed on every request. This is done in the package's service provider.

**File:** `src/SecurityServiceProvider.php`

**Action:** In the `boot` method, use the injected `Kernel` to push the new middleware onto the global middleware stack.

```php
// In src/SecurityServiceProvider.php, inside the boot() method

use ArtisanPackUI\Security\Http\Middleware\SecurityHeadersMiddleware;
// ... other use statements

public function boot(Kernel $kernel): void
{
    // ... existing boot logic ...

    $kernel->pushMiddleware(EnsureSessionIsEncrypted::class);
    $kernel->pushMiddleware(SecurityHeadersMiddleware::class); // Add this line

    $this->bootTwoFactorAuthentication();
}
```

## 4. Testing

A feature test should be created to ensure the middleware correctly adds the configured headers to the response.

**Location:** `tests/Feature/`
**New File:** `SecurityHeadersMiddlewareTest.php`

**Action:** Create a new test file that verifies the middleware's behavior.

```php
// In tests/Feature/SecurityHeadersMiddlewareTest.php

namespace Tests\Feature;

use ArtisanPackUI\Security\Http\Middleware\SecurityHeadersMiddleware;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Config;
use Tests\TestCase;

class SecurityHeadersMiddlewareTest extends TestCase
{
    /** @test */
    public function it_adds_configured_security_headers_to_the_response()
    {
        $headers = [
            'X-Frame-Options' => 'DENY',
            'X-Content-Type-Options' => 'nosniff',
            'Content-Security-Policy' => "default-src 'none'",
        ];
        Config::set('artisanpack.security.security-headers', $headers);

        $request = new Request();
        $middleware = new SecurityHeadersMiddleware();

        $response = $middleware->handle($request, function () {
            return new Response('Test Content');
        });

        $this->assertEquals('DENY', $response->headers->get('X-Frame-Options'));
        $this->assertEquals('nosniff', $response->headers->get('X-Content-Type-Options'));
        $this->assertEquals("default-src 'none'", $response->headers->get('Content-Security-Policy'));
    }

    /** @test */
    public function it_does_not_add_headers_that_are_null_or_empty()
    {
        $headers = [
            'X-Frame-Options' => 'SAMEORIGIN',
            'X-Content-Type-Options' => null, // This should be ignored
            'Referrer-Policy' => '', // This should be ignored
        ];
        Config::set('artisanpack.security.security-headers', $headers);

        $request = new Request();
        $middleware = new SecurityHeadersMiddleware();

        $response = $middleware->handle($request, function () {
            return new Response('Test Content');
        });

        $this->assertEquals('SAMEORIGIN', $response->headers->get('X-Frame-Options'));
        $this->assertFalse($response->headers->has('X-Content-Type-Options'));
        $this->assertFalse($response->headers->has('Referrer-Policy'));
    }
}
```

## 5. Documentation

A new documentation file should be created to explain the feature, its configuration, and how to use it.

**Location:** `docs/`
**New File:** `security-headers.md`

**Action:** Create the new markdown file with the following content.

```markdown
# Security Headers

The ArtisanPack UI Security package automatically adds essential security headers to all outgoing responses to protect your application from common attacks like clickjacking and cross-site scripting (XSS).

## Configuration

The headers are enabled by default. You can customize them by publishing the package's configuration file:

```bash
php artisan vendor:publish --tag=artisanpack-package-config
```

This will create a `config/artisanpack/security.php` file in your application. You can then edit the `security-headers` array to modify or disable specific headers. To disable a header, set its value to `null` or an empty string.

```php
// config/artisanpack/security.php

'security-headers' => [
    'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
    'X-Frame-Options' => 'SAMEORIGIN',
    'X-Content-Type-Options' => 'nosniff',
    'X-XSS-Protection' => '1; mode=block',
    'Referrer-Policy' => 'no-referrer-when-downgrade',
    // Disable CSP by setting it to null
    'Content-Security-Policy' => null,
],
```

## Default Headers

- **Strict-Transport-Security:** Enforces HTTPS across your site.
- **X-Frame-Options:** Protects against clickjacking.
- **X-Content-Type-Options:** Prevents MIME-sniffing.
- **X-XSS-Protection:** A basic XSS filter (mostly for older browsers).
- **Referrer-Policy:** Controls how much referrer information is sent.
- **Content-Security-Policy (CSP):** A powerful tool to prevent XSS and data injection attacks. The default is very restrictive (`default-src 'self'`); you will likely need to customize it for your application.

```
