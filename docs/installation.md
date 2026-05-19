---
title: Installation
---

# Installation

## Install via Composer

```bash
composer require artisanpack-ui/security
```

The package auto-registers via Laravel's package discovery.

## Publish the config

```bash
php artisan vendor:publish --tag=security-config
```

Publishes `config/artisanpack/security.php`. Override headers, rate limiting, XSS protection, API security, CSP, testing, logging, and command defaults here.

## Run migrations

```bash
php artisan migrate
```

Adds the `csp_violation_reports` table used by the CSP violation reporting endpoint.

## Apply middleware

The package's middleware are aliased by the service provider but **not applied globally** — you opt in per route or in your `app/Http/Kernel.php` middleware groups:

```php
// app/Http/Kernel.php (Laravel 10)
protected $middlewareGroups = [
    'web' => [
        // ...
        \ArtisanPackUI\Security\Http\Middleware\SecurityHeadersMiddleware::class,
        \ArtisanPackUI\Security\Http\Middleware\ContentSecurityPolicy::class,
    ],
];
```

Or in `bootstrap/app.php` (Laravel 11+):

```php
->withMiddleware(function (Middleware $middleware) {
    $middleware->web(append: [
        \ArtisanPackUI\Security\Http\Middleware\SecurityHeadersMiddleware::class,
        \ArtisanPackUI\Security\Http\Middleware\ContentSecurityPolicy::class,
    ]);
})
```

The shipped middleware aliases (`csp`, `security.headers`, `xss.protection`, `api.security`, `api.rate_limit`) work in route definitions:

```php
Route::middleware(['csp', 'security.headers'])->group(function () {
    // ...
});
```

## Deeper topics

- [Configuration](installation/configuration.md) — full config reference
- [Configuration management](installation/configuration-management.md) — patterns for layered / per-environment overrides
- [Environment variables](installation/environment-variables.md) — every env var the package reads
