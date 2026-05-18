---
title: CSP Framework Guide
---

# CSP Framework Guide

This guide covers the Content Security Policy (CSP) framework including policy configuration, nonce-based scripts, report-only mode, and violation reporting.

## Overview

The ArtisanPack Security package provides a comprehensive CSP implementation:

- **Policy Builder**: Fluent API for building CSP policies
- **Nonce Generation**: Automatic nonce generation for inline scripts/styles
- **Report-Only Mode**: Test policies without breaking functionality
- **Violation Reporting**: Collect and analyze CSP violations
- **Environment Profiles**: Different policies for development/production

## What is CSP?

Content Security Policy is an HTTP header that helps prevent cross-site scripting (XSS), clickjacking, and other code injection attacks by specifying which sources of content are allowed to load on your pages.

## Configuration

Configure CSP in `config/artisanpack/security.php`:

```php
'csp' => [
    'enabled' => env('SECURITY_CSP_ENABLED', true),
    'report_only' => env('SECURITY_CSP_REPORT_ONLY', false),

    'directives' => [
        'default-src' => ["'self'"],
        'script-src' => ["'self'", "'nonce'"],
        'style-src' => ["'self'", "'nonce'", "'unsafe-inline'"],
        'img-src' => ["'self'", 'data:', 'https:'],
        'font-src' => ["'self'", 'https://fonts.gstatic.com'],
        'connect-src' => ["'self'"],
        'media-src' => ["'self'"],
        'object-src' => ["'none'"],
        'frame-src' => ["'self'"],
        'frame-ancestors' => ["'self'"],
        'form-action' => ["'self'"],
        'base-uri' => ["'self'"],
        'upgrade-insecure-requests' => true,
    ],

    'nonce' => [
        'enabled' => true,
        'directives' => ['script-src', 'style-src'],
    ],

    'report' => [
        'enabled' => true,
        'endpoint' => '/csp-report',
        'log_violations' => true,
        'notify_on_violation' => false,
    ],
],
```

## Basic Usage

### Applying CSP Middleware

```php
// Apply to all web routes
Route::middleware(['csp'])->group(function () {
    Route::get('/', [HomeController::class, 'index']);
});

// Or in app/Http/Kernel.php for global application
protected $middlewareGroups = [
    'web' => [
        // ... other middleware
        \ArtisanPackUI\Security\Http\Middleware\ContentSecurityPolicy::class,
    ],
];
```

### Using Nonces in Blade Templates

```blade
{{-- Inline script with nonce --}}
<script nonce="{{ cspNonce() }}">
    console.log('This script is allowed');
</script>

{{-- Inline style with nonce --}}
<style nonce="{{ cspNonce() }}">
    .custom-class { color: blue; }
</style>

{{-- Or use the directive --}}
@cspNonce
<script nonce="{{ $cspNonce }}">
    // Your inline JavaScript
</script>
```

### JavaScript Framework Integration

For frameworks like Alpine.js or Vue.js:

```blade
<script nonce="{{ cspNonce() }}">
    window.Alpine = Alpine;
    Alpine.start();
</script>
```

For Livewire:

```php
// In config/livewire.php
'inject_assets' => true,

// CSP is automatically handled when using nonces
```

## Policy Builder

### Fluent API

```php
use ArtisanPackUI\Security\Services\CspPolicyService;

$csp = app(CspPolicyService::class);

$policy = $csp->policy()
    ->defaultSrc("'self'")
    ->scriptSrc("'self'", "'nonce'", 'https://cdn.example.com')
    ->styleSrc("'self'", "'unsafe-inline'")
    ->imgSrc("'self'", 'data:', 'https:')
    ->fontSrc("'self'", 'https://fonts.gstatic.com')
    ->connectSrc("'self'", 'https://api.example.com')
    ->frameSrc("'none'")
    ->objectSrc("'none'")
    ->baseUri("'self'")
    ->formAction("'self'")
    ->frameAncestors("'self'")
    ->upgradeInsecureRequests()
    ->build();
```

### Route-Specific Policies

```php
Route::get('/embed', [EmbedController::class, 'show'])
    ->middleware('csp:embed');

// Define the 'embed' policy in config
'csp' => [
    'policies' => [
        'default' => [
            // Default policy
        ],
        'embed' => [
            'directives' => [
                'frame-ancestors' => ['https://partner.example.com'],
            ],
        ],
    ],
],
```

### Dynamic Policy Modification

```php
use ArtisanPackUI\Security\Facades\Csp;

class PaymentController extends Controller
{
    public function checkout()
    {
        // Add payment provider to CSP for this request
        Csp::addSource('script-src', 'https://js.stripe.com');
        Csp::addSource('frame-src', 'https://js.stripe.com');
        Csp::addSource('connect-src', 'https://api.stripe.com');

        return view('checkout');
    }
}
```

## CSP Directives Reference

| Directive | Purpose | Common Values |
|-----------|---------|---------------|
| `default-src` | Fallback for other directives | `'self'` |
| `script-src` | JavaScript sources | `'self'`, `'nonce'`, domains |
| `style-src` | CSS sources | `'self'`, `'unsafe-inline'` |
| `img-src` | Image sources | `'self'`, `data:`, `https:` |
| `font-src` | Font sources | `'self'`, Google Fonts |
| `connect-src` | AJAX/WebSocket sources | `'self'`, API domains |
| `media-src` | Audio/Video sources | `'self'` |
| `object-src` | Plugin sources (Flash, etc.) | `'none'` |
| `frame-src` | iframe sources | `'self'`, embed domains |
| `frame-ancestors` | Who can embed this page | `'self'` |
| `form-action` | Form submission targets | `'self'` |
| `base-uri` | Base URL restrictions | `'self'` |
| `worker-src` | Web Worker sources | `'self'` |
| `manifest-src` | Manifest file sources | `'self'` |

### Source Values

| Value | Meaning |
|-------|---------|
| `'self'` | Same origin only |
| `'none'` | Block all sources |
| `'unsafe-inline'` | Allow inline (not recommended) |
| `'unsafe-eval'` | Allow eval() (not recommended) |
| `'nonce'` | Allow nonce-matched content |
| `'strict-dynamic'` | Trust scripts loaded by trusted scripts |
| `data:` | Allow data: URIs |
| `https:` | Allow any HTTPS source |
| `domain.com` | Specific domain |
| `*.domain.com` | Wildcard subdomain |

## Nonce-Based CSP

### How Nonces Work

A nonce is a random value generated per-request that allows specific inline scripts/styles to execute:

```html
<!-- This script will execute (nonce matches) -->
<script nonce="abc123">
    console.log('Allowed');
</script>

<!-- This script will be blocked (no nonce) -->
<script>
    console.log('Blocked');
</script>
```

### Configuration

```php
'nonce' => [
    'enabled' => true,
    'directives' => ['script-src', 'style-src'],  // Which directives use nonces
    'length' => 32,                                // Nonce length in bytes
],
```

### Accessing the Nonce

```php
// In controllers
use ArtisanPackUI\Security\Facades\Csp;

$nonce = Csp::getNonce();

// In Blade
{{ cspNonce() }}

// In JavaScript (via meta tag)
<meta name="csp-nonce" content="{{ cspNonce() }}">

<script>
    const nonce = document.querySelector('meta[name="csp-nonce"]').content;
</script>
```

### Nonce with Third-Party Scripts

For scripts that need to dynamically load other scripts:

```php
'directives' => [
    'script-src' => ["'self'", "'nonce'", "'strict-dynamic'"],
],
```

With `'strict-dynamic'`, scripts loaded by a nonced script are automatically trusted.

## Report-Only Mode

Test your CSP without breaking functionality:

### Configuration

```php
'csp' => [
    'report_only' => true,  // Use Content-Security-Policy-Report-Only header
],
```

### Gradual Rollout

```php
// Start in report-only mode
'report_only' => env('CSP_REPORT_ONLY', true),

// In production, gradually enable enforcement
// .env
CSP_REPORT_ONLY=false
```

### Environment-Based Policies

```php
'csp' => [
    'profiles' => [
        'development' => [
            'report_only' => true,
            'directives' => [
                'default-src' => ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
            ],
        ],
        'production' => [
            'report_only' => false,
            'directives' => [
                'default-src' => ["'self'"],
                'script-src' => ["'self'", "'nonce'"],
            ],
        ],
    ],
    'active_profile' => env('CSP_PROFILE', 'production'),
],
```

## Violation Reporting

### Enable Reporting

```php
'report' => [
    'enabled' => true,
    'endpoint' => '/csp-report',
    'log_violations' => true,
    'store_violations' => true,
    'notify_on_violation' => true,
    'notification_threshold' => 10,  // Notify after 10 violations/hour
],
```

### Report Endpoint

The package automatically registers a report endpoint:

```php
// Handled automatically, but you can customize:
Route::post('/csp-report', [CspReportController::class, 'store'])
    ->withoutMiddleware(['csrf']);
```

### Viewing Violations

```php
use ArtisanPackUI\Security\Models\CspViolation;

// Get recent violations
$violations = CspViolation::recent()->get();

// Get violations by directive
$scriptViolations = CspViolation::where('violated_directive', 'script-src')
    ->get();

// Get violation summary
$summary = CspViolation::selectRaw('violated_directive, COUNT(*) as count')
    ->groupBy('violated_directive')
    ->get();
```

### Violation Analysis

```bash
# List recent CSP violations
php artisan csp:violations

# Get violation summary
php artisan csp:violations --summary

# Export violations to CSV
php artisan csp:violations --export=violations.csv

# Clear old violations
php artisan csp:violations --clear --older-than=30
```

### Livewire Component

```blade
<livewire:csp-violation-viewer />
```

## Common Configurations

### Minimal Secure Policy

```php
'directives' => [
    'default-src' => ["'self'"],
    'script-src' => ["'self'"],
    'style-src' => ["'self'"],
    'img-src' => ["'self'"],
    'font-src' => ["'self'"],
    'object-src' => ["'none'"],
    'base-uri' => ["'self'"],
    'form-action' => ["'self'"],
    'frame-ancestors' => ["'none'"],
],
```

### With Google Services

```php
'directives' => [
    'default-src' => ["'self'"],
    'script-src' => [
        "'self'",
        "'nonce'",
        'https://www.google-analytics.com',
        'https://www.googletagmanager.com',
        'https://www.google.com/recaptcha/',
        'https://www.gstatic.com/recaptcha/',
    ],
    'style-src' => [
        "'self'",
        "'unsafe-inline'",  // Required for some Google widgets
        'https://fonts.googleapis.com',
    ],
    'img-src' => [
        "'self'",
        'data:',
        'https://www.google-analytics.com',
        'https://www.googletagmanager.com',
    ],
    'font-src' => [
        "'self'",
        'https://fonts.gstatic.com',
    ],
    'frame-src' => [
        "'self'",
        'https://www.google.com/recaptcha/',
    ],
    'connect-src' => [
        "'self'",
        'https://www.google-analytics.com',
    ],
],
```

### With Stripe

```php
'directives' => [
    'script-src' => [
        "'self'",
        "'nonce'",
        'https://js.stripe.com',
    ],
    'frame-src' => [
        "'self'",
        'https://js.stripe.com',
        'https://hooks.stripe.com',
    ],
    'connect-src' => [
        "'self'",
        'https://api.stripe.com',
    ],
],
```

### With CDN Assets

```php
'directives' => [
    'script-src' => [
        "'self'",
        'https://cdn.jsdelivr.net',
        'https://unpkg.com',
    ],
    'style-src' => [
        "'self'",
        'https://cdn.jsdelivr.net',
        'https://unpkg.com',
    ],
],
```

### SPA with API

```php
'directives' => [
    'default-src' => ["'self'"],
    'script-src' => ["'self'", "'nonce'"],
    'style-src' => ["'self'", "'nonce'"],
    'connect-src' => [
        "'self'",
        'https://api.example.com',
        'wss://ws.example.com',  // WebSocket
    ],
    'img-src' => ["'self'", 'data:', 'blob:', 'https://cdn.example.com'],
],
```

## Artisan Commands

### Generate CSP Policy

```bash
# Interactive policy generator
php artisan security:generate-csp

# Generate from template
php artisan security:generate-csp --template=strict

# Generate for specific use case
php artisan security:generate-csp --preset=google-analytics,stripe
```

### Test CSP Policy

```bash
# Test current policy against a URL
php artisan security:csp:test https://example.com

# Validate policy syntax
php artisan security:csp:test --validate

# Check for common issues
php artisan security:csp:test --audit
```

### Analyze Violations

```bash
# View violation report
php artisan csp:violations --period=7d

# Get recommendations based on violations
php artisan csp:analyze

# Export report
php artisan csp:violations --export=report.json
```

## Troubleshooting

### Common Issues

#### Inline Scripts Blocked

**Problem**: `Refused to execute inline script`

**Solution**: Add nonce to inline scripts:

```blade
{{-- Before --}}
<script>console.log('blocked');</script>

{{-- After --}}
<script nonce="{{ cspNonce() }}">console.log('allowed');</script>
```

#### Styles Not Loading

**Problem**: Inline styles blocked

**Solution**: Use nonces or external stylesheets:

```blade
{{-- Option 1: Nonce --}}
<style nonce="{{ cspNonce() }}">
    .class { color: blue; }
</style>

{{-- Option 2: Move to external file --}}
<link rel="stylesheet" href="/css/custom.css">
```

#### Third-Party Script Blocked

**Problem**: External script blocked

**Solution**: Add domain to script-src:

```php
'script-src' => ["'self'", 'https://example-cdn.com'],
```

#### Images Not Loading

**Problem**: Images from data: URIs blocked

**Solution**: Add data: to img-src:

```php
'img-src' => ["'self'", 'data:'],
```

### Debugging Tips

1. **Check Browser Console**: CSP violations appear in the console
2. **Use Report-Only**: Test without breaking functionality
3. **Review Violation Reports**: Identify what's being blocked
4. **Start Permissive**: Begin with a loose policy and tighten

### Development vs Production

```php
// config/artisanpack/security.php
'csp' => [
    'enabled' => env('CSP_ENABLED', true),
    'report_only' => env('CSP_REPORT_ONLY', app()->isLocal()),
],
```

## Events

| Event | Trigger |
|-------|---------|
| `CspViolationReported` | CSP violation received |
| `CspPolicyApplied` | CSP header added to response |
| `CspNonceGenerated` | New nonce generated for request |

## Best Practices

### 1. Start with Report-Only

```php
'report_only' => true,
```

Monitor violations before enforcing.

### 2. Use Nonces Over unsafe-inline

```php
// Good
'script-src' => ["'self'", "'nonce'"],

// Avoid
'script-src' => ["'self'", "'unsafe-inline'"],
```

### 3. Be Specific with Sources

```php
// Good - specific domain
'script-src' => ["'self'", 'https://cdn.example.com'],

// Avoid - too permissive
'script-src' => ["'self'", 'https:'],
```

### 4. Block Dangerous Directives

```php
'object-src' => ["'none'"],      // Block plugins
'base-uri' => ["'self'"],        // Prevent base tag injection
'form-action' => ["'self'"],     // Prevent form hijacking
```

### 5. Use frame-ancestors

```php
'frame-ancestors' => ["'self'"],  // Prevent clickjacking
```

### 6. Upgrade Insecure Requests

```php
'upgrade-insecure-requests' => true,
```

## Related Documentation

- [Implementation Guide](implementation-guide.md)
- [Security Headers](security-guidelines.md)
- [Configuration Reference](configuration-reference.md)
- [Troubleshooting Guide](troubleshooting.md)
