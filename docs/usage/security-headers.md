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
