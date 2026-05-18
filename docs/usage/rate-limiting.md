# Rate Limiting

The ArtisanPack UI Security package provides a simple way to protect your application from brute force attacks by rate limiting incoming requests. It leverages Laravel's built-in rate-limiting capabilities.

## Configuration

The rate limiting feature is enabled by default. To customize the settings, publish the package's configuration file:

```bash
php artisan vendor:publish --tag=artisanpack-package-config
```

This will create a `config/artisanpack/security.php` file. You can then edit the `rateLimiting` section.

```php
// config/artisanpack/security.php

'rateLimiting' => [
    'enabled' => env('SECURITY_RATE_LIMITING_ENABLED', true),

    'limiters' => [
        'web' => [
            'maxAttempts' => 60,
            'decayMinutes' => 1,
        ],
        'api' => [
            'maxAttempts' => 60,
            'decayMinutes' => 1,
        ],
        'login' => [
            'maxAttempts' => 5,
            'decayMinutes' => 1,
        ],
        'password_reset' => [
            'maxAttempts' => 5,
            'decayMinutes' => 1,
        ],
    ],
],
```

## Usage

To apply a rate limit to a route or route group, use the `throttle` middleware with the name of the limiter you defined in the configuration file.

For example, to protect your login routes:

```php
// In routes/web.php

Route::post('/login', [LoginController::class, 'store'])
    ->middleware('throttle:login');
```

To protect your entire API:

```php
// In routes/api.php

Route::group(['middleware' => 'throttle:api'], function () {
    // Your API routes...
});
```

## Clearing Rate Limits

You can clear the rate limiter cache for a specific user or IP address using the provided Artisan command:

```bash
# Clear for a specific IP address
php artisan security:rate-limit:clear --ip="127.0.0.1"

# Clear for a specific user ID
php artisan security:rate-limit:clear --user=1
```
