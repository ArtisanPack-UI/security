# Plan: Implement Rate Limiting Protection

This document outlines the step-by-step plan to integrate a configurable, robust rate-limiting system into the ArtisanPack UI Security package, leveraging Laravel's built-in capabilities.

This plan assumes the best practice is to define named limiters and allow the end-user to apply them via middleware aliases, rather than creating a new middleware class that reimplements core framework functionality.

## 1. Configuration

First, we will add a new `rateLimiting` section to the main configuration file. This will allow users to enable/disable the feature and define various rate limit policies.

**File:** `config/security.php`

**Action:** Add a new `rateLimiting` key to the configuration array.

```php
// In config/security.php

return [
    // ... existing configuration ...
    'security-headers' => [
        // ... existing headers ...
    ],

    /*
    |--------------------------------------------------------------------------
    | Rate Limiting
    |--------------------------------------------------------------------------
    |
    | Here you may configure the `rateLimiting` settings for your application.
    | You can define different limiters for various parts of your
    | application, such as the API, web routes, or specific actions
    | like login attempts and password resets.
    |
    */
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
];
```

## 2. Service Provider Integration

Next, we will configure Laravel's `RateLimiter` in the service provider. This will create the named limiters based on the configuration file. This approach avoids creating a redundant middleware class and uses the framework as intended.

**File:** `src/SecurityServiceProvider.php`

**Action:** In the `boot` method, read the configuration and define the limiters.

```php
// In src/SecurityServiceProvider.php

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Http\Request;

// ... inside the boot() method

public function boot(Kernel $kernel): void
{
    // ... existing boot logic ...
    $this->bootRateLimiting();
}

/**
 * Boots the rate limiting services.
 *
 * Configures the named rate limiters based on the package's configuration file.
 *
 * @return void
 */
protected function bootRateLimiting(): void
{
    if (!config('artisanpack.security.rateLimiting.enabled')) {
        return;
    }

    $limiters = config('artisanpack.security.rateLimiting.limiters', []);

    foreach ($limiters as $name => $config) {
        $maxAttempts = $config['maxAttempts'] ?? 60;
        $decayMinutes = $config['decayMinutes'] ?? 1;

        RateLimiter::for($name, function (Request $request) use ($maxAttempts, $decayMinutes) {
            $key = optional($request->user())->id ?: $request->ip();
            return Limit::perMinutes($decayMinutes, $maxAttempts)->by($key);
        });
    }
}
```

## 3. Artisan Command

An Artisan command is needed to allow administrators to manually clear rate limits for a specific IP address or user.

**Location:** `src/Console/Commands/`
**New File:** `ClearRateLimits.php`

**Action:** Create the new Artisan command file.

```php
// In src/Console/Commands/ClearRateLimits.php

namespace ArtisanPackUI\Security\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\RateLimiter;

class ClearRateLimits extends Command
{
    protected $signature = 'security:rate-limit:clear {--ip=} {--user=}';
    protected $description = 'Clear the rate limiter cache for a given IP address or user ID';

    public function handle(): int
    {
        $ip = $this->option('ip');
        $user = $this->option('user');

        if (!$ip && !$user) {
            $this->error('You must provide either an --ip or a --user option.');
            return 1;
        }

        if ($ip) {
            RateLimiter::clear($ip);
            $this->info("Cleared rate limit for IP: {$ip}");
        }

        if ($user) {
            RateLimiter::clear($user);
            $this->info("Cleared rate limit for User ID: {$user}");
        }

        return 0;
    }
}
```

**Action:** Register the command in `src/SecurityServiceProvider.php`.

```php
// In src/SecurityServiceProvider.php, inside boot() method's runningInConsole() block:
use ArtisanPackUI\Security\Console\Commands\ClearRateLimits;
// ...
$this->commands([
    CheckSessionSecurity::class,
    ClearRateLimits::class, // Add this line
]);
```

## 4. Testing

A feature test is required to validate that the rate limiters work as expected.

**Location:** `tests/Feature/`
**New File:** `RateLimitingTest.php`

**Action:** Create a new test file that defines a temporary route and tests the configured limiters.

```php
// In tests/Feature/RateLimitingTest.php

namespace Tests\Feature;

use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Config;
use Tests\TestCase;

class RateLimitingTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Enable rate limiting and define a test route with a limiter
        Config::set('artisanpack.security.rateLimiting.enabled', true);
        Config::set('artisanpack.security.rateLimiting.limiters.test', [
            'maxAttempts' => 3,
            'decayMinutes' => 1,
        ]);

        // Manually boot the provider to register our test limiter
        $this->app->register(\ArtisanPackUI\Security\SecurityServiceProvider::class);

        Route::get('/_test/rate-limited-route', function () {
            return 'Success';
        })->middleware('throttle:test');
    }

    /** @test */
    public function it_rate_limits_requests_from_the_same_ip()
    {
        $response = null;
        for ($i = 0; $i < 3; $i++) {
            $response = $this->get('/_test/rate-limited-route');
            $response->assertStatus(200);
        }

        // The 4th request should be throttled
        $response = $this->get('/_test/rate-limited-route');
        $response->assertStatus(429); // Too Many Requests
    }

    /** @test */
    public function it_rate_limits_requests_for_an_authenticated_user()
    {
        $user = new User();
        $user->id = 1;
        $this->actingAs($user);

        $response = null;
        for ($i = 0; $i < 3; $i++) {
            $response = $this->get('/_test/rate-limited-route');
            $response->assertStatus(200);
        }

        // The 4th request should be throttled
        $response = $this->get('/_test/rate-limited-route');
        $response->assertStatus(429);
    }
}

```

## 5. Documentation

Finally, create a documentation file explaining how to configure and use the new rate-limiting feature.

**Location:** `docs/`
**New File:** `rate-limiting.md`

**Action:** Create the markdown file with instructions.

````markdown
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
````