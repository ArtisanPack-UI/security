# API Security Layer Implementation Plan

This document outlines the plan to implement a comprehensive API Security Layer using Laravel Sanctum with token management and API-specific protection.

## Overview

The API Security Layer will provide:
- Laravel Sanctum integration with configurable token management
- API-specific authentication guards
- Token-based authentication with scopes/abilities
- API rate limiting configuration
- Security middleware stack for API routes
- Artisan commands for token lifecycle management
- Testing utilities for API security

---

## How It Works With Laravel Sanctum

### Sanctum Provides the Foundation

Laravel Sanctum is the underlying authentication system. It provides:

| Sanctum Feature | What It Does |
|-----------------|--------------|
| `HasApiTokens` trait | Adds `createToken()`, `tokens()` relationship to User model |
| `personal_access_tokens` table | Stores hashed tokens with abilities |
| `auth:sanctum` guard | Authenticates requests via Bearer token |
| Token abilities | Basic scope checking with `tokenCan()` |

### Our Package Extends It

Our API Security Layer **wraps and extends** Sanctum rather than replacing it:

```
┌─────────────────────────────────────────────────────────────┐
│                  Your Application                            │
├─────────────────────────────────────────────────────────────┤
│            ArtisanPack API Security Layer                    │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  - Token expiration & revocation                     │    │
│  │  - Ability groups (readonly, admin, etc.)            │    │
│  │  - API-specific rate limiting                        │    │
│  │  - Artisan commands for token management             │    │
│  │  - Audit logging & metadata                          │    │
│  │  - Testing utilities                                 │    │
│  └─────────────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────┤
│                   Laravel Sanctum                            │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  - Token hashing & storage                           │    │
│  │  - auth:sanctum guard                                │    │
│  │  - Basic token abilities                             │    │
│  │  - Request authentication                            │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### Specific Integration Points

**1. Custom Token Model**

Sanctum allows swapping its token model. We register our extended model:

```php
// In SecurityServiceProvider::configureSanctum()
Sanctum::usePersonalAccessTokenModel(ApiToken::class);
```

Our `ApiToken` model extends Sanctum's `PersonalAccessToken`:

```php
use Laravel\Sanctum\PersonalAccessToken;

class ApiToken extends PersonalAccessToken
{
    // Adds: expires_at, is_revoked, metadata, scopes, etc.
}
```

**2. Extended Trait**

Our `HasApiTokens` trait uses Sanctum's trait internally:

```php
trait HasApiTokens
{
    use \Laravel\Sanctum\HasApiTokens; // Sanctum's trait

    // We add on top:
    public function createApiToken(string $name, array $abilities, ?int $expiresInMinutes): NewAccessToken
    {
        // Creates token using Sanctum's method
        $token = $this->createToken($name, $abilities);

        // Then adds our extensions (expiration, metadata)
        $token->accessToken->update([
            'expires_at' => $expiresInMinutes ? now()->addMinutes($expiresInMinutes) : null,
            'ip_address' => request()->ip(),
        ]);

        return $token;
    }
}
```

**3. Authentication Flow**

The authentication still uses Sanctum's guard - we just add validation layers:

```
Request with Bearer Token
         │
         ▼
┌─────────────────────┐
│   auth:sanctum      │  ◄── Sanctum validates token hash
│   (Sanctum Guard)   │
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│   api.security      │  ◄── Our middleware checks expiration/revocation
│   (Our Middleware)  │
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│   token.ability     │  ◄── Our middleware checks abilities
│   (Our Middleware)  │
└─────────────────────┘
         │
         ▼
    Controller
```

**4. Route Protection Example**

```php
// Standard Sanctum (still works)
Route::middleware('auth:sanctum')->get('/user', fn() => auth()->user());

// With our extensions
Route::middleware(['auth:sanctum', 'api.security', 'token.ability:write'])
    ->post('/posts', [PostController::class, 'store']);
```

**5. What Sanctum Handles vs. What We Handle**

| Concern | Handled By |
|---------|------------|
| Token hashing/storage | Sanctum |
| Request authentication | Sanctum (`auth:sanctum`) |
| Basic `tokenCan()` check | Sanctum |
| Token expiration | **Our package** |
| Token revocation tracking | **Our package** |
| Ability groups | **Our package** |
| API rate limiting | **Our package** |
| Token management commands | **Our package** |
| Audit logging | **Our package** |

### Sanctum as a Dependency

Sanctum is a **suggested** dependency, not required:

```json
// composer.json
{
    "suggest": {
        "laravel/sanctum": "Required for API Security Layer features (^4.0)"
    }
}
```

The feature gracefully degrades if Sanctum isn't installed:

```php
protected function bootApiSecurity(): void
{
    if (! config('artisanpack.security.api.enabled')) {
        return;
    }

    // Check if Sanctum is installed
    if (! class_exists(\Laravel\Sanctum\Sanctum::class)) {
        if ($this->app->runningInConsole()) {
            $this->app['log']->warning(
                'API Security Layer requires Laravel Sanctum. Install with: composer require laravel/sanctum'
            );
        }
        return;
    }

    // Continue with setup...
}
```

### Why Extend Rather Than Replace?

1. **Sanctum is battle-tested** - No need to reinvent token hashing, guard logic
2. **Ecosystem compatibility** - Works with existing Sanctum tutorials, packages
3. **Laravel standards** - Follows patterns Laravel developers expect
4. **Upgradability** - Sanctum updates automatically benefit our package
5. **Simplicity** - Users familiar with Sanctum can adopt easily

---

## 1. Configuration Structure

**Status:** Not started

Add a new `api` configuration section to `config/security.php`:

```php
'api' => [
    'enabled' => env('SECURITY_API_ENABLED', true),

    /*
     * Authentication driver configuration.
     * Sanctum is the default and recommended driver.
     */
    'driver' => 'sanctum',

    /*
     * Token configuration for Sanctum.
     */
    'tokens' => [
        /*
         * Default token expiration in minutes.
         * Set to null for non-expiring tokens.
         */
        'expiration' => env('API_TOKEN_EXPIRATION', 60 * 24 * 7), // 7 days

        /*
         * Prefix for token names to identify tokens created by this package.
         */
        'prefix' => env('API_TOKEN_PREFIX', 'artisanpack'),

        /*
         * Whether to hash tokens before storage.
         * Sanctum does this by default; this controls display behavior.
         */
        'hash' => true,
    ],

    /*
     * Define available token abilities/scopes.
     * These can be assigned when creating tokens.
     */
    'abilities' => [
        'read' => 'Read-only access to resources',
        'write' => 'Create and update resources',
        'delete' => 'Delete resources',
        'admin' => 'Full administrative access',
    ],

    /*
     * Ability groups for convenience.
     * Assign a group name to get all included abilities.
     */
    'ability_groups' => [
        'readonly' => ['read'],
        'standard' => ['read', 'write'],
        'full' => ['read', 'write', 'delete'],
        'admin' => ['read', 'write', 'delete', 'admin'],
    ],

    /*
     * API-specific rate limiting configuration.
     * These override the general rate limiting settings for API routes.
     */
    'rate_limiting' => [
        'enabled' => env('API_RATE_LIMITING_ENABLED', true),

        /*
         * Default rate limit for authenticated API requests.
         */
        'authenticated' => [
            'max_attempts' => env('API_RATE_LIMIT_AUTHENTICATED', 60),
            'decay_minutes' => 1,
        ],

        /*
         * Rate limit for unauthenticated/guest API requests.
         */
        'guest' => [
            'max_attempts' => env('API_RATE_LIMIT_GUEST', 30),
            'decay_minutes' => 1,
        ],

        /*
         * Rate limit for token creation/authentication endpoints.
         */
        'token_requests' => [
            'max_attempts' => env('API_RATE_LIMIT_TOKEN', 5),
            'decay_minutes' => 1,
        ],
    ],

    /*
     * Security middleware applied to API routes.
     */
    'middleware' => [
        'throttle:api',
        'api.security',
    ],

    /*
     * Routes configuration for token management endpoints.
     * Set to null to disable built-in routes.
     */
    'routes' => [
        'enabled' => env('API_ROUTES_ENABLED', false),
        'prefix' => 'api/auth',
        'middleware' => ['api'],
    ],
],
```

---

## 2. Database Migrations

**Status:** Not started

### Token Metadata Table

Create a migration to extend Sanctum's `personal_access_tokens` table with additional metadata:

**File:** `database/migrations/2025_XX_XX_XXXXXX_add_metadata_to_personal_access_tokens_table.php`

```php
Schema::table('personal_access_tokens', function (Blueprint $table) {
    $table->timestamp('expires_at')->nullable()->after('last_used_at');
    $table->string('ip_address', 45)->nullable()->after('expires_at');
    $table->text('user_agent')->nullable()->after('ip_address');
    $table->json('metadata')->nullable()->after('user_agent');
    $table->boolean('is_revoked')->default(false)->after('metadata');
    $table->timestamp('revoked_at')->nullable()->after('is_revoked');

    $table->index(['tokenable_type', 'tokenable_id', 'is_revoked']);
    $table->index('expires_at');
});
```

### API Audit Log Table (Optional)

**File:** `database/migrations/2025_XX_XX_XXXXXX_create_api_access_logs_table.php`

```php
Schema::create('api_access_logs', function (Blueprint $table) {
    $table->id();
    $table->foreignId('token_id')->nullable()->constrained('personal_access_tokens')->nullOnDelete();
    $table->nullableMorphs('user');
    $table->string('method', 10);
    $table->text('path');
    $table->string('ip_address', 45);
    $table->integer('response_status');
    $table->integer('response_time_ms')->nullable();
    $table->timestamp('created_at');

    $table->index(['token_id', 'created_at']);
    $table->index(['user_type', 'user_id', 'created_at']);
});
```

---

## 3. Trait: HasApiTokens

**Status:** Not started

**File:** `src/Concerns/HasApiTokens.php`

This trait extends Laravel Sanctum's `HasApiTokens` trait with additional functionality:

```php
<?php

namespace ArtisanPackUI\Security\Concerns;

use Laravel\Sanctum\HasApiTokens as SanctumHasApiTokens;
use Laravel\Sanctum\NewAccessToken;
use Illuminate\Support\Collection;

trait HasApiTokens
{
    use SanctumHasApiTokens;

    /**
     * Create a new API token with expiration and metadata.
     */
    public function createApiToken(
        string $name,
        array $abilities = ['*'],
        ?int $expiresInMinutes = null,
        array $metadata = []
    ): NewAccessToken;

    /**
     * Create a token using an ability group name.
     */
    public function createApiTokenWithGroup(
        string $name,
        string $group,
        ?int $expiresInMinutes = null
    ): NewAccessToken;

    /**
     * Get all active (non-expired, non-revoked) tokens.
     */
    public function activeTokens(): Collection;

    /**
     * Revoke a specific token by ID.
     */
    public function revokeToken(int $tokenId): bool;

    /**
     * Revoke all tokens for this user.
     */
    public function revokeAllTokens(): int;

    /**
     * Revoke all tokens except the current one.
     */
    public function revokeOtherTokens(): int;

    /**
     * Check if user has any active tokens.
     */
    public function hasActiveTokens(): bool;

    /**
     * Prune expired tokens for this user.
     */
    public function pruneExpiredTokens(): int;

    /**
     * Get token usage statistics.
     */
    public function tokenUsageStats(): array;
}
```

---

## 4. Models

**Status:** Not started

### Extended PersonalAccessToken Model

**File:** `src/Models/ApiToken.php`

Extends Sanctum's `PersonalAccessToken` model with additional functionality:

```php
<?php

namespace ArtisanPackUI\Security\Models;

use Laravel\Sanctum\PersonalAccessToken;
use Illuminate\Database\Eloquent\Builder;

class ApiToken extends PersonalAccessToken
{
    protected $casts = [
        'abilities' => 'array',
        'metadata' => 'array',
        'last_used_at' => 'datetime',
        'expires_at' => 'datetime',
        'revoked_at' => 'datetime',
        'is_revoked' => 'boolean',
    ];

    /**
     * Scope to only active tokens.
     */
    public function scopeActive(Builder $query): Builder;

    /**
     * Scope to expired tokens.
     */
    public function scopeExpired(Builder $query): Builder;

    /**
     * Scope to revoked tokens.
     */
    public function scopeRevoked(Builder $query): Builder;

    /**
     * Check if token is expired.
     */
    public function isExpired(): bool;

    /**
     * Check if token is valid (not expired and not revoked).
     */
    public function isValid(): bool;

    /**
     * Revoke this token.
     */
    public function revoke(): bool;

    /**
     * Check if token has a specific ability.
     */
    public function hasAbility(string $ability): bool;

    /**
     * Get human-readable expiration status.
     */
    public function getExpirationStatusAttribute(): string;
}
```

### API Access Log Model (Optional)

**File:** `src/Models/ApiAccessLog.php`

```php
<?php

namespace ArtisanPackUI\Security\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\MorphTo;

class ApiAccessLog extends Model
{
    public $timestamps = false;

    protected $fillable = [
        'token_id',
        'user_type',
        'user_id',
        'method',
        'path',
        'ip_address',
        'response_status',
        'response_time_ms',
        'created_at',
    ];

    public function token(): BelongsTo;
    public function user(): MorphTo;
}
```

---

## 5. Middleware

**Status:** Not started

### API Security Middleware

**File:** `src/Http/Middleware/ApiSecurity.php`

Composite middleware that applies API-specific security measures:

```php
<?php

namespace ArtisanPackUI\Security\Http\Middleware;

class ApiSecurity
{
    /**
     * Handle an incoming API request.
     *
     * - Validates token expiration
     * - Checks token revocation status
     * - Records token usage (last_used_at, IP, user agent)
     * - Applies API-specific security headers
     */
    public function handle(Request $request, Closure $next): Response;
}
```

### API Token Ability Middleware

**File:** `src/Http/Middleware/CheckTokenAbility.php`

```php
<?php

namespace ArtisanPackUI\Security\Http\Middleware;

class CheckTokenAbility
{
    /**
     * Check if the current token has the required ability.
     *
     * Usage: ->middleware('token.ability:write')
     *        ->middleware('token.ability:read,write') // requires all
     */
    public function handle(Request $request, Closure $next, ...$abilities): Response;
}
```

### API Token Ability (Any) Middleware

**File:** `src/Http/Middleware/CheckTokenAbilityAny.php`

```php
<?php

namespace ArtisanPackUI\Security\Http\Middleware;

class CheckTokenAbilityAny
{
    /**
     * Check if the current token has any of the required abilities.
     *
     * Usage: ->middleware('token.ability.any:write,admin')
     */
    public function handle(Request $request, Closure $next, ...$abilities): Response;
}
```

### API Rate Limiting Middleware

**File:** `src/Http/Middleware/ApiRateLimiting.php`

```php
<?php

namespace ArtisanPackUI\Security\Http\Middleware;

class ApiRateLimiting
{
    /**
     * Apply API-specific rate limiting based on authentication status.
     *
     * - Authenticated users: higher limits, keyed by user ID + token ID
     * - Guest users: lower limits, keyed by IP address
     */
    public function handle(Request $request, Closure $next): Response;
}
```

---

## 6. Artisan Commands

**Status:** Not started

### Token Creation Command

**File:** `src/Console/Commands/CreateApiToken.php`

```bash
php artisan api:token:create {user} {--name=} {--abilities=*} {--expires=} {--group=}

# Examples:
php artisan api:token:create 1 --name="CI/CD Token" --abilities=read --abilities=write
php artisan api:token:create user@example.com --group=admin --expires=30
php artisan api:token:create 1 --name="Read Only" --group=readonly
```

### Token List Command

**File:** `src/Console/Commands/ListApiTokens.php`

```bash
php artisan api:token:list {user?} {--expired} {--revoked} {--active}

# Examples:
php artisan api:token:list                    # List all tokens
php artisan api:token:list 1                  # List tokens for user ID 1
php artisan api:token:list --active           # List only active tokens
php artisan api:token:list --expired          # List expired tokens
```

### Token Revoke Command

**File:** `src/Console/Commands/RevokeApiToken.php`

```bash
php artisan api:token:revoke {token_id} {--user=} {--all} {--expired}

# Examples:
php artisan api:token:revoke 123              # Revoke specific token
php artisan api:token:revoke --user=1 --all   # Revoke all tokens for user
php artisan api:token:revoke --expired        # Revoke all expired tokens
```

### Token Prune Command

**File:** `src/Console/Commands/PruneApiTokens.php`

```bash
php artisan api:token:prune {--days=30} {--revoked} {--expired}

# Examples:
php artisan api:token:prune --days=7          # Delete tokens unused for 7 days
php artisan api:token:prune --expired         # Delete all expired tokens
php artisan api:token:prune --revoked         # Delete all revoked tokens
```

### API Security Check Command

**File:** `src/Console/Commands/CheckApiSecurity.php`

```bash
php artisan api:security:check

# Validates:
# - Sanctum is properly installed
# - Token expiration is configured
# - Rate limiting is enabled
# - HTTPS is enforced in production
```

---

## 7. Service Integration

**Status:** Not started

### Update SecurityServiceProvider

Add new `bootApiSecurity()` method:

```php
protected function bootApiSecurity(): void
{
    if (! config('artisanpack.security.api.enabled')) {
        return;
    }

    // Configure Sanctum
    $this->configureSanctum();

    // Register API rate limiters
    $this->registerApiRateLimiters();

    // Register middleware aliases
    $this->app['router']->aliasMiddleware('api.security', ApiSecurity::class);
    $this->app['router']->aliasMiddleware('token.ability', CheckTokenAbility::class);
    $this->app['router']->aliasMiddleware('token.ability.any', CheckTokenAbilityAny::class);
    $this->app['router']->aliasMiddleware('api.throttle', ApiRateLimiting::class);

    // Register console commands
    if ($this->app->runningInConsole()) {
        $this->commands([
            CreateApiToken::class,
            ListApiTokens::class,
            RevokeApiToken::class,
            PruneApiTokens::class,
            CheckApiSecurity::class,
        ]);
    }

    // Load migrations if enabled
    $this->loadMigrationsFrom(__DIR__ . '/../database/migrations/api');

    // Register optional routes
    if (config('artisanpack.security.api.routes.enabled')) {
        $this->loadRoutesFrom(__DIR__ . '/../routes/api.php');
    }
}

protected function configureSanctum(): void
{
    // Set custom token model
    Sanctum::usePersonalAccessTokenModel(ApiToken::class);

    // Configure token expiration
    $expiration = config('artisanpack.security.api.tokens.expiration');
    if ($expiration) {
        Sanctum::$personalAccessTokenExpiration = now()->addMinutes($expiration);
    }
}

protected function registerApiRateLimiters(): void
{
    if (! config('artisanpack.security.api.rate_limiting.enabled')) {
        return;
    }

    // Authenticated API limiter
    RateLimiter::for('api-authenticated', function (Request $request) {
        $config = config('artisanpack.security.api.rate_limiting.authenticated');
        return Limit::perMinutes($config['decay_minutes'], $config['max_attempts'])
            ->by($request->user()?->id ?: $request->ip());
    });

    // Guest API limiter
    RateLimiter::for('api-guest', function (Request $request) {
        $config = config('artisanpack.security.api.rate_limiting.guest');
        return Limit::perMinutes($config['decay_minutes'], $config['max_attempts'])
            ->by($request->ip());
    });

    // Token request limiter
    RateLimiter::for('api-token-request', function (Request $request) {
        $config = config('artisanpack.security.api.rate_limiting.token_requests');
        return Limit::perMinutes($config['decay_minutes'], $config['max_attempts'])
            ->by($request->ip());
    });
}
```

---

## 8. Testing Utilities

**Status:** Not started

### API Security Test Trait

**File:** `src/Testing/ApiSecurityAssertions.php`

```php
<?php

namespace ArtisanPackUI\Security\Testing;

trait ApiSecurityAssertions
{
    /**
     * Create an API token for testing.
     */
    protected function createTestToken(
        $user,
        array $abilities = ['*'],
        ?int $expiresInMinutes = null
    ): string;

    /**
     * Assert the response requires authentication.
     */
    protected function assertRequiresAuthentication($response): void;

    /**
     * Assert the response requires a specific token ability.
     */
    protected function assertRequiresAbility($response, string $ability): void;

    /**
     * Assert the request was rate limited.
     */
    protected function assertRateLimited($response): void;

    /**
     * Assert the token is valid and not expired.
     */
    protected function assertTokenValid(string $token): void;

    /**
     * Assert the token has specific abilities.
     */
    protected function assertTokenHasAbilities(string $token, array $abilities): void;

    /**
     * Act as a user with a specific API token.
     */
    protected function actingAsApiUser($user, array $abilities = ['*']): self;

    /**
     * Make an authenticated API request.
     */
    protected function apiAs($user, string $method, string $uri, array $data = []): TestResponse;
}
```

### Test Helpers

**File:** `src/Testing/ApiSecurityTestHelpers.php`

```php
<?php

namespace ArtisanPackUI\Security\Testing;

class ApiSecurityTestHelpers
{
    /**
     * Create a mock expired token for testing.
     */
    public static function createExpiredToken($user, array $abilities = ['*']): string;

    /**
     * Create a mock revoked token for testing.
     */
    public static function createRevokedToken($user, array $abilities = ['*']): string;

    /**
     * Simulate rate limit exhaustion.
     */
    public static function exhaustRateLimit(string $key, int $attempts): void;

    /**
     * Clear rate limits for testing.
     */
    public static function clearRateLimits(): void;
}
```

---

## 9. Optional API Routes

**Status:** Not started

**File:** `routes/api.php`

When `api.routes.enabled` is true, provide built-in token management endpoints:

```php
Route::prefix(config('artisanpack.security.api.routes.prefix'))
    ->middleware(config('artisanpack.security.api.routes.middleware'))
    ->group(function () {

        // Token management (requires authentication)
        Route::middleware('auth:sanctum')->group(function () {
            Route::get('/tokens', [ApiTokenController::class, 'index']);
            Route::post('/tokens', [ApiTokenController::class, 'store']);
            Route::delete('/tokens/{token}', [ApiTokenController::class, 'destroy']);
            Route::delete('/tokens', [ApiTokenController::class, 'destroyAll']);
            Route::get('/tokens/current', [ApiTokenController::class, 'current']);
        });

        // Token creation (with rate limiting)
        Route::middleware('throttle:api-token-request')
            ->post('/token', [ApiAuthController::class, 'createToken']);
    });
```

---

## 10. Documentation

**Status:** Not started

**File:** `docs/api-security.md`

### Documentation Sections:

1. **Overview**
   - What the API Security Layer provides
   - When to use it

2. **Installation & Configuration**
   - Enabling the feature
   - Configuration options
   - Environment variables

3. **Token Management**
   - Creating tokens programmatically
   - Token abilities and groups
   - Token expiration
   - Revoking tokens

4. **Middleware Usage**
   - Protecting routes with `api.security`
   - Checking abilities with `token.ability`
   - Rate limiting with `api.throttle`

5. **Artisan Commands**
   - Complete command reference
   - Examples and use cases

6. **Testing**
   - Using the test trait
   - Testing authenticated requests
   - Testing rate limiting

7. **Security Best Practices**
   - Token storage recommendations
   - Rotation strategies
   - Audit logging

---

## 11. Implementation Order

### Phase 1: Foundation
1. Add configuration to `config/security.php`
2. Create database migrations
3. Create `ApiToken` model
4. Create `HasApiTokens` trait

### Phase 2: Middleware & Protection
5. Create `ApiSecurity` middleware
6. Create `CheckTokenAbility` middleware
7. Create `CheckTokenAbilityAny` middleware
8. Create `ApiRateLimiting` middleware

### Phase 3: Service Integration
9. Update `SecurityServiceProvider` with `bootApiSecurity()`
10. Register middleware aliases
11. Register rate limiters

### Phase 4: Commands
12. Create `CreateApiToken` command
13. Create `ListApiTokens` command
14. Create `RevokeApiToken` command
15. Create `PruneApiTokens` command
16. Create `CheckApiSecurity` command

### Phase 5: Testing & Polish
17. Create `ApiSecurityAssertions` trait
18. Create feature tests for all functionality
19. Create unit tests for models and traits

### Phase 6: Documentation
20. Create `docs/api-security.md`
21. Update `docs/home.md` with links
22. Add examples and best practices

---

## 12. Dependencies

- **Laravel Sanctum** (`laravel/sanctum`): Required for token-based authentication
  - Should be listed as a suggested dependency in `composer.json`
  - Package should gracefully handle missing Sanctum installation

---

## 13. Considerations

### Backward Compatibility
- Feature is disabled by default (`'enabled' => false` or `env('SECURITY_API_ENABLED', true)`)
- Existing rate limiting configuration is preserved
- No breaking changes to existing functionality

### Performance
- Token abilities cached in memory during request lifecycle
- Rate limit checks use Laravel's optimized cache drivers
- Optional access logging can be disabled for high-traffic APIs

### Security
- Tokens are hashed before storage (Sanctum default)
- IP address and user agent recorded for audit
- Expired/revoked tokens rejected at middleware level
- Rate limiting prevents brute force attacks

### Extensibility
- Custom token abilities can be defined in config
- Ability groups provide convenient presets
- Custom middleware can extend base classes
- Model events allow hooking into token lifecycle
