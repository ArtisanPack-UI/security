# API Security Layer

The API Security Layer extends Laravel Sanctum with comprehensive token management, expiration, revocation tracking, and API-specific rate limiting.

## Requirements

- Laravel Sanctum (`composer require laravel/sanctum`)
- Sanctum's `personal_access_tokens` migration must be run

## Installation

### 1. Install Laravel Sanctum

If you haven't already, install Laravel Sanctum:

```bash
composer require laravel/sanctum
php artisan vendor:publish --provider="Laravel\Sanctum\SanctumServiceProvider"
php artisan migrate
```

### 2. Enable API Security

The API Security Layer is enabled by default. To disable it, set the environment variable:

```bash
SECURITY_API_ENABLED=false
```

Or in your configuration:

```php
// config/artisanpack/security.php
'api' => [
    'enabled' => false,
],
```

### 3. Add the Trait to Your User Model

```php
use ArtisanPackUI\Security\Concerns\HasApiTokens;

class User extends Authenticatable
{
    use HasApiTokens;

    // ...
}
```

### 4. Run Migrations

The package will automatically add additional columns to the `personal_access_tokens` table for expiration and revocation tracking.

## Configuration

The full configuration options are available in `config/artisanpack/security.php` under the `api` key:

```php
'api' => [
    'enabled' => env('SECURITY_API_ENABLED', true),
    'driver' => 'sanctum',

    'tokens' => [
        'expiration' => env('API_TOKEN_EXPIRATION', 60 * 24 * 7), // 7 days
        'prefix' => env('API_TOKEN_PREFIX', 'artisanpack'),
    ],

    'abilities' => [
        'read' => 'Read-only access to resources',
        'write' => 'Create and update resources',
        'delete' => 'Delete resources',
        'admin' => 'Full administrative access',
    ],

    'ability_groups' => [
        'readonly' => ['read'],
        'standard' => ['read', 'write'],
        'full' => ['read', 'write', 'delete'],
        'admin' => ['read', 'write', 'delete', 'admin'],
    ],

    'rate_limiting' => [
        'enabled' => env('API_RATE_LIMITING_ENABLED', true),
        'authenticated' => [
            'max_attempts' => env('API_RATE_LIMIT_AUTHENTICATED', 60),
            'decay_minutes' => 1,
        ],
        'guest' => [
            'max_attempts' => env('API_RATE_LIMIT_GUEST', 30),
            'decay_minutes' => 1,
        ],
        'token_requests' => [
            'max_attempts' => env('API_RATE_LIMIT_TOKEN', 5),
            'decay_minutes' => 1,
        ],
    ],
],
```

## Token Management

### Creating Tokens Programmatically

```php
// Create a token with default expiration
$token = $user->createApiToken('my-app-token');
echo $token->plainTextToken; // Use this for API authentication

// Create a token with specific abilities
$token = $user->createApiToken('read-only-token', ['read']);

// Create a token with custom expiration (30 days)
$token = $user->createApiToken('long-lived-token', ['*'], 60 * 24 * 30);

// Create a token with metadata
$token = $user->createApiToken('service-token', ['*'], null, [
    'service' => 'ci-cd',
    'environment' => 'production',
]);

// Create a token using an ability group
$token = $user->createApiTokenWithGroup('admin-token', 'admin');
```

### Managing Tokens

```php
// Get all active tokens for a user
$tokens = $user->activeApiTokens();

// Get all tokens (including expired and revoked)
$tokens = $user->allApiTokens();

// Revoke a specific token
$user->revokeApiToken($tokenId);

// Revoke all tokens
$user->revokeAllApiTokens();

// Revoke all tokens except the current one
$user->revokeOtherApiTokens();

// Delete expired tokens
$user->pruneExpiredApiTokens();

// Delete revoked tokens
$user->pruneRevokedApiTokens();

// Get token statistics
$stats = $user->apiTokenStats();
// Returns: ['total' => 5, 'active' => 3, 'expired' => 1, 'revoked' => 1, ...]
```

### Token Model Methods

```php
$token = ApiToken::find($id);

// Check status
$token->isValid();    // Not expired and not revoked
$token->isExpired();  // Past expiration date
$token->is_revoked;   // Has been revoked

// Revoke the token
$token->revoke();

// Check abilities
$token->hasAbility('read');
$token->hasAllAbilities(['read', 'write']);
$token->hasAnyAbility(['admin', 'write']);

// Get human-readable status
$token->expiration_status; // "Active", "Expired 2 hours ago", "Revoked", etc.

// Metadata
$token->getMetadata('service');
$token->setMetadata('last_sync', now());
```

## Middleware

### API Security Middleware

Validates token expiration/revocation and records usage:

```php
Route::middleware(['auth:sanctum', 'api.security'])->group(function () {
    Route::get('/user', fn() => auth()->user());
});
```

### Token Ability Middleware

Check if the token has ALL required abilities:

```php
// Requires the 'write' ability
Route::middleware(['auth:sanctum', 'token.ability:write'])
    ->post('/posts', [PostController::class, 'store']);

// Requires BOTH 'read' and 'write' abilities
Route::middleware(['auth:sanctum', 'token.ability:read,write'])
    ->put('/posts/{id}', [PostController::class, 'update']);
```

### Token Ability Any Middleware

Check if the token has ANY of the required abilities:

```php
// Requires either 'admin' OR 'moderator' ability
Route::middleware(['auth:sanctum', 'token.ability.any:admin,moderator'])
    ->delete('/posts/{id}', [PostController::class, 'destroy']);
```

### API Rate Limiting Middleware

Applies API-specific rate limits based on authentication status:

```php
Route::middleware(['api.throttle'])->group(function () {
    // Authenticated users: 60 requests/minute
    // Guest users: 30 requests/minute
});
```

### Combining Middleware

```php
Route::middleware([
    'auth:sanctum',
    'api.security',
    'api.throttle',
    'token.ability:write',
])->group(function () {
    Route::post('/posts', [PostController::class, 'store']);
    Route::put('/posts/{id}', [PostController::class, 'update']);
});
```

## Artisan Commands

### Create a Token

```bash
# Create a token for user ID 1
php artisan api:token:create 1 --name="My Token"

# Create a token for user by email
php artisan api:token:create user@example.com --name="Service Token"

# Create a token with specific abilities
php artisan api:token:create 1 --name="Read Only" --abilities=read

# Create a token with multiple abilities
php artisan api:token:create 1 --name="Editor" --abilities=read --abilities=write

# Create a token using an ability group
php artisan api:token:create 1 --name="Admin Token" --group=admin

# Create a token with custom expiration (30 days)
php artisan api:token:create 1 --name="Long Token" --expires=43200
```

### List Tokens

```bash
# List all tokens
php artisan api:token:list

# List tokens for a specific user
php artisan api:token:list 1
php artisan api:token:list user@example.com

# List only active tokens
php artisan api:token:list --active

# List only expired tokens
php artisan api:token:list --expired

# List only revoked tokens
php artisan api:token:list --revoked
```

### Revoke Tokens

```bash
# Revoke a specific token by ID
php artisan api:token:revoke 123

# Revoke all tokens for a user
php artisan api:token:revoke --user=1 --all

# Revoke all expired tokens
php artisan api:token:revoke --expired

# Skip confirmation
php artisan api:token:revoke --expired --force
```

### Prune (Delete) Tokens

```bash
# Delete tokens unused for 30 days (default)
php artisan api:token:prune

# Delete tokens unused for 7 days
php artisan api:token:prune --days=7

# Delete all expired tokens
php artisan api:token:prune --expired

# Delete all revoked tokens
php artisan api:token:prune --revoked

# Skip confirmation
php artisan api:token:prune --expired --force
```

### Check Security Configuration

```bash
php artisan api:security:check
```

This command validates:
- Sanctum is installed
- Token expiration is configured
- Rate limiting is enabled
- HTTPS in production

## Testing

### Using the Test Trait

```php
use ArtisanPackUI\Security\Testing\ApiSecurityAssertions;

class ApiTest extends TestCase
{
    use ApiSecurityAssertions;

    public function test_authenticated_user_can_access_api()
    {
        $user = User::factory()->create();

        $response = $this->apiAs($user, 'GET', '/api/user');

        $response->assertOk();
    }

    public function test_unauthenticated_request_returns_401()
    {
        $response = $this->getJson('/api/user');

        $this->assertRequiresAuthentication($response);
    }

    public function test_token_without_ability_returns_403()
    {
        $user = User::factory()->create();

        $response = $this->apiAs($user, 'POST', '/api/posts', [], ['read']);

        $this->assertRequiresAbility($response);
    }

    public function test_expired_token_is_rejected()
    {
        $user = User::factory()->create();
        $token = $this->createExpiredTestApiToken($user);

        $response = $this->apiWithToken($token, 'GET', '/api/user');

        $response->assertStatus(401);
    }
}
```

### Available Test Methods

```php
// Create tokens
$token = $this->createTestApiToken($user, ['read', 'write']);
$token = $this->createExpiredTestApiToken($user);
$token = $this->createRevokedTestApiToken($user);

// Make authenticated requests
$response = $this->apiAs($user, 'GET', '/api/endpoint');
$response = $this->apiWithToken($token, 'POST', '/api/endpoint', $data);

// Assertions
$this->assertRequiresAuthentication($response);
$this->assertRequiresAbility($response);
$this->assertRateLimited($response);
$this->assertTokenValid($token);
$this->assertTokenRevoked($token);
$this->assertTokenExpired($token);
$this->assertTokenHasAbilities($token, ['read', 'write']);
```

## Security Best Practices

### Token Storage

- Never store tokens in plain text on the client
- Use secure storage mechanisms (Keychain, encrypted storage)
- Don't log tokens or include them in error messages

### Token Rotation

Implement regular token rotation for long-lived integrations:

```php
// Rotate token: create new, revoke old
$newToken = $user->createApiToken('service-token', $oldToken->abilities);
$oldToken->revoke();
```

### Expiration Strategy

- Use short-lived tokens for user-facing applications
- Use longer expiration for service-to-service communication
- Consider implementing refresh tokens for mobile apps

### Ability Scoping

- Follow the principle of least privilege
- Create specific abilities for specific actions
- Use ability groups for common permission sets

### Rate Limiting

- Always enable rate limiting in production
- Use stricter limits for authentication endpoints
- Consider implementing per-endpoint rate limits

## How It Integrates with Sanctum

This package extends Laravel Sanctum rather than replacing it:

1. **Custom Token Model**: Our `ApiToken` model extends Sanctum's `PersonalAccessToken`
2. **Extended Trait**: `HasApiTokens` wraps Sanctum's trait with additional methods
3. **Authentication Flow**: Uses Sanctum's `auth:sanctum` guard, then adds our middleware
4. **Full Compatibility**: Standard Sanctum usage still works

```
Request with Bearer Token
         │
         ▼
┌─────────────────────┐
│   auth:sanctum      │  ◄── Sanctum validates token
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│   api.security      │  ◄── Our middleware checks expiration/revocation
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│   token.ability     │  ◄── Our middleware checks abilities
└─────────────────────┘
         │
         ▼
    Controller
```
