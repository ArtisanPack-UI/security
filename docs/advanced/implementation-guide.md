---
title: Security Implementation Guide
---

# Security Implementation Guide

This guide walks you through implementing the security features in the ArtisanPack UI Security package. Follow these steps to secure your Laravel application with comprehensive protection against common vulnerabilities.

## Quick Start Checklist

Before diving into specific features, ensure your base setup is complete:

- [ ] Install the package via Composer
- [ ] Publish configuration files
- [ ] Run database migrations
- [ ] Add required traits to your User model
- [ ] Register middleware in your application
- [ ] Configure environment variables

## Installation

### Step 1: Install the Package

```bash
composer require artisanpackui/security
```

### Step 2: Publish Configuration

```bash
php artisan vendor:publish --provider="ArtisanPackUI\Security\SecurityServiceProvider"
```

This publishes the configuration file to `config/artisanpack/security.php`.

### Step 3: Run Migrations

```bash
php artisan migrate
```

### Step 4: Configure Your User Model

Add the required traits to your User model based on the features you want to use:

```php
<?php

namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use ArtisanPackUI\Security\TwoFactor\TwoFactorAuthenticatable;
use ArtisanPackUI\Security\Concerns\HasRoles;
use ArtisanPackUI\Security\Concerns\HasApiTokens;
use ArtisanPackUI\Security\Concerns\HasPasswordHistory;
use ArtisanPackUI\Security\Concerns\HasDevices;
use ArtisanPackUI\Security\Concerns\HasAdvancedSessions;
use ArtisanPackUI\Security\Concerns\HasSecureFiles;
use ArtisanPackUI\Security\Concerns\HasSocialIdentities;
use ArtisanPackUI\Security\Concerns\HasSsoIdentities;
use ArtisanPackUI\Security\Concerns\HasWebAuthnCredentials;

class User extends Authenticatable
{
    // Core security features
    use TwoFactorAuthenticatable;  // Two-factor authentication
    use HasRoles;                   // Role-based access control
    use HasApiTokens;               // API token management
    use HasPasswordHistory;         // Password history tracking

    // Advanced authentication
    use HasDevices;                 // Device management
    use HasAdvancedSessions;        // Session management
    use HasSocialIdentities;        // Social login
    use HasSsoIdentities;           // SSO authentication
    use HasWebAuthnCredentials;     // WebAuthn/Passkeys

    // File security
    use HasSecureFiles;             // Secure file associations
}
```

### Step 5: Register Middleware

Add the security middleware to your `app/Http/Kernel.php` or route files:

```php
// In app/Http/Kernel.php
protected $middlewareAliases = [
    // ... existing middleware

    // Security headers
    'security.headers' => \ArtisanPackUI\Security\Http\Middleware\SecurityHeadersMiddleware::class,
    'csp' => \ArtisanPackUI\Security\Http\Middleware\ContentSecurityPolicy::class,

    // Authentication
    'two-factor' => \ArtisanPackUI\Security\Http\Middleware\TwoFactorMiddleware::class,
    'step-up' => \ArtisanPackUI\Security\Http\Middleware\StepUpAuthentication::class,

    // Authorization
    'permission' => \ArtisanPackUI\Security\Http\Middleware\CheckPermission::class,
    'token.ability' => \ArtisanPackUI\Security\Http\Middleware\CheckTokenAbility::class,
    'token.ability.any' => \ArtisanPackUI\Security\Http\Middleware\CheckTokenAbilityAny::class,

    // Session security
    'session.encrypted' => \ArtisanPackUI\Security\Http\Middleware\EnsureSessionIsEncrypted::class,
    'session.binding' => \ArtisanPackUI\Security\Http\Middleware\EnforceSessionBinding::class,

    // Account protection
    'lockout' => \ArtisanPackUI\Security\Http\Middleware\CheckAccountLockout::class,
    'password.change' => \ArtisanPackUI\Security\Http\Middleware\RequirePasswordChange::class,
    'password.policy' => \ArtisanPackUI\Security\Http\Middleware\EnforcePasswordPolicy::class,
    'device.trusted' => \ArtisanPackUI\Security\Http\Middleware\RequireTrustedDevice::class,

    // API security
    'api.security' => \ArtisanPackUI\Security\Http\Middleware\ApiSecurity::class,
    'api.throttle' => \ArtisanPackUI\Security\Http\Middleware\ApiRateLimiting::class,

    // File security
    'upload.scan' => \ArtisanPackUI\Security\Http\Middleware\ScanUploadedFiles::class,
    'upload.validate' => \ArtisanPackUI\Security\Http\Middleware\ValidateFileUpload::class,

    // Protection
    'xss' => \ArtisanPackUI\Security\Http\Middleware\XssProtection::class,
    'suspicious' => \ArtisanPackUI\Security\Http\Middleware\DetectSuspiciousActivity::class,
];
```

## Implementation by Feature

### 1. Basic Security (Sanitization & Escaping)

The package provides helper functions for sanitizing input and escaping output.

#### Sanitizing User Input

```php
// Using helper functions
$email = sanitizeEmail($request->input('email'));
$text = sanitizeText($request->input('name'));
$integer = sanitizeInt($request->input('age'));
$url = sanitizeUrl($request->input('website'));
$filename = sanitizeFilename($file->getClientOriginalName());

// Sanitize arrays recursively
$data = sanitizeArray($request->all());

// Using the Security facade
use ArtisanPackUI\Security\Facades\Security;

$clean = Security::sanitizeText($userInput);
```

#### Escaping Output

```php
// In Blade templates
<div>{{ escHtml($content) }}</div>
<input value="{{ escAttr($value) }}">
<a href="{{ escUrl($link) }}">Link</a>

<script>
    var data = {!! escJs($jsonData) !!};
</script>

<style>
    .class { content: {{ escCss($value) }}; }
</style>

// For rich HTML content (filtered)
{!! kses($userHtml) !!}
```

### 2. Security Headers

Apply security headers to all responses:

```php
// In routes/web.php or a route group
Route::middleware(['security.headers', 'csp'])->group(function () {
    // Your routes here
});
```

Configure headers in `config/artisanpack/security.php`:

```php
'security-headers' => [
    'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
    'X-Frame-Options' => 'SAMEORIGIN',
    'X-Content-Type-Options' => 'nosniff',
    'X-XSS-Protection' => '1; mode=block',
    'Referrer-Policy' => 'strict-origin-when-cross-origin',
],
```

For detailed CSP configuration, see the [CSP Framework Guide](csp-framework.md).

### 3. Two-Factor Authentication

#### Setup

1. Add the trait to your User model (see Step 4 above)

2. Create the required routes:

```php
// routes/web.php
Route::get('/two-factor/challenge', function () {
    return view('auth.two-factor-challenge');
})->name('two-factor.challenge');

Route::post('/two-factor/challenge', [TwoFactorController::class, 'verify'])
    ->name('two-factor.verify');
```

3. Apply the middleware to protected routes:

```php
Route::middleware(['auth', 'two-factor'])->group(function () {
    Route::get('/dashboard', [DashboardController::class, 'index']);
});
```

#### Enabling 2FA for Users

```php
use ArtisanPackUI\Security\Facades\TwoFactor;

// Enable 2FA for a user
$recoveryCodes = TwoFactor::enable($user);

// Generate and send a verification code
TwoFactor::generateCode($user);

// Verify a code
$valid = TwoFactor::verify($user, $code);

// Disable 2FA
TwoFactor::disable($user);
```

For complete 2FA implementation, see the [Two-Factor Authentication Guide](two-factor-authentication.md).

### 4. Role-Based Access Control

#### Creating Roles and Permissions

```bash
# Using Artisan commands
php artisan role:create admin
php artisan role:create editor
php artisan permission:create manage-users
php artisan permission:create edit-content

# Assign role to user
php artisan user:assign-role 1 admin
```

Or programmatically:

```php
use ArtisanPackUI\Security\Models\Role;
use ArtisanPackUI\Security\Models\Permission;

// Create roles
$admin = Role::create(['name' => 'admin', 'display_name' => 'Administrator']);
$editor = Role::create(['name' => 'editor', 'display_name' => 'Editor']);

// Create permissions
$manageUsers = Permission::create(['name' => 'manage-users']);
$editContent = Permission::create(['name' => 'edit-content']);

// Assign permissions to roles
$admin->permissions()->attach([$manageUsers->id, $editContent->id]);
$editor->permissions()->attach($editContent->id);

// Assign roles to users
$user->assignRole('admin');
$user->assignRole(['admin', 'editor']);
```

#### Checking Permissions

```php
// In controllers
if ($user->hasRole('admin')) {
    // User is admin
}

if ($user->hasPermission('edit-content')) {
    // User can edit content
}

if ($user->can('manage-users')) {
    // User can manage users
}
```

#### In Blade Templates

```blade
@role('admin')
    <a href="/admin">Admin Panel</a>
@endrole

@permission('edit-content')
    <button>Edit</button>
@endpermission
```

#### Protecting Routes

```php
Route::middleware(['auth', 'permission:manage-users'])->group(function () {
    Route::resource('users', UserController::class);
});
```

For more details, see the [RBAC Guide](rbac.md).

### 5. API Security

#### Creating API Tokens

```php
// Create a token with default expiration
$token = $user->createApiToken('my-app');
echo $token->plainTextToken; // Use this for API authentication

// Create a token with specific abilities
$token = $user->createApiToken('read-only', ['read']);

// Create a token with custom expiration (30 days in minutes)
$token = $user->createApiToken('service', ['*'], 60 * 24 * 30);

// Using ability groups
$token = $user->createApiTokenWithGroup('admin-token', 'admin');
```

#### Protecting API Routes

```php
Route::middleware(['auth:sanctum', 'api.security', 'api.throttle'])->group(function () {
    Route::get('/user', fn() => auth()->user());

    Route::middleware('token.ability:write')->group(function () {
        Route::post('/posts', [PostController::class, 'store']);
    });
});
```

For complete API security, see the [API Security Guide](api-security.md).

### 6. Password Security

#### Validation Rules

```php
use ArtisanPackUI\Security\Rules\PasswordComplexity;
use ArtisanPackUI\Security\Rules\NotCompromised;
use ArtisanPackUI\Security\Rules\PasswordHistoryRule;

$request->validate([
    'password' => [
        'required',
        'confirmed',
        new PasswordComplexity(),
        new NotCompromised(),
        new PasswordHistoryRule($user),
    ],
]);
```

#### Password Strength Meter

Use the Livewire component for real-time password strength feedback:

```blade
<livewire:password-strength-meter />
```

Configure password requirements in `config/artisanpack/security.php`:

```php
'passwordSecurity' => [
    'complexity' => [
        'minLength' => 8,
        'requireUppercase' => true,
        'requireLowercase' => true,
        'requireNumbers' => true,
        'requireSymbols' => true,
    ],
    'breachChecking' => [
        'enabled' => true,
        'onRegistration' => true,
        'onPasswordChange' => true,
    ],
],
```

### 7. Session Security

#### Enforce Session Encryption

```php
Route::middleware(['auth', 'session.encrypted'])->group(function () {
    // These routes require encrypted sessions
});
```

#### Session Binding

Bind sessions to specific client attributes:

```php
Route::middleware(['auth', 'session.binding'])->group(function () {
    // Sessions are bound to IP and user agent
});
```

Configure in `config/artisanpack/security.php`:

```php
'advanced_sessions' => [
    'binding' => [
        'enabled' => true,
        'ip_address' => ['enabled' => true, 'strictness' => 'subnet'],
        'user_agent' => ['enabled' => true, 'strictness' => 'exact'],
    ],
    'concurrent_sessions' => [
        'enabled' => true,
        'max_sessions' => 5,
    ],
],
```

For advanced session features, see the [Session Security Guide](session-security.md).

### 8. File Upload Security

#### Validating Uploads

```php
Route::post('/upload', function (Request $request) {
    $request->validate([
        'file' => [
            'required',
            'file',
            new \ArtisanPackUI\Security\Rules\SecureFile(),
        ],
    ]);

    // File is validated
})->middleware(['auth', 'upload.validate', 'upload.scan']);
```

#### Secure File Storage

```php
use ArtisanPackUI\Security\Contracts\SecureFileStorageInterface;

public function store(Request $request, SecureFileStorageInterface $storage)
{
    $file = $storage->store(
        $request->file('document'),
        $request->user(),
        ['category' => 'documents']
    );

    return response()->json(['id' => $file->id]);
}
```

For complete file security, see the [File Upload Security Guide](file-upload-security.md).

## Security Architecture Overview

### Service Layer

The package provides these core services:

| Service | Purpose |
|---------|---------|
| `SecurityEventLogger` | Centralized security event logging |
| `PasswordSecurityService` | Password validation and breach checking |
| `FileValidationService` | File upload validation |
| `SecureFileStorageService` | Encrypted file storage |
| `CspPolicyService` | CSP policy generation |
| `HaveIBeenPwnedService` | Password breach detection |

### Middleware Chain

A typical secure request flows through:

```text
Request
    │
    ▼
┌──────────────────────────┐
│   SecurityHeaders        │  Apply security headers
└──────────────────────────┘
    │
    ▼
┌──────────────────────────┐
│   ContentSecurityPolicy  │  Apply CSP with nonces
└──────────────────────────┘
    │
    ▼
┌──────────────────────────┐
│   CheckAccountLockout    │  Prevent locked account access
└──────────────────────────┘
    │
    ▼
┌──────────────────────────┐
│   auth:sanctum           │  Authenticate request
└──────────────────────────┘
    │
    ▼
┌──────────────────────────┐
│   TwoFactorMiddleware    │  Verify 2FA if enabled
└──────────────────────────┘
    │
    ▼
┌──────────────────────────┐
│   CheckPermission        │  Verify authorization
└──────────────────────────┘
    │
    ▼
┌──────────────────────────┐
│   DetectSuspiciousActivity│  Monitor for threats
└──────────────────────────┘
    │
    ▼
  Controller
```

### Event System

The package emits events for security-related actions:

```php
// Listen for security events
use ArtisanPackUI\Security\Events\SecurityEventOccurred;
use ArtisanPackUI\Security\Events\SuspiciousActivityDetected;
use ArtisanPackUI\Security\Events\AccountLocked;

Event::listen(SecurityEventOccurred::class, function ($event) {
    // Handle security event
});

Event::listen(SuspiciousActivityDetected::class, function ($event) {
    // Handle suspicious activity
    Log::warning('Suspicious activity', [
        'user_id' => $event->userId,
        'type' => $event->type,
        'severity' => $event->severity,
    ]);
});
```

## Verification

After implementation, verify your security setup:

```bash
# Check security configuration
php artisan security:check-config

# Test security headers
php artisan security:test-headers

# Run a full security audit
php artisan security:audit

# Check for vulnerable dependencies
php artisan security:scan-dependencies
```

## Next Steps

- [Configuration Reference](configuration-reference.md) - Complete configuration options
- [Command Reference](command-reference.md) - All available Artisan commands
- [Troubleshooting Guide](troubleshooting.md) - Common issues and solutions
- [Security Checklist](security-checklist.md) - Pre-launch security checklist
