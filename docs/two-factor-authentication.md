---
title: Two-Factor Authentication Guide
---

# Two-Factor Authentication

This guide provides comprehensive documentation for implementing two-factor authentication (2FA) in your Laravel application using the ArtisanPack UI Security package.

## Overview

The 2FA system provides:
- **Email-based authentication**: Sends 6-digit codes via email
- **Google Authenticator/TOTP support**: For authenticator apps (requires additional setup)
- **Extensible provider system**: Create custom 2FA providers
- **Recovery codes**: Backup authentication method
- **Session-based code storage**: Secure temporary code storage with expiration

## Quick Setup

### 1. Database Migration

Add the required columns to your users table:

```php
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class AddTwoFactorColumnsToUsersTable extends Migration
{
    public function up()
    {
        Schema::table('users', function (Blueprint $table) {
            $table->string('two_factor_secret')->nullable();
            $table->text('two_factor_recovery_codes')->nullable();
            $table->timestamp('two_factor_enabled_at')->nullable();
        });
    }

    public function down()
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn([
                'two_factor_secret',
                'two_factor_recovery_codes', 
                'two_factor_enabled_at'
            ]);
        });
    }
}
```

### 2. Update User Model

Add the `TwoFactorAuthenticatable` trait to your User model:

```php
<?php

namespace App\Models;

use ArtisanPackUI\Security\TwoFactor\TwoFactorAuthenticatable;
use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable
{
    use TwoFactorAuthenticatable;

    protected $fillable = [
        'name',
        'email', 
        'password',
        // Don't add 2FA fields to fillable for security
    ];

    protected $hidden = [
        'password',
        'remember_token',
        'two_factor_secret',
        'two_factor_recovery_codes',
    ];

    protected $casts = [
        'email_verified_at' => 'datetime',
        'two_factor_enabled_at' => 'datetime',
    ];
}
```

### 3. Create Required Routes

**⚠️ Critical Requirement:** You must create these routes for 2FA to work:

```php
<?php
// routes/web.php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use ArtisanPackUI\Security\Facades\TwoFactor;

// Show 2FA challenge form
Route::get('/two-factor/challenge', function () {
    return view('auth.two-factor-challenge');
})->name('two-factor.challenge');

// Verify 2FA code
Route::post('/two-factor/challenge', function (Request $request) {
    $request->validate([
        'code' => 'required|string',
    ]);

    $user = Auth::user();
    
    if (TwoFactor::verify($user, $request->code)) {
        // Mark user as fully authenticated
        session(['two_factor_verified' => true]);
        return redirect()->intended('/dashboard');
    }

    return back()->withErrors([
        'code' => 'The provided two-factor authentication code is invalid.',
    ]);
})->name('two-factor.verify');
```

### 4. Create Challenge View

Create the view file at `resources/views/auth/two-factor-challenge.blade.php`:

```blade
@extends('layouts.app')

@section('content')
<div class="container">
    <div class="row justify-content-center">
        <div class="col-md-8">
            <div class="card">
                <div class="card-header">{{ __('Two-Factor Authentication') }}</div>

                <div class="card-body">
                    <p>Please enter the 6-digit code sent to your email address.</p>

                    <form method="POST" action="{{ route('two-factor.verify') }}">
                        @csrf

                        <div class="row mb-3">
                            <label for="code" class="col-md-4 col-form-label text-md-end">{{ __('Authentication Code') }}</label>

                            <div class="col-md-6">
                                <input id="code" type="text" class="form-control @error('code') is-invalid @enderror" 
                                       name="code" required autocomplete="off" autofocus maxlength="6" 
                                       placeholder="000000">

                                @error('code')
                                    <span class="invalid-feedback" role="alert">
                                        <strong>{{ $message }}</strong>
                                    </span>
                                @enderror
                            </div>
                        </div>

                        <div class="row mb-0">
                            <div class="col-md-8 offset-md-4">
                                <button type="submit" class="btn btn-primary">
                                    {{ __('Verify') }}
                                </button>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
@endsection
```

## Usage

### Basic Email-Based 2FA

```php
use ArtisanPackUI\Security\Facades\TwoFactor;

// In your login controller, after password verification
public function login(Request $request)
{
    // ... standard login logic ...
    
    if (Auth::attempt($credentials)) {
        $user = Auth::user();
        
        // Check if user has 2FA enabled
        if ($user->hasTwoFactorEnabled()) {
            // Generate and send 2FA challenge
            TwoFactor::generateChallenge($user);
            
            // Redirect to 2FA challenge
            return redirect()->route('two-factor.challenge');
        }
        
        // Normal login flow
        return redirect()->intended('/dashboard');
    }
    
    return back()->withErrors(['email' => 'Invalid credentials.']);
}
```

### Enabling 2FA for Users

```php
// In a controller method for enabling 2FA
public function enable2FA(Request $request)
{
    $user = $request->user();
    
    // Mark 2FA as enabled
    $user->two_factor_enabled_at = now();
    $user->save();
    
    // Optionally generate recovery codes
    $user->generateRecoveryCodes();
    
    return response()->json(['message' => '2FA enabled successfully']);
}

// Disable 2FA
public function disable2FA(Request $request)
{
    $user = $request->user();
    
    $user->two_factor_enabled_at = null;
    $user->two_factor_secret = null;
    $user->two_factor_recovery_codes = null;
    $user->save();
    
    return response()->json(['message' => '2FA disabled successfully']);
}
```

### Working with Recovery Codes

```php
// Generate recovery codes
$user->generateRecoveryCodes();

// Check if user has recovery codes
if ($user->two_factor_recovery_codes) {
    $codes = json_decode(decrypt($user->two_factor_recovery_codes));
    // Display codes to user (one-time only!)
}

// Verify recovery code (implement this logic)
public function verifyRecoveryCode($user, $code)
{
    if (!$user->two_factor_recovery_codes) {
        return false;
    }
    
    $codes = collect(json_decode(decrypt($user->two_factor_recovery_codes)));
    
    if (!$codes->contains($code)) {
        return false;
    }
    
    // Remove used code
    $codes = $codes->reject(function ($c) use ($code) {
        return hash_equals($c, $code);
    });
    
    // Save remaining codes
    $user->two_factor_recovery_codes = encrypt(json_encode($codes->values()->all()));
    $user->save();
    
    return true;
}
```

## Configuration

### Environment Variables

Configure 2FA in your `.env` file:

```env
# Default 2FA provider (email, authenticator, etc.)
TWO_FACTOR_PROVIDER=email

# Mail configuration (required for email provider)
MAIL_MAILER=smtp
MAIL_HOST=your-smtp-host
MAIL_PORT=587
MAIL_USERNAME=your-username
MAIL_PASSWORD=your-password
MAIL_ENCRYPTION=tls
MAIL_FROM_ADDRESS=noreply@yourapp.com
MAIL_FROM_NAME="${APP_NAME}"
```

### Configuration File

The package configuration is located at `config/security.php`:

```php
return [
    'routes' => [
        // The route name where users will be redirected to enter their 2FA code
        'verify' => 'two-factor.challenge',
    ],

    'two_factor' => [
        // Default provider
        'default' => env('TWO_FACTOR_PROVIDER', 'email'),

        // Available providers
        'providers' => [
            'email' => [
                'driver' => \ArtisanPackUI\Security\TwoFactor\Providers\EmailProvider::class,
            ],
            // Add custom providers here
        ],
    ],
];
```

## Advanced Usage

### Custom 2FA Providers

Create custom providers by implementing the `TwoFactorProvider` interface:

```php
<?php

namespace App\TwoFactor\Providers;

use ArtisanPackUI\Security\TwoFactor\Contracts\TwoFactorProvider;
use Illuminate\Contracts\Auth\Authenticatable;

class SmsProvider implements TwoFactorProvider
{
    public function generateChallenge(Authenticatable $user): void
    {
        $code = random_int(100000, 999999);
        
        // Store code in session
        session([
            'two_factor_code' => $code,
            'two_factor_expires' => now()->addMinutes(5),
            'two_factor_user_id' => $user->getAuthIdentifier(),
        ]);
        
        // Send SMS (implement your SMS logic)
        $this->sendSms($user->phone, "Your verification code: {$code}");
    }

    public function verify(Authenticatable $user, string $code): bool
    {
        if (
            session('two_factor_user_id') !== $user->getAuthIdentifier() ||
            now()->isAfter(session('two_factor_expires')) ||
            !hash_equals((string) session('two_factor_code'), $code)
        ) {
            return false;
        }

        session()->forget(['two_factor_code', 'two_factor_expires', 'two_factor_user_id']);
        return true;
    }

    private function sendSms($phone, $message)
    {
        // Implement SMS sending logic
    }
}
```

Register your custom provider:

```php
// In config/security.php
'providers' => [
    'email' => [
        'driver' => \ArtisanPackUI\Security\TwoFactor\Providers\EmailProvider::class,
    ],
    'sms' => [
        'driver' => \App\TwoFactor\Providers\SmsProvider::class,
    ],
],
```

### Middleware for 2FA Protection

Create middleware to ensure 2FA verification:

```php
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class EnsureTwoFactorAuthenticated
{
    public function handle(Request $request, Closure $next)
    {
        $user = Auth::user();
        
        if ($user && $user->hasTwoFactorEnabled() && !session('two_factor_verified')) {
            return redirect()->route('two-factor.challenge');
        }
        
        return $next($request);
    }
}
```

## Security Best Practices

### 1. Rate Limiting

Implement rate limiting for 2FA verification:

```php
// In routes/web.php
Route::post('/two-factor/challenge', function (Request $request) {
    // ... verification logic ...
})->name('two-factor.verify')->middleware('throttle:5,1'); // 5 attempts per minute
```

### 2. Code Expiration

The email provider automatically expires codes after 10 minutes. Ensure your custom providers implement similar expiration:

```php
session([
    'two_factor_code' => $code,
    'two_factor_expires' => now()->addMinutes(10), // Adjust as needed
    'two_factor_user_id' => $user->getAuthIdentifier(),
]);
```

### 3. Secure Code Generation

Use cryptographically secure random number generation:

```php
// Good - cryptographically secure
$code = random_int(100000, 999999);

// Bad - not cryptographically secure
$code = rand(100000, 999999);
```

### 4. Hash Timing Attack Protection

Always use `hash_equals()` for code comparison:

```php
// Good - timing attack resistant
if (hash_equals((string) session('two_factor_code'), $code)) {
    // Valid code
}

// Bad - vulnerable to timing attacks
if (session('two_factor_code') == $code) {
    // Valid code
}
```

## Troubleshooting

### Common Issues

**2FA emails not sending:**
- Verify mail configuration in `.env`
- Check mail logs for errors
- Test mail configuration with `php artisan tinker`: `Mail::raw('test', function($m) { $m->to('test@example.com')->subject('Test'); });`

**Route not found error:**
- Ensure you've created the `two-factor.challenge` route
- Clear route cache: `php artisan route:clear`

**Session issues:**
- Verify session driver is configured properly
- Check that session cookies are being set
- Consider session lifetime settings

**Database errors:**
- Ensure migration has been run: `php artisan migrate`
- Verify database connection
- Check table structure matches migration

### Testing

Test 2FA functionality:

```php
<?php

namespace Tests\Feature;

use App\Models\User;
use Tests\TestCase;
use ArtisanPackUI\Security\Facades\TwoFactor;

class TwoFactorAuthTest extends TestCase
{
    public function test_two_factor_challenge_generation()
    {
        $user = User::factory()->create([
            'two_factor_enabled_at' => now(),
        ]);

        TwoFactor::generateChallenge($user);

        $this->assertNotNull(session('two_factor_code'));
        $this->assertNotNull(session('two_factor_expires'));
        $this->assertEquals($user->id, session('two_factor_user_id'));
    }

    public function test_two_factor_code_verification()
    {
        $user = User::factory()->create([
            'two_factor_enabled_at' => now(),
        ]);

        // Simulate code generation
        session([
            'two_factor_code' => '123456',
            'two_factor_expires' => now()->addMinutes(10),
            'two_factor_user_id' => $user->id,
        ]);

        $this->assertTrue(TwoFactor::verify($user, '123456'));
        $this->assertFalse(TwoFactor::verify($user, '654321'));
    }
}
```

## API Reference

### TwoFactorManager Methods

- `generateChallenge(Authenticatable $user)` - Generate and send 2FA challenge
- `verify(Authenticatable $user, string $code)` - Verify 2FA code
- `provider(?string $name = null)` - Get specific provider instance

### TwoFactorAuthenticatable Trait Methods

- `hasTwoFactorEnabled()` - Check if 2FA is enabled
- `generateTwoFactorSecret()` - Generate TOTP secret for authenticator apps
- `generateRecoveryCodes()` - Generate backup recovery codes

### Configuration Options

- `security.two_factor.default` - Default 2FA provider
- `security.two_factor.providers` - Available provider configurations
- `security.routes.verify` - Route name for 2FA challenge page

## Support

For additional help:
- Check the [Security Guidelines](security-guidelines.md) for general security best practices
- Review the [API Reference](api-reference.md) for detailed function documentation
- See the [Contributing Guide](contributing.md) for how to report issues or contribute improvements