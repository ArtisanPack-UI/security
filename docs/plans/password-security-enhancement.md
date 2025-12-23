# Password Security Enhancement Implementation Plan

## Overview

This document outlines the implementation plan for enhanced password security features in the ArtisanPack Security package. The feature set includes password complexity validation, history tracking, expiration policies, strength metering, breach checking via HaveIBeenPwned, and comprehensive policy enforcement.

---

## Table of Contents

1. [Feature Summary](#feature-summary)
2. [Architecture Overview](#architecture-overview)
3. [Implementation Details](#implementation-details)
   - [Phase 1: Configuration & Core Infrastructure](#phase-1-configuration--core-infrastructure)
   - [Phase 2: Password History Tracking](#phase-2-password-history-tracking)
   - [Phase 3: Password Complexity Validation](#phase-3-password-complexity-validation)
   - [Phase 4: Password Expiration Policies](#phase-4-password-expiration-policies)
   - [Phase 5: HaveIBeenPwned Integration](#phase-5-haveibeenpwned-integration)
   - [Phase 6: Password Strength Meter Component](#phase-6-password-strength-meter-component)
   - [Phase 7: Policy Enforcement Middleware](#phase-7-policy-enforcement-middleware)
4. [Database Schema](#database-schema)
5. [Configuration Structure](#configuration-structure)
6. [API Reference](#api-reference)
7. [Testing Strategy](#testing-strategy)
8. [Documentation Requirements](#documentation-requirements)
9. [Acceptance Criteria Checklist](#acceptance-criteria-checklist)

---

## Feature Summary

| Feature | Description | Priority |
|---------|-------------|----------|
| Password Complexity | Configurable rules for length, characters, patterns | High |
| Password History | Prevent reuse of recent N passwords | High |
| Password Expiration | Force password changes after N days | Medium |
| Strength Meter | Real-time password strength feedback UI | Medium |
| Breach Checking | HaveIBeenPwned API integration | High |
| Policy Enforcement | Middleware to enforce all policies | High |

---

## Architecture Overview

### Dependencies

This feature relies on:
- **artisanpack-ui/livewire-ui-components** - For UI components in Blade views using the `x-artisanpack-` prefix:
  - `<x-artisanpack-progress>` - Progress bar for strength visualization
  - `<x-artisanpack-badge>` - Badge for strength label (error, warning, info, success colors)
  - `<x-artisanpack-alert>` - Alert for feedback suggestions
  - `<x-artisanpack-icon>` - Icons with `o-` (outline), `s-` (solid) prefixes
  - `<x-artisanpack-text>` - Text with size, muted, semibold props
- **Laravel's Password validation** - Extended for breach checking
- **zxcvbn-php** (optional) - For advanced password strength calculation

### Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    Password Security Layer                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────┐    ┌──────────────────┐                   │
│  │   Validation     │    │    Services      │                   │
│  │   Rules          │    │                  │                   │
│  ├──────────────────┤    ├──────────────────┤                   │
│  │ PasswordPolicy   │    │ PasswordSecurity │                   │
│  │ PasswordHistory  │◄───│ Service          │                   │
│  │ PasswordStrength │    │                  │                   │
│  │ NotCompromised   │    │ BreachChecker    │                   │
│  └──────────────────┘    │ Service          │                   │
│                          └────────┬─────────┘                   │
│  ┌──────────────────┐             │                             │
│  │   Middleware     │             │                             │
│  ├──────────────────┤             │                             │
│  │ EnforcePassword  │◄────────────┘                             │
│  │ Policy           │                                           │
│  │                  │                                           │
│  │ RequirePassword  │                                           │
│  │ Change           │                                           │
│  └──────────────────┘                                           │
│                                                                  │
│  ┌──────────────────┐    ┌──────────────────┐                   │
│  │   Livewire       │    │    Models        │                   │
│  │   Components     │    │                  │                   │
│  ├──────────────────┤    ├──────────────────┤                   │
│  │ PasswordStrength │    │ PasswordHistory  │                   │
│  │ Meter            │    │                  │                   │
│  └──────────────────┘    └──────────────────┘                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### File Structure

```
src/
├── Contracts/
│   ├── PasswordSecurityServiceInterface.php
│   └── BreachCheckerInterface.php
├── Services/
│   ├── PasswordSecurityService.php
│   └── HaveIBeenPwnedService.php
├── Rules/
│   ├── PasswordComplexity.php
│   ├── PasswordHistory.php
│   ├── PasswordStrength.php
│   └── NotCompromised.php
├── Http/
│   └── Middleware/
│       ├── EnforcePasswordPolicy.php
│       └── RequirePasswordChange.php
├── Models/
│   └── PasswordHistory.php
├── Livewire/
│   └── PasswordStrengthMeter.php
├── Concerns/
│   └── HasPasswordHistory.php
└── Events/
    ├── PasswordChanged.php
    ├── PasswordExpired.php
    └── CompromisedPasswordDetected.php

database/
└── migrations/
    └── 2025_XX_XX_000001_create_password_history_table.php

resources/
└── views/
    └── livewire/
        └── password-strength-meter.blade.php

config/
└── security.php (additions to existing file)
```

---

## Implementation Details

### Phase 1: Configuration & Core Infrastructure

#### 1.1 Configuration Additions (`config/security.php`)

Add a new `passwordSecurity` section to the existing configuration:

```php
'passwordSecurity' => [
    'enabled' => env('SECURITY_PASSWORD_ENABLED', true),

    /*
     * Password complexity requirements
     */
    'complexity' => [
        'minLength' => 8,
        'maxLength' => 128,
        'requireUppercase' => true,
        'requireLowercase' => true,
        'requireNumbers' => true,
        'requireSymbols' => true,
        'minUniqueCharacters' => 4,
        'disallowRepeatingCharacters' => 3, // Max consecutive repeating chars
        'disallowSequentialCharacters' => 3, // e.g., "abc", "123"
        'disallowCommonPasswords' => true,
        'disallowUserAttributes' => true, // Disallow email, name in password
    ],

    /*
     * Password history settings
     */
    'history' => [
        'enabled' => true,
        'count' => 5, // Number of previous passwords to remember
        'minDaysBetweenChanges' => 1, // Minimum days before password can be changed
    ],

    /*
     * Password expiration settings
     */
    'expiration' => [
        'enabled' => false,
        'days' => 90, // Days until password expires
        'warningDays' => 14, // Days before expiration to warn user
        'graceLogins' => 3, // Number of logins allowed after expiration
        'exemptRoles' => [], // Roles exempt from expiration
    ],

    /*
     * Password breach checking (HaveIBeenPwned)
     */
    'breachChecking' => [
        'enabled' => env('SECURITY_BREACH_CHECK_ENABLED', true),
        'onRegistration' => true,
        'onPasswordChange' => true,
        'onLogin' => false, // Check on every login (performance impact)
        'blockCompromised' => true, // Block or warn only
        'apiTimeout' => 5, // Seconds
        'cacheResults' => true,
        'cacheTtl' => 86400, // Cache breach results for 24 hours
    ],

    /*
     * Password strength meter settings
     */
    'strengthMeter' => [
        'enabled' => true,
        'showFeedback' => true,
        'minScore' => 3, // Minimum zxcvbn score (0-4)
        'showCrackTime' => true,
    ],

    /*
     * Logging settings
     */
    'logging' => [
        'passwordChanges' => true,
        'failedValidations' => true,
        'breachDetections' => true,
        'expirationWarnings' => true,
    ],
],
```

#### 1.2 Contract Interface (`src/Contracts/PasswordSecurityServiceInterface.php`)

```php
<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

interface PasswordSecurityServiceInterface
{
    /**
     * Validate a password against all configured policies.
     */
    public function validatePassword(string $password, ?Authenticatable $user = null): array;

    /**
     * Check if a password meets complexity requirements.
     */
    public function checkComplexity(string $password): array;

    /**
     * Check if password exists in user's history.
     */
    public function isInHistory(string $password, Authenticatable $user): bool;

    /**
     * Record a password in user's history.
     */
    public function recordPassword(string $hashedPassword, Authenticatable $user): void;

    /**
     * Check if user's password has expired.
     */
    public function isExpired(Authenticatable $user): bool;

    /**
     * Get days until password expires.
     */
    public function daysUntilExpiration(Authenticatable $user): ?int;

    /**
     * Check if password has been compromised in known breaches.
     */
    public function isCompromised(string $password): bool;

    /**
     * Calculate password strength score (0-4).
     */
    public function calculateStrength(string $password, array $userInputs = []): array;

    /**
     * Prune old password history records.
     */
    public function pruneHistory(Authenticatable $user): int;
}
```

#### 1.3 Breach Checker Interface (`src/Contracts/BreachCheckerInterface.php`)

```php
<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Contracts;

interface BreachCheckerInterface
{
    /**
     * Check if a password has been exposed in known data breaches.
     *
     * @return int Number of times password has been seen in breaches (0 if not found)
     */
    public function check(string $password): int;

    /**
     * Check if password is compromised (boolean convenience method).
     */
    public function isCompromised(string $password): bool;
}
```

---

### Phase 2: Password History Tracking

#### 2.1 Database Migration

**File:** `database/migrations/2025_XX_XX_000001_create_password_history_table.php`

```php
<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (! Schema::hasTable('password_history')) {
            Schema::create('password_history', function (Blueprint $table): void {
                $table->id();
                $table->unsignedBigInteger('user_id')->index();
                $table->string('password_hash');
                $table->timestamp('created_at')->index();

                $table->foreign('user_id')
                    ->references('id')
                    ->on('users')
                    ->onDelete('cascade');

                // Composite index for efficient history lookups
                $table->index(['user_id', 'created_at']);
            });
        }
    }

    public function down(): void
    {
        Schema::dropIfExists('password_history');
    }
};
```

#### 2.2 Add Password Expiration Columns to Users Table

**File:** `database/migrations/2025_XX_XX_000002_add_password_security_columns_to_users_table.php`

> **Note:** This migration only runs if the `users` table exists. Applications without a standard users table can skip this migration or customize it for their user model's table.

```php
<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Only modify users table if it exists
        if (! Schema::hasTable('users')) {
            return;
        }

        Schema::table('users', function (Blueprint $table): void {
            if (! Schema::hasColumn('users', 'password_changed_at')) {
                $table->timestamp('password_changed_at')
                    ->nullable()
                    ->after('password');
            }

            if (! Schema::hasColumn('users', 'password_expires_at')) {
                $table->timestamp('password_expires_at')
                    ->nullable()
                    ->after('password_changed_at');
            }

            if (! Schema::hasColumn('users', 'force_password_change')) {
                $table->boolean('force_password_change')
                    ->default(false)
                    ->after('password_expires_at');
            }

            if (! Schema::hasColumn('users', 'grace_logins_remaining')) {
                $table->unsignedTinyInteger('grace_logins_remaining')
                    ->nullable()
                    ->after('force_password_change');
            }
        });
    }

    public function down(): void
    {
        if (! Schema::hasTable('users')) {
            return;
        }

        Schema::table('users', function (Blueprint $table): void {
            $columns = ['password_changed_at', 'password_expires_at', 'force_password_change', 'grace_logins_remaining'];

            foreach ($columns as $column) {
                if (Schema::hasColumn('users', $column)) {
                    $table->dropColumn($column);
                }
            }
        });
    }
};
```

#### 2.3 Password History Model

**File:** `src/Models/PasswordHistory.php`

```php
<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class PasswordHistory extends Model
{
    public $timestamps = false;

    protected $table = 'password_history';

    protected $fillable = [
        'user_id',
        'password_hash',
        'created_at',
    ];

    protected $casts = [
        'created_at' => 'datetime',
    ];

    protected $hidden = [
        'password_hash',
    ];

    public function user(): BelongsTo
    {
        return $this->belongsTo(config('auth.providers.users.model'));
    }

    /**
     * Scope to get recent password history for a user.
     */
    public function scopeForUser($query, int $userId, int $limit = 5)
    {
        return $query->where('user_id', $userId)
            ->orderByDesc('created_at')
            ->limit($limit);
    }
}
```

#### 2.4 HasPasswordHistory Concern

**File:** `src/Concerns/HasPasswordHistory.php`

```php
<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Concerns;

use ArtisanPackUI\Security\Models\PasswordHistory;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Facades\Hash;

trait HasPasswordHistory
{
    /**
     * Boot the trait.
     */
    public static function bootHasPasswordHistory(): void
    {
        // When password is updated, record in history
        static::updating(function ($user) {
            if ($user->isDirty('password') && config('artisanpack.security.passwordSecurity.history.enabled', false)) {
                $originalPassword = $user->getOriginal('password');
                if ($originalPassword) {
                    $user->recordPasswordInHistory($originalPassword);
                }

                // Update password_changed_at timestamp
                $user->password_changed_at = now();

                // Calculate new expiration if enabled
                if (config('artisanpack.security.passwordSecurity.expiration.enabled', false)) {
                    $days = config('artisanpack.security.passwordSecurity.expiration.days', 90);
                    $user->password_expires_at = now()->addDays($days);
                }

                // Reset force change flag
                $user->force_password_change = false;
                $user->grace_logins_remaining = null;
            }
        });
    }

    /**
     * Get the user's password history.
     */
    public function passwordHistory(): HasMany
    {
        return $this->hasMany(PasswordHistory::class, 'user_id');
    }

    /**
     * Record a password hash in history.
     */
    public function recordPasswordInHistory(string $hashedPassword): void
    {
        $this->passwordHistory()->create([
            'password_hash' => $hashedPassword,
            'created_at' => now(),
        ]);

        // Prune old history entries
        $this->prunePasswordHistory();
    }

    /**
     * Check if a plain-text password matches any in history.
     */
    public function passwordExistsInHistory(string $password): bool
    {
        $count = config('artisanpack.security.passwordSecurity.history.count', 5);

        $recentPasswords = $this->passwordHistory()
            ->orderByDesc('created_at')
            ->limit($count)
            ->pluck('password_hash');

        foreach ($recentPasswords as $hashedPassword) {
            if (Hash::check($password, $hashedPassword)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Prune old password history entries beyond the configured count.
     */
    public function prunePasswordHistory(): int
    {
        $count = config('artisanpack.security.passwordSecurity.history.count', 5);

        $idsToKeep = $this->passwordHistory()
            ->orderByDesc('created_at')
            ->limit($count)
            ->pluck('id');

        return $this->passwordHistory()
            ->whereNotIn('id', $idsToKeep)
            ->delete();
    }

    /**
     * Check if password has expired.
     */
    public function passwordHasExpired(): bool
    {
        if (! config('artisanpack.security.passwordSecurity.expiration.enabled', false)) {
            return false;
        }

        // Check exempt roles
        $exemptRoles = config('artisanpack.security.passwordSecurity.expiration.exemptRoles', []);
        if (method_exists($this, 'hasRole')) {
            foreach ($exemptRoles as $role) {
                if ($this->hasRole($role)) {
                    return false;
                }
            }
        }

        if ($this->password_expires_at === null) {
            return false;
        }

        return $this->password_expires_at->isPast();
    }

    /**
     * Check if password is expiring soon.
     */
    public function passwordExpiringSoon(): bool
    {
        if (! config('artisanpack.security.passwordSecurity.expiration.enabled', false)) {
            return false;
        }

        if ($this->password_expires_at === null) {
            return false;
        }

        $warningDays = config('artisanpack.security.passwordSecurity.expiration.warningDays', 14);

        return $this->password_expires_at->isBetween(now(), now()->addDays($warningDays));
    }

    /**
     * Get days until password expires.
     */
    public function daysUntilPasswordExpires(): ?int
    {
        if ($this->password_expires_at === null) {
            return null;
        }

        $days = now()->diffInDays($this->password_expires_at, false);

        return max(0, $days);
    }

    /**
     * Check if user can still login with grace period.
     */
    public function hasGraceLoginsRemaining(): bool
    {
        return $this->grace_logins_remaining !== null && $this->grace_logins_remaining > 0;
    }

    /**
     * Decrement grace logins.
     */
    public function decrementGraceLogins(): void
    {
        if ($this->grace_logins_remaining !== null && $this->grace_logins_remaining > 0) {
            $this->decrement('grace_logins_remaining');
        }
    }
}
```

---

### Phase 3: Password Complexity Validation

#### 3.1 Password Complexity Rule

**File:** `src/Rules/PasswordComplexity.php`

```php
<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Rules;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Validation\Rule;

class PasswordComplexity implements Rule
{
    protected array $errors = [];
    protected ?Authenticatable $user;

    public function __construct(?Authenticatable $user = null)
    {
        $this->user = $user;
    }

    public function passes($attribute, $value): bool
    {
        $this->errors = [];
        $config = config('artisanpack.security.passwordSecurity.complexity', []);

        // Length checks
        $minLength = $config['minLength'] ?? 8;
        $maxLength = $config['maxLength'] ?? 128;

        if (strlen($value) < $minLength) {
            $this->errors[] = "Password must be at least {$minLength} characters.";
        }

        if (strlen($value) > $maxLength) {
            $this->errors[] = "Password must not exceed {$maxLength} characters.";
        }

        // Character type requirements
        if (($config['requireUppercase'] ?? true) && ! preg_match('/[A-Z]/', $value)) {
            $this->errors[] = 'Password must contain at least one uppercase letter.';
        }

        if (($config['requireLowercase'] ?? true) && ! preg_match('/[a-z]/', $value)) {
            $this->errors[] = 'Password must contain at least one lowercase letter.';
        }

        if (($config['requireNumbers'] ?? true) && ! preg_match('/[0-9]/', $value)) {
            $this->errors[] = 'Password must contain at least one number.';
        }

        if (($config['requireSymbols'] ?? true) && ! preg_match('/[^A-Za-z0-9]/', $value)) {
            $this->errors[] = 'Password must contain at least one special character.';
        }

        // Unique characters
        $minUnique = $config['minUniqueCharacters'] ?? 4;
        if (count(array_unique(str_split($value))) < $minUnique) {
            $this->errors[] = "Password must contain at least {$minUnique} unique characters.";
        }

        // Repeating characters
        $maxRepeat = $config['disallowRepeatingCharacters'] ?? 3;
        if ($maxRepeat > 0 && preg_match('/(.)\1{' . $maxRepeat . ',}/', $value)) {
            $this->errors[] = "Password must not contain more than {$maxRepeat} consecutive repeating characters.";
        }

        // Sequential characters
        $maxSequential = $config['disallowSequentialCharacters'] ?? 3;
        if ($maxSequential > 0 && $this->hasSequentialCharacters($value, $maxSequential)) {
            $this->errors[] = "Password must not contain more than {$maxSequential} sequential characters.";
        }

        // User attributes check
        if (($config['disallowUserAttributes'] ?? true) && $this->user) {
            $this->checkUserAttributes($value);
        }

        return empty($this->errors);
    }

    public function message(): array
    {
        return $this->errors;
    }

    protected function hasSequentialCharacters(string $value, int $maxSequential): bool
    {
        $sequences = [
            'abcdefghijklmnopqrstuvwxyz',
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            '0123456789',
            'qwertyuiop',
            'asdfghjkl',
            'zxcvbnm',
        ];

        $lowerValue = strtolower($value);

        foreach ($sequences as $sequence) {
            $sequence = strtolower($sequence);
            for ($i = 0; $i <= strlen($sequence) - $maxSequential; $i++) {
                $chunk = substr($sequence, $i, $maxSequential + 1);
                if (str_contains($lowerValue, $chunk)) {
                    return true;
                }
                // Check reverse
                if (str_contains($lowerValue, strrev($chunk))) {
                    return true;
                }
            }
        }

        return false;
    }

    protected function checkUserAttributes(string $value): void
    {
        $lowerValue = strtolower($value);
        $attributes = ['email', 'name', 'username', 'first_name', 'last_name'];

        foreach ($attributes as $attr) {
            if (isset($this->user->{$attr})) {
                $attrValue = strtolower((string) $this->user->{$attr});
                // Check if attribute value (or parts of it) are in password
                if (strlen($attrValue) >= 3) {
                    // Check email local part
                    if ($attr === 'email') {
                        $localPart = explode('@', $attrValue)[0];
                        if (strlen($localPart) >= 3 && str_contains($lowerValue, $localPart)) {
                            $this->errors[] = 'Password must not contain parts of your email address.';
                            continue;
                        }
                    }

                    if (str_contains($lowerValue, $attrValue)) {
                        $this->errors[] = "Password must not contain your {$attr}.";
                    }
                }
            }
        }
    }
}
```

#### 3.2 Password History Rule

**File:** `src/Rules/PasswordHistory.php`

```php
<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Rules;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Validation\Rule;

class PasswordHistory implements Rule
{
    protected ?Authenticatable $user;

    public function __construct(?Authenticatable $user = null)
    {
        $this->user = $user;
    }

    public function passes($attribute, $value): bool
    {
        if (! config('artisanpack.security.passwordSecurity.history.enabled', false)) {
            return true;
        }

        if ($this->user === null) {
            return true;
        }

        if (! method_exists($this->user, 'passwordExistsInHistory')) {
            return true;
        }

        return ! $this->user->passwordExistsInHistory($value);
    }

    public function message(): string
    {
        $count = config('artisanpack.security.passwordSecurity.history.count', 5);

        return "You cannot reuse any of your last {$count} passwords.";
    }
}
```

---

### Phase 4: Password Expiration Policies

#### 4.1 Require Password Change Middleware

**File:** `src/Http/Middleware/RequirePasswordChange.php`

```php
<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class RequirePasswordChange
{
    /**
     * Routes that should be accessible even when password change is required.
     */
    protected array $exceptRoutes = [
        'password.change',
        'password.update',
        'logout',
    ];

    public function handle(Request $request, Closure $next): Response
    {
        if (! config('artisanpack.security.passwordSecurity.expiration.enabled', false)) {
            return $next($request);
        }

        $user = $request->user();

        if (! $user) {
            return $next($request);
        }

        // Check if current route is exempt
        $currentRoute = $request->route()?->getName();
        if ($currentRoute && in_array($currentRoute, $this->exceptRoutes, true)) {
            return $next($request);
        }

        // Check for forced password change
        if ($user->force_password_change ?? false) {
            return $this->redirectToPasswordChange($request, 'Your password must be changed.');
        }

        // Check if method exists (trait may not be applied)
        if (! method_exists($user, 'passwordHasExpired')) {
            return $next($request);
        }

        // Check password expiration
        if ($user->passwordHasExpired()) {
            // Check grace logins
            if ($user->hasGraceLoginsRemaining()) {
                $user->decrementGraceLogins();
                session()->flash('password_warning', sprintf(
                    'Your password has expired. You have %d login(s) remaining before you must change it.',
                    $user->grace_logins_remaining
                ));

                return $next($request);
            }

            return $this->redirectToPasswordChange($request, 'Your password has expired and must be changed.');
        }

        // Check if password is expiring soon (warning only)
        if ($user->passwordExpiringSoon()) {
            $days = $user->daysUntilPasswordExpires();
            session()->flash('password_warning', sprintf(
                'Your password will expire in %d day(s). Please change it soon.',
                $days
            ));
        }

        return $next($request);
    }

    protected function redirectToPasswordChange(Request $request, string $message)
    {
        if ($request->expectsJson()) {
            return response()->json([
                'message' => $message,
                'password_change_required' => true,
            ], 403);
        }

        return redirect()
            ->route('password.change')
            ->with('password_error', $message);
    }
}
```

---

### Phase 5: HaveIBeenPwned Integration

#### 5.1 HaveIBeenPwned Service

**File:** `src/Services/HaveIBeenPwnedService.php`

```php
<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Services;

use ArtisanPackUI\Security\Contracts\BreachCheckerInterface;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class HaveIBeenPwnedService implements BreachCheckerInterface
{
    protected const API_URL = 'https://api.pwnedpasswords.com/range/';

    /**
     * Check if a password has been exposed in known data breaches.
     *
     * Uses k-Anonymity model - only first 5 chars of SHA1 hash are sent.
     *
     * @return int Number of times password has been seen in breaches
     */
    public function check(string $password): int
    {
        if (! config('artisanpack.security.passwordSecurity.breachChecking.enabled', true)) {
            return 0;
        }

        $sha1 = strtoupper(sha1($password));
        $prefix = substr($sha1, 0, 5);
        $suffix = substr($sha1, 5);

        // Check cache first
        if (config('artisanpack.security.passwordSecurity.breachChecking.cacheResults', true)) {
            $cacheKey = "hibp_prefix_{$prefix}";
            $ttl = config('artisanpack.security.passwordSecurity.breachChecking.cacheTtl', 86400);

            $results = Cache::remember($cacheKey, $ttl, fn () => $this->fetchFromApi($prefix));
        } else {
            $results = $this->fetchFromApi($prefix);
        }

        if ($results === null) {
            // API failed, fail open (don't block user)
            return 0;
        }

        // Search for our suffix in the results
        foreach (explode("\n", $results) as $line) {
            $line = trim($line);
            if (empty($line)) {
                continue;
            }

            [$hashSuffix, $count] = explode(':', $line);

            if (strtoupper($hashSuffix) === $suffix) {
                return (int) $count;
            }
        }

        return 0;
    }

    /**
     * Check if password is compromised.
     */
    public function isCompromised(string $password): bool
    {
        return $this->check($password) > 0;
    }

    /**
     * Fetch hash range from HIBP API.
     */
    protected function fetchFromApi(string $prefix): ?string
    {
        try {
            $timeout = config('artisanpack.security.passwordSecurity.breachChecking.apiTimeout', 5);

            $response = Http::timeout($timeout)
                ->withHeaders([
                    'User-Agent' => 'ArtisanPack-Security-Laravel-Package',
                    'Add-Padding' => 'true', // Enable padding for privacy
                ])
                ->get(self::API_URL . $prefix);

            if ($response->successful()) {
                return $response->body();
            }

            Log::warning('HIBP API returned non-success status', [
                'status' => $response->status(),
                'prefix' => $prefix,
            ]);

            return null;
        } catch (\Exception $e) {
            Log::error('HIBP API request failed', [
                'error' => $e->getMessage(),
                'prefix' => $prefix,
            ]);

            return null;
        }
    }
}
```

#### 5.2 Not Compromised Rule

**File:** `src/Rules/NotCompromised.php`

```php
<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Rules;

use ArtisanPackUI\Security\Contracts\BreachCheckerInterface;
use Illuminate\Contracts\Validation\Rule;

class NotCompromised implements Rule
{
    protected int $threshold;
    protected int $occurrences = 0;

    public function __construct(int $threshold = 0)
    {
        $this->threshold = $threshold;
    }

    public function passes($attribute, $value): bool
    {
        if (! config('artisanpack.security.passwordSecurity.breachChecking.enabled', true)) {
            return true;
        }

        $checker = app(BreachCheckerInterface::class);
        $this->occurrences = $checker->check($value);

        return $this->occurrences <= $this->threshold;
    }

    public function message(): string
    {
        if ($this->occurrences > 0) {
            return sprintf(
                'This password has appeared in %s data breach(es) and should not be used. Please choose a different password.',
                number_format($this->occurrences)
            );
        }

        return 'This password has been compromised in a data breach. Please choose a different password.';
    }
}
```

---

### Phase 6: Password Strength Meter Component

#### 6.1 Livewire Component

**File:** `src/Livewire/PasswordStrengthMeter.php`

```php
<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Livewire;

use ArtisanPackUI\Security\Contracts\PasswordSecurityServiceInterface;
use Livewire\Attributes\Reactive;
use Livewire\Component;

class PasswordStrengthMeter extends Component
{
    #[Reactive]
    public string $password = '';

    public array $userInputs = [];

    public int $score = 0;

    public string $label = '';

    public string $crackTime = '';

    public array $feedback = [];

    public array $requirements = [];

    public function mount(array $userInputs = []): void
    {
        $this->userInputs = $userInputs;
        $this->initializeRequirements();
    }

    public function updatedPassword(): void
    {
        if (empty($this->password)) {
            $this->resetMetrics();
            return;
        }

        $service = app(PasswordSecurityServiceInterface::class);
        $result = $service->calculateStrength($this->password, $this->userInputs);

        $this->score = $result['score'];
        $this->label = $result['label'];
        $this->crackTime = $result['crackTime'] ?? '';
        $this->feedback = $result['feedback'] ?? [];

        // Update requirements status
        $this->updateRequirements();
    }

    public function render()
    {
        return view('security::livewire.password-strength-meter');
    }

    protected function initializeRequirements(): void
    {
        $config = config('artisanpack.security.passwordSecurity.complexity', []);

        $this->requirements = [
            'length' => [
                'label' => sprintf('At least %d characters', $config['minLength'] ?? 8),
                'met' => false,
            ],
            'uppercase' => [
                'label' => 'Contains uppercase letter',
                'met' => false,
                'enabled' => $config['requireUppercase'] ?? true,
            ],
            'lowercase' => [
                'label' => 'Contains lowercase letter',
                'met' => false,
                'enabled' => $config['requireLowercase'] ?? true,
            ],
            'number' => [
                'label' => 'Contains number',
                'met' => false,
                'enabled' => $config['requireNumbers'] ?? true,
            ],
            'symbol' => [
                'label' => 'Contains special character',
                'met' => false,
                'enabled' => $config['requireSymbols'] ?? true,
            ],
        ];
    }

    protected function updateRequirements(): void
    {
        $config = config('artisanpack.security.passwordSecurity.complexity', []);

        $this->requirements['length']['met'] = strlen($this->password) >= ($config['minLength'] ?? 8);
        $this->requirements['uppercase']['met'] = (bool) preg_match('/[A-Z]/', $this->password);
        $this->requirements['lowercase']['met'] = (bool) preg_match('/[a-z]/', $this->password);
        $this->requirements['number']['met'] = (bool) preg_match('/[0-9]/', $this->password);
        $this->requirements['symbol']['met'] = (bool) preg_match('/[^A-Za-z0-9]/', $this->password);
    }

    protected function resetMetrics(): void
    {
        $this->score = 0;
        $this->label = '';
        $this->crackTime = '';
        $this->feedback = [];
        $this->initializeRequirements();
    }
}
```

#### 6.2 Blade View

**File:** `resources/views/livewire/password-strength-meter.blade.php`

> **Note:** This view uses components from the `artisanpack-ui/livewire-ui-components` package for consistent styling. The default component prefix is `x-artisanpack-`.

```blade
<div class="password-strength-meter">
    {{-- Strength Bar --}}
    <div class="mt-2">
        <div class="flex justify-between mb-1">
            <x-artisanpack-text size="text-sm" semibold>
                Password Strength
            </x-artisanpack-text>
            @if($label)
                <x-artisanpack-badge
                    :value="$label"
                    :color="$this->getBadgeColor()"
                    class="badge-sm"
                />
            @endif
        </div>
        <x-artisanpack-progress
            :value="$this->getBarWidth()"
            :class="'progress-' . $this->getProgressColor()"
        />
    </div>

    {{-- Crack Time --}}
    @if(config('artisanpack.security.passwordSecurity.strengthMeter.showCrackTime') && $crackTime)
        <x-artisanpack-text size="text-xs" muted class="mt-1">
            Estimated crack time: <span class="font-medium">{{ $crackTime }}</span>
        </x-artisanpack-text>
    @endif

    {{-- Requirements Checklist --}}
    <div class="mt-3 space-y-1">
        @foreach($requirements as $key => $requirement)
            @if($requirement['enabled'] ?? true)
                <div class="flex items-center">
                    @if($requirement['met'])
                        <x-artisanpack-icon name="o-check-circle" class="w-4 h-4 text-success mr-2" />
                        <x-artisanpack-text size="text-sm" class="text-success">
                            {{ $requirement['label'] }}
                        </x-artisanpack-text>
                    @else
                        <x-artisanpack-icon name="o-x-circle" class="w-4 h-4 text-gray-400 mr-2" />
                        <x-artisanpack-text size="text-sm" muted>
                            {{ $requirement['label'] }}
                        </x-artisanpack-text>
                    @endif
                </div>
            @endif
        @endforeach
    </div>

    {{-- Feedback Messages --}}
    @if(config('artisanpack.security.passwordSecurity.strengthMeter.showFeedback') && count($feedback) > 0)
        <x-artisanpack-alert
            title="Suggestions"
            icon="o-light-bulb"
            color="warning"
            class="mt-3"
        >
            <ul class="mt-1 text-sm list-disc list-inside">
                @foreach($feedback as $suggestion)
                    <li>{{ $suggestion }}</li>
                @endforeach
            </ul>
        </x-artisanpack-alert>
    @endif
</div>
```

**Helper Methods for Component Props:**

Add these methods to the `PasswordStrengthMeter` Livewire component:

```php
public function getBadgeColor(): string
{
    return match ($this->score) {
        0 => 'error',
        1 => 'error',
        2 => 'warning',
        3 => 'info',
        4 => 'success',
        default => 'secondary',
    };
}

public function getProgressColor(): string
{
    return match ($this->score) {
        0 => 'error',
        1 => 'error',
        2 => 'warning',
        3 => 'info',
        4 => 'success',
        default => 'secondary',
    };
}

public function getBarWidth(): int
{
    return match ($this->score) {
        0 => 5,
        1 => 25,
        2 => 50,
        3 => 75,
        4 => 100,
        default => 0,
    };
}
```

---

### Phase 7: Policy Enforcement Middleware

#### 7.1 Enforce Password Policy Middleware

**File:** `src/Http/Middleware/EnforcePasswordPolicy.php`

```php
<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Http\Middleware;

use ArtisanPackUI\Security\Contracts\PasswordSecurityServiceInterface;
use ArtisanPackUI\Security\Contracts\SecurityEventLoggerInterface;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class EnforcePasswordPolicy
{
    public function __construct(
        protected PasswordSecurityServiceInterface $passwordService,
        protected ?SecurityEventLoggerInterface $logger = null
    ) {}

    /**
     * Handle password validation on registration/password change routes.
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (! config('artisanpack.security.passwordSecurity.enabled', true)) {
            return $next($request);
        }

        // Only validate on POST/PUT/PATCH requests with password field
        if (! in_array($request->method(), ['POST', 'PUT', 'PATCH'], true)) {
            return $next($request);
        }

        $password = $request->input('password');

        if ($password === null) {
            return $next($request);
        }

        $user = $request->user();
        $errors = $this->passwordService->validatePassword($password, $user);

        if (! empty($errors)) {
            $this->logValidationFailure($request, $errors);

            if ($request->expectsJson()) {
                return response()->json([
                    'message' => 'Password does not meet security requirements.',
                    'errors' => ['password' => $errors],
                ], 422);
            }

            return back()
                ->withInput($request->except('password', 'password_confirmation'))
                ->withErrors(['password' => $errors]);
        }

        return $next($request);
    }

    protected function logValidationFailure(Request $request, array $errors): void
    {
        if (! config('artisanpack.security.passwordSecurity.logging.failedValidations', true)) {
            return;
        }

        $this->logger?->authentication('password_validation_failed', [
            'user_id' => $request->user()?->id,
            'route' => $request->route()?->getName(),
            'errors' => $errors,
        ]);
    }
}
```

---

## Database Schema

### Entity Relationship Diagram

```
┌─────────────────┐         ┌─────────────────────┐
│     users       │         │   password_history  │
├─────────────────┤         ├─────────────────────┤
│ id              │◄────────│ user_id (FK)        │
│ email           │    1:N  │ id                  │
│ password        │         │ password_hash       │
│ password_changed│         │ created_at          │
│   _at           │         └─────────────────────┘
│ password_expires│
│   _at           │
│ force_password  │
│   _change       │
│ grace_logins    │
│   _remaining    │
└─────────────────┘
```

### Table Specifications

#### password_history

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | bigint unsigned | PK, AUTO_INCREMENT | Primary key |
| user_id | bigint unsigned | FK, INDEX, NOT NULL | References users.id |
| password_hash | varchar(255) | NOT NULL | Bcrypt hash of previous password |
| created_at | timestamp | INDEX, NOT NULL | When password was recorded |

**Indexes:**
- PRIMARY KEY (id)
- INDEX (user_id)
- INDEX (created_at)
- COMPOSITE INDEX (user_id, created_at)

---

## Configuration Structure

See [Phase 1.1](#11-configuration-additions-configsecurityphp) for complete configuration structure.

---

## API Reference

### PasswordSecurityService Methods

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `validatePassword` | string $password, ?User $user | array | Validate against all policies |
| `checkComplexity` | string $password | array | Check complexity requirements |
| `isInHistory` | string $password, User $user | bool | Check password history |
| `recordPassword` | string $hash, User $user | void | Record password in history |
| `isExpired` | User $user | bool | Check if password expired |
| `daysUntilExpiration` | User $user | ?int | Days until expiration |
| `isCompromised` | string $password | bool | Check HIBP breach database |
| `calculateStrength` | string $password, array $inputs | array | Calculate strength score |
| `pruneHistory` | User $user | int | Remove old history records |

### Validation Rules

| Rule | Usage | Description |
|------|-------|-------------|
| `PasswordComplexity` | `new PasswordComplexity($user)` | Validates complexity requirements |
| `PasswordHistory` | `new PasswordHistory($user)` | Prevents password reuse |
| `NotCompromised` | `new NotCompromised($threshold)` | Checks HIBP database |

### Events

| Event | Payload | Description |
|-------|---------|-------------|
| `PasswordChanged` | user, changed_at | Fired when password is changed |
| `PasswordExpired` | user, expired_at | Fired when password expires |
| `CompromisedPasswordDetected` | user, occurrences | Fired when breach detected |

---

## Testing Strategy

### Unit Tests

1. **PasswordComplexityTest**
   - Test minimum length validation
   - Test maximum length validation
   - Test uppercase requirement
   - Test lowercase requirement
   - Test number requirement
   - Test symbol requirement
   - Test unique character requirement
   - Test repeating character detection
   - Test sequential character detection
   - Test user attribute detection
   - Test configuration overrides

2. **PasswordHistoryTest**
   - Test password not in history passes
   - Test password in history fails
   - Test with empty history
   - Test history count limit
   - Test disabled history passes all

3. **NotCompromisedTest**
   - Test uncompromised password passes
   - Test compromised password fails
   - Test threshold configuration
   - Test API failure handling
   - Test caching behavior

4. **PasswordSecurityServiceTest**
   - Test full validation pipeline
   - Test strength calculation
   - Test expiration checking
   - Test history management

### Feature Tests

1. **PasswordExpirationTest**
   - Test expired password redirect
   - Test grace login countdown
   - Test expiration warning
   - Test exempt roles

2. **PasswordChangeMiddlewareTest**
   - Test force password change
   - Test normal flow
   - Test exempt routes

3. **BreachCheckingTest**
   - Test registration with compromised password
   - Test password change with compromised password
   - Test API timeout handling

### Integration Tests

1. **FullPasswordFlowTest**
   - Test registration with all policies
   - Test password change with history
   - Test expiration lifecycle

---

## Documentation Requirements

### User Documentation

1. **Installation Guide**
   - Migration commands
   - Configuration options
   - User model setup

2. **Configuration Guide**
   - All configuration options explained
   - Environment variables
   - Recommended settings

3. **Usage Guide**
   - Applying traits to User model
   - Using validation rules
   - Customizing middleware

4. **Livewire Component Guide**
   - Including strength meter
   - Customizing appearance
   - JavaScript integration

### API Documentation

1. **Service Methods**
2. **Validation Rules**
3. **Events**
4. **Middleware**

---

## Acceptance Criteria Checklist

- [ ] **Password complexity validation rules**
  - [ ] Configurable minimum/maximum length
  - [ ] Uppercase/lowercase requirements
  - [ ] Number and symbol requirements
  - [ ] Unique character requirements
  - [ ] Sequential/repeating character detection
  - [ ] User attribute detection

- [ ] **Password history tracking**
  - [ ] Database migration for history table
  - [ ] HasPasswordHistory trait
  - [ ] Configurable history count
  - [ ] PasswordHistory validation rule
  - [ ] Automatic pruning

- [ ] **Password expiration policies**
  - [ ] User table migration for expiration columns
  - [ ] Configurable expiration days
  - [ ] Warning period before expiration
  - [ ] Grace login support
  - [ ] Role-based exemptions
  - [ ] RequirePasswordChange middleware

- [ ] **Password strength meter component**
  - [ ] Livewire component implementation
  - [ ] Real-time strength calculation
  - [ ] Visual strength indicator
  - [ ] Requirements checklist
  - [ ] Crack time display
  - [ ] Feedback suggestions

- [ ] **Password breach checking (HaveIBeenPwned)**
  - [ ] k-Anonymity API integration
  - [ ] Result caching
  - [ ] Configurable timeout
  - [ ] NotCompromised validation rule
  - [ ] Graceful API failure handling

- [ ] **Password policy enforcement**
  - [ ] EnforcePasswordPolicy middleware
  - [ ] PasswordSecurityService
  - [ ] Security event logging
  - [ ] JSON API support

- [ ] **Documentation**
  - [ ] Installation guide
  - [ ] Configuration reference
  - [ ] Usage examples
  - [ ] API documentation
  - [ ] Troubleshooting guide

---

## Implementation Order

1. **Week 1: Core Infrastructure**
   - Configuration structure
   - Contracts/Interfaces
   - Database migrations
   - Basic service scaffolding

2. **Week 2: Password History & Complexity**
   - PasswordHistory model
   - HasPasswordHistory trait
   - PasswordComplexity rule
   - PasswordHistory rule
   - Unit tests

3. **Week 3: Expiration & Breach Checking**
   - Expiration logic in trait
   - RequirePasswordChange middleware
   - HaveIBeenPwnedService
   - NotCompromised rule
   - Integration tests

4. **Week 4: UI & Polish**
   - PasswordStrengthMeter component
   - Blade views
   - EnforcePasswordPolicy middleware
   - Documentation
   - Final testing

---

*Document Version: 1.0*
*Created: December 2024*
*Package: ArtisanPack Security*
