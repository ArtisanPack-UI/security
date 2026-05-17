---
title: Session Security Guide
---

# Session Security Guide

This guide covers advanced session security features including session binding, concurrent session management, session rotation, timeouts, and hijacking detection.

## Overview

The ArtisanPack Security package provides comprehensive session security through:

- **Session Binding**: Tie sessions to specific client attributes (IP, user agent, device)
- **Concurrent Session Management**: Limit simultaneous active sessions
- **Session Rotation**: Automatically rotate session IDs
- **Session Timeouts**: Configure idle and absolute timeouts
- **Hijacking Detection**: Detect and respond to session hijacking attempts

## Configuration

Configure session security in `config/artisanpack/security.php`:

```php
'advanced_sessions' => [
    'enabled' => env('SECURITY_ADVANCED_SESSIONS_ENABLED', true),

    'binding' => [
        'enabled' => true,
        'ip_address' => [
            'enabled' => true,
            'strictness' => 'subnet',  // 'none', 'subnet', 'exact'
        ],
        'user_agent' => [
            'enabled' => true,
            'strictness' => 'exact',   // 'none', 'browser_only', 'exact'
        ],
        'bind_to_device' => true,      // Requires device fingerprinting
    ],

    'concurrent_sessions' => [
        'enabled' => true,
        'max_sessions' => 5,
        'strategy' => 'oldest',        // 'oldest', 'newest'
    ],

    'rotation' => [
        'enabled' => true,
        'interval_minutes' => 15,
        'on_privilege_change' => true,
    ],

    'timeouts' => [
        'idle_minutes' => 30,
        'idle_warning_minutes' => 25,
        'absolute_minutes' => 480,     // 8 hours
        'extend_on_activity' => true,
    ],

    'hijacking_detection' => [
        'enabled' => true,
        'action' => 'terminate',       // 'terminate', 'require_reauth', 'notify'
    ],
],
```

## Session Encryption

### Enforcing Encrypted Sessions

The package can enforce session encryption in production:

```php
// In config/artisanpack/security.php
'encrypt' => env('SESSION_ENCRYPT', true),
```

Apply the middleware to routes:

```php
Route::middleware(['auth', 'session.encrypted'])->group(function () {
    // These routes require encrypted sessions
});
```

### Checking Session Encryption

```bash
php artisan security:check-session
```

This command verifies:
- Session encryption is enabled
- Session driver is secure (not `file` in production)
- Cookie settings are secure

## Session Binding

Session binding ties a session to specific client attributes, preventing session hijacking by token theft.

### IP Address Binding

```php
'ip_address' => [
    'enabled' => true,
    'strictness' => 'subnet',  // Options below
],
```

**Strictness Levels:**

| Level | Description | Use Case |
|-------|-------------|----------|
| `none` | No IP binding | Mobile users, VPN users |
| `subnet` | Same /24 subnet required | Balance of security and usability |
| `exact` | Exact IP match required | High security environments |

### User Agent Binding

```php
'user_agent' => [
    'enabled' => true,
    'strictness' => 'exact',
],
```

**Strictness Levels:**

| Level | Description | Use Case |
|-------|-------------|----------|
| `none` | No UA binding | Maximum compatibility |
| `browser_only` | Browser name must match | Allows minor version updates |
| `exact` | Exact UA string required | High security |

### Device Binding

When device fingerprinting is enabled, sessions can be bound to specific devices:

```php
'bind_to_device' => true,
```

This requires the `HasDevices` trait on your User model and device fingerprint collection during login.

### Applying Session Binding

```php
Route::middleware(['auth', 'session.binding'])->group(function () {
    Route::get('/dashboard', [DashboardController::class, 'index']);
});
```

### Handling Binding Violations

When a binding violation is detected:

```php
use ArtisanPackUI\Security\Events\SessionHijackingAttempted;

Event::listen(SessionHijackingAttempted::class, function ($event) {
    Log::warning('Session binding violation', [
        'user_id' => $event->userId,
        'session_id' => $event->sessionId,
        'violation_type' => $event->violationType,
        'expected' => $event->expectedValue,
        'actual' => $event->actualValue,
    ]);
});
```

## Concurrent Session Management

Limit the number of simultaneous active sessions per user.

### Configuration

```php
'concurrent_sessions' => [
    'enabled' => true,
    'max_sessions' => 5,
    'strategy' => 'oldest',
],
```

**Strategies:**

| Strategy | Behavior |
|----------|----------|
| `oldest` | Terminate the oldest session when limit reached |
| `newest` | Prevent new login, keep existing sessions |

### User Model Setup

```php
use ArtisanPackUI\Security\Concerns\HasAdvancedSessions;

class User extends Authenticatable
{
    use HasAdvancedSessions;
}
```

### Managing Sessions Programmatically

```php
// Get all active sessions for a user
$sessions = $user->activeSessions();

// Get session details
foreach ($sessions as $session) {
    echo $session->ip_address;
    echo $session->user_agent;
    echo $session->last_activity;
    echo $session->getLocationDisplay();  // "San Francisco, US"
}

// Terminate a specific session
$user->terminateSession($sessionId);

// Terminate all other sessions (keep current)
$user->terminateOtherSessions();

// Terminate all sessions
$user->terminateAllSessions();
```

### Session Management Commands

```bash
# Terminate all sessions for a user
php artisan session:terminate 1

# Terminate sessions by email
php artisan session:terminate user@example.com

# Terminate all sessions except current
php artisan session:terminate 1 --except-current

# Clean up expired sessions
php artisan session:cleanup
```

### Livewire Component

Display and manage sessions in the UI:

```blade
<livewire:session-manager />
```

This component shows:
- Active sessions with device/location info
- Current session indicator
- Ability to terminate individual sessions
- Terminate all other sessions button

## Session Rotation

Automatic session ID rotation prevents session fixation attacks.

### Configuration

```php
'rotation' => [
    'enabled' => true,
    'interval_minutes' => 15,      // Rotate every 15 minutes
    'on_privilege_change' => true, // Rotate after login, role change, etc.
],
```

### Manual Rotation

```php
use ArtisanPackUI\Security\Authentication\Session\SessionSecurityService;

public function sensitiveAction(SessionSecurityService $sessionService)
{
    // Rotate session before sensitive action
    $sessionService->rotateSession();

    // Perform action...
}
```

### Rotation Triggers

Sessions are automatically rotated on:

- Login (always)
- Password change
- Role/permission changes
- Two-factor authentication
- Privilege escalation
- Time-based interval

## Session Timeouts

Configure idle and absolute session timeouts.

### Configuration

```php
'timeouts' => [
    'idle_minutes' => 30,           // Expire after 30 min of inactivity
    'idle_warning_minutes' => 25,   // Warn 5 minutes before expiry
    'absolute_minutes' => 480,      // Max 8-hour session
    'extend_on_activity' => true,   // Reset idle timer on activity
],
```

### Idle Timeout Warning

Show a warning before the session expires:

```javascript
// Listen for the warning event
window.addEventListener('session-expiring', (event) => {
    const minutesLeft = event.detail.minutes;
    showModal(`Your session expires in ${minutesLeft} minutes. Continue?`);
});

// Extend session on user action
async function extendSession() {
    await fetch('/session/extend', { method: 'POST' });
}
```

Server-side endpoint:

```php
Route::post('/session/extend', function () {
    session()->regenerate();
    return response()->json(['extended' => true]);
})->middleware('auth');
```

### Absolute Timeout

The absolute timeout ensures sessions don't last indefinitely, even with activity:

```php
// In a middleware or listener
if ($session->created_at->diffInMinutes(now()) > 480) {
    Auth::logout();
    return redirect('/login')->with('message', 'Session expired. Please log in again.');
}
```

## Hijacking Detection

Detect and respond to potential session hijacking attempts.

### Configuration

```php
'hijacking_detection' => [
    'enabled' => true,
    'action' => 'terminate',
],
```

**Actions:**

| Action | Behavior |
|--------|----------|
| `terminate` | Immediately terminate the session |
| `require_reauth` | Require password/2FA verification |
| `notify` | Log and notify but allow access |

### Detection Triggers

The system monitors for:

- IP address changes (based on binding strictness)
- User agent changes
- Device fingerprint changes
- Impossible travel (login from distant location too quickly)
- Concurrent access from multiple IPs

### Custom Hijacking Response

```php
use ArtisanPackUI\Security\Events\SessionHijackingAttempted;

Event::listen(SessionHijackingAttempted::class, function ($event) {
    // Custom response logic
    if ($event->severity === 'critical') {
        // Lock the account
        $event->user->lockAccount('suspicious_activity');

        // Alert security team
        Notification::route('slack', config('services.slack.security_channel'))
            ->notify(new SecurityAlertNotification($event));
    }
});
```

## Step-Up Authentication

Require re-authentication for sensitive actions.

### Configuration

```php
'step_up_authentication' => [
    'enabled' => env('SECURITY_STEP_UP_ENABLED', true),
    'timeout_minutes' => 15,

    'methods' => [
        'password' => true,
        '2fa' => true,
        'webauthn' => true,
        'biometric' => true,
    ],

    'protected_actions' => [
        'password_change',
        'email_change',
        'two_factor_disable',
        'delete_account',
    ],
],
```

### Applying Step-Up Authentication

```php
Route::middleware(['auth', 'step-up'])->group(function () {
    Route::post('/account/password', [AccountController::class, 'updatePassword']);
    Route::post('/account/email', [AccountController::class, 'updateEmail']);
    Route::delete('/account', [AccountController::class, 'destroy']);
});
```

### Programmatic Check

```php
use ArtisanPackUI\Security\Authentication\Session\SessionSecurityService;

public function sensitiveAction(SessionSecurityService $session)
{
    if (!$session->hasRecentVerification(15)) {
        return redirect()->route('verify.identity')
            ->with('intended', url()->current());
    }

    // Proceed with sensitive action
}
```

### Livewire Component

```blade
<livewire:step-up-authentication-modal />
```

## Events

The session security system emits these events:

| Event | Trigger |
|-------|---------|
| `SessionTerminated` | Session was terminated |
| `SessionHijackingAttempted` | Potential hijacking detected |
| `SessionRotated` | Session ID was rotated |
| `ConcurrentSessionLimitReached` | Max sessions reached |

## Best Practices

### Production Configuration

```php
// Recommended production settings
'advanced_sessions' => [
    'enabled' => true,

    'binding' => [
        'enabled' => true,
        'ip_address' => [
            'enabled' => true,
            'strictness' => 'subnet',  // Balance security/usability
        ],
        'user_agent' => [
            'enabled' => true,
            'strictness' => 'browser_only',  // Allow updates
        ],
        'bind_to_device' => true,
    ],

    'concurrent_sessions' => [
        'enabled' => true,
        'max_sessions' => 5,
        'strategy' => 'oldest',
    ],

    'rotation' => [
        'enabled' => true,
        'interval_minutes' => 15,
        'on_privilege_change' => true,
    ],

    'timeouts' => [
        'idle_minutes' => 30,
        'idle_warning_minutes' => 25,
        'absolute_minutes' => 480,
        'extend_on_activity' => true,
    ],

    'hijacking_detection' => [
        'enabled' => true,
        'action' => 'terminate',
    ],
],
```

### Session Driver

Use a secure session driver in production:

```env
SESSION_DRIVER=database
# or
SESSION_DRIVER=redis
```

Avoid `file` driver in production for:
- Better performance
- Easier session management
- Cross-server compatibility

### Secure Cookie Settings

```env
SESSION_SECURE_COOKIE=true
SESSION_SAME_SITE=lax
SESSION_HTTP_ONLY=true
```

## Troubleshooting

### Sessions Expiring Too Quickly

1. Check `idle_minutes` configuration
2. Verify `extend_on_activity` is enabled
3. Ensure AJAX requests include session cookies

### Binding Violations on Mobile

Mobile users may experience IP changes. Consider:

```php
'ip_address' => [
    'strictness' => 'none',  // Disable for mobile
],
```

### Too Many Session Terminations

If legitimate users are being logged out:

1. Increase `concurrent_sessions.max_sessions`
2. Relax binding strictness
3. Check for proxy/CDN IP changes

See the [Troubleshooting Guide](troubleshooting.md) for more solutions.

## Related Documentation

- [Advanced Authentication Guide](advanced-authentication.md)
- [Implementation Guide](implementation-guide.md)
- [Configuration Reference](configuration-reference.md)
