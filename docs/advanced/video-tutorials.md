---
title: Video Tutorials
---

# Video Tutorials

Step-by-step video guides for implementing security features in your Laravel application.

## Getting Started Series

### 1. Installation & Setup

**Duration**: 15 minutes

Learn how to install and configure the ArtisanPack Security package in a fresh Laravel application.

**Topics Covered**:
- Installing via Composer
- Publishing configuration files
- Running migrations
- Basic configuration overview
- Verifying installation

**What You'll Build**:
A Laravel application with the security package installed and basic configuration complete.

**Prerequisites**:
- Laravel 10.x or 11.x application
- Composer installed
- Basic Laravel knowledge

**Code Along**:

```bash
# Install the package
composer require artisanpackui/security

# Publish configuration
php artisan vendor:publish --provider="ArtisanPackUI\Security\SecurityServiceProvider"

# Run migrations
php artisan migrate

# Verify installation
php artisan security:check-config
```

---

### 2. Configuring Your User Model

**Duration**: 10 minutes

Add the required traits to your User model to enable security features.

**Topics Covered**:
- Understanding available traits
- Adding traits based on features needed
- Trait dependencies
- Testing trait functionality

**What You'll Build**:
A User model configured with core security traits.

**Code Along**:

```php
<?php

namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use ArtisanPackUI\Security\TwoFactor\TwoFactorAuthenticatable;
use ArtisanPackUI\Security\Concerns\HasRoles;
use ArtisanPackUI\Security\Concerns\HasApiTokens;
use ArtisanPackUI\Security\Concerns\HasPasswordHistory;

class User extends Authenticatable
{
    use TwoFactorAuthenticatable;
    use HasRoles;
    use HasApiTokens;
    use HasPasswordHistory;

    // Your existing code...
}
```

---

### 3. Registering Middleware

**Duration**: 12 minutes

Configure security middleware for your routes.

**Topics Covered**:
- Available middleware aliases
- Applying middleware to routes
- Middleware groups
- Testing middleware

**What You'll Build**:
Protected routes with security middleware applied.

---

## Authentication Series

### 4. Implementing Two-Factor Authentication

**Duration**: 25 minutes

Add TOTP-based two-factor authentication to your application.

**Topics Covered**:
- Enabling 2FA in configuration
- Creating setup flow UI
- QR code generation
- Code verification
- Recovery codes
- Testing 2FA flow

**What You'll Build**:
Complete 2FA setup and challenge flow.

**Code Along**:

```php
// Enable 2FA for a user
use ArtisanPackUI\Security\Facades\TwoFactor;

$recoveryCodes = TwoFactor::enable($user);

// Verify a code
$valid = TwoFactor::verify($user, $code);
```

---

### 5. Social Login Integration

**Duration**: 20 minutes

Add Google, GitHub, and other social login providers.

**Topics Covered**:
- Configuring OAuth providers
- Setting up callback routes
- Handling authentication
- Linking accounts
- Error handling

**What You'll Build**:
Login with Google and GitHub buttons.

**Code Along**:

```env
# .env configuration
SECURITY_SOCIAL_AUTH_ENABLED=true
SECURITY_SOCIAL_GOOGLE_ENABLED=true
GOOGLE_CLIENT_ID=your-client-id
GOOGLE_CLIENT_SECRET=your-client-secret
```

---

### 6. WebAuthn/Passkey Authentication

**Duration**: 30 minutes

Implement passwordless authentication with hardware security keys.

**Topics Covered**:
- WebAuthn overview
- Configuration
- Registration flow
- Authentication flow
- Browser support
- Fallback handling

**What You'll Build**:
Passwordless login with passkeys.

---

### 7. SSO with SAML 2.0

**Duration**: 35 minutes

Integrate with enterprise identity providers using SAML.

**Topics Covered**:
- SAML concepts
- IDP configuration
- SP configuration
- Attribute mapping
- Testing with a test IDP
- Troubleshooting

**What You'll Build**:
SAML SSO integration with Azure AD or Okta.

---

## Authorization Series

### 8. Role-Based Access Control

**Duration**: 25 minutes

Implement roles and permissions for your application.

**Topics Covered**:
- Creating roles
- Creating permissions
- Assigning permissions to roles
- Assigning roles to users
- Checking permissions
- Blade directives

**What You'll Build**:
Admin, editor, and user role hierarchy.

**Code Along**:

```php
// Create roles
$admin = Role::create(['name' => 'admin']);
$editor = Role::create(['name' => 'editor']);

// Create permissions
$manageUsers = Permission::create(['name' => 'manage-users']);
$editContent = Permission::create(['name' => 'edit-content']);

// Assign permissions
$admin->permissions()->attach([$manageUsers->id, $editContent->id]);
$editor->permissions()->attach($editContent->id);

// Assign role to user
$user->assignRole('admin');

// Check permission
if ($user->hasPermission('manage-users')) {
    // ...
}
```

---

### 9. API Token Management

**Duration**: 20 minutes

Create and manage API tokens with abilities.

**Topics Covered**:
- Token creation
- Token abilities
- Rate limiting
- Token revocation
- Testing API authentication

**What You'll Build**:
API with token-based authentication.

---

## Security Features Series

### 10. Content Security Policy

**Duration**: 25 minutes

Implement CSP to prevent XSS attacks.

**Topics Covered**:
- CSP concepts
- Configuration
- Nonces for inline scripts
- Report-only mode
- Violation reporting
- Common configurations

**What You'll Build**:
Strict CSP with nonce support.

**Code Along**:

```blade
{{-- Using nonces --}}
<script nonce="{{ cspNonce() }}">
    console.log('This script is allowed');
</script>
```

---

### 11. Secure File Uploads

**Duration**: 30 minutes

Implement secure file upload handling.

**Topics Covered**:
- Configuration
- Validation rules
- MIME type checking
- Malware scanning
- Secure storage
- Signed URLs

**What You'll Build**:
Secure document upload system.

---

### 12. Session Security

**Duration**: 20 minutes

Implement advanced session security features.

**Topics Covered**:
- Session binding
- Concurrent sessions
- Session rotation
- Timeouts
- Hijacking detection

**What You'll Build**:
Session management dashboard.

---

## Compliance Series

### 13. GDPR Compliance

**Duration**: 30 minutes

Implement GDPR features for EU compliance.

**Topics Covered**:
- Data export
- Right to erasure
- Consent management
- Audit logging
- Data retention

**What You'll Build**:
Privacy dashboard for users.

---

### 14. Security Monitoring Dashboard

**Duration**: 25 minutes

Set up monitoring and alerting.

**Topics Covered**:
- Metrics collection
- Security dashboard
- Alert configuration
- Threat detection
- Reporting

**What You'll Build**:
Admin security dashboard.

---

## Testing Series

### 15. Testing Security Features

**Duration**: 20 minutes

Write tests for your security implementation.

**Topics Covered**:
- Test traits
- Authentication testing
- Authorization testing
- 2FA testing
- Mock services

**What You'll Build**:
Comprehensive security test suite.

---

## Quick Tutorials

### Password Strength Meter

**Duration**: 5 minutes

Add real-time password strength feedback.

```blade
<livewire:password-strength-meter />
```

---

### Security Headers Check

**Duration**: 5 minutes

Test your application's security headers.

```bash
php artisan security:test-headers https://yourapp.com --verbose
```

---

### Audit Log Viewer

**Duration**: 8 minutes

Add an audit log viewer to your admin panel.

```blade
<livewire:audit-log-viewer :user="$user" />
```

---

### Session Manager Component

**Duration**: 8 minutes

Let users manage their active sessions.

```blade
<livewire:session-manager />
```

---

## Workshop: Building a Secure Application

### Full Workshop (2 hours)

Build a complete secure application from scratch.

**Part 1: Setup (20 min)**
- New Laravel project
- Package installation
- Basic configuration

**Part 2: Authentication (30 min)**
- User registration with password policy
- Two-factor authentication
- Social login

**Part 3: Authorization (20 min)**
- Roles and permissions
- Protected routes
- Admin panel

**Part 4: Security Features (30 min)**
- CSP configuration
- Security headers
- File upload security

**Part 5: Monitoring & Compliance (20 min)**
- Security dashboard
- Audit logging
- GDPR features

**Final Result**:
Production-ready secure application.

---

## Tips for Following Along

### Development Environment

For the best experience:
- Use Laravel Sail or Herd for local development
- Have a fresh Laravel installation ready
- Use VS Code with Laravel extensions

### Code Repository

Each tutorial has an accompanying code repository:
- Starting point for each video
- Completed code for reference
- Additional examples

### Common Issues

If you get stuck:
1. Check the [Troubleshooting Guide](troubleshooting.md)
2. Review the [FAQ](faq.md)
3. Compare with the completed code
4. Ask in the community forum

---

## Request a Tutorial

Have a topic you'd like covered? We welcome suggestions for new tutorials.

**Popular Requests**:
- Integration with specific frameworks (Filament, Nova)
- Enterprise SSO configurations
- Custom authentication providers
- Advanced threat detection

---

## Related Documentation

- [Implementation Guide](implementation-guide.md)
- [Configuration Reference](configuration-reference.md)
- [FAQ](faq.md)
