---
title: Security Testing Guide
---

# Security Testing Guide

This guide covers testing security features including PHPUnit helpers, test traits, penetration testing support, vulnerability scanning, and CI/CD integration.

## Overview

The ArtisanPack Security package provides comprehensive testing support:

- **Test Traits**: Helpers for testing authentication, authorization, and security features
- **Security Assertions**: Custom PHPUnit assertions for security testing
- **Mock Services**: Mock implementations for external security services
- **Penetration Testing**: Built-in support for security scanning
- **CI/CD Integration**: Commands for automated security testing

## Test Setup

### Installing Test Dependencies

```bash
composer require --dev artisanpackui/security-testing
```

### Base Test Case

```php
<?php

namespace Tests;

use ArtisanPackUI\Security\Testing\SecurityTestCase;

abstract class TestCase extends SecurityTestCase
{
    use CreatesApplication;
}
```

Or use individual traits:

```php
use ArtisanPackUI\Security\Testing\Traits\InteractsWithAuthentication;
use ArtisanPackUI\Security\Testing\Traits\InteractsWithRoles;
use ArtisanPackUI\Security\Testing\Traits\InteractsWithTwoFactor;
use ArtisanPackUI\Security\Testing\Traits\SecurityAssertions;

class MyTest extends TestCase
{
    use InteractsWithAuthentication;
    use InteractsWithRoles;
    use InteractsWithTwoFactor;
    use SecurityAssertions;
}
```

## Authentication Testing

### Testing Login

```php
use ArtisanPackUI\Security\Testing\Traits\InteractsWithAuthentication;

class AuthenticationTest extends TestCase
{
    use InteractsWithAuthentication;

    public function test_user_can_login_with_valid_credentials()
    {
        $user = User::factory()->create([
            'password' => bcrypt('password'),
        ]);

        $response = $this->attemptLogin([
            'email' => $user->email,
            'password' => 'password',
        ]);

        $response->assertRedirect('/dashboard');
        $this->assertAuthenticated();
    }

    public function test_login_fails_with_invalid_credentials()
    {
        $user = User::factory()->create();

        $response = $this->attemptLogin([
            'email' => $user->email,
            'password' => 'wrong-password',
        ]);

        $response->assertSessionHasErrors('email');
        $this->assertGuest();
    }

    public function test_login_is_rate_limited()
    {
        $user = User::factory()->create();

        // Attempt login multiple times
        for ($i = 0; $i < 6; $i++) {
            $this->attemptLogin([
                'email' => $user->email,
                'password' => 'wrong-password',
            ]);
        }

        $response = $this->attemptLogin([
            'email' => $user->email,
            'password' => 'wrong-password',
        ]);

        $response->assertStatus(429);
    }
}
```

### Testing Account Lockout

```php
public function test_account_locks_after_failed_attempts()
{
    $user = User::factory()->create();

    // Configure lockout threshold
    config(['artisanpack.security.authentication.lockout.threshold' => 5]);

    // Fail 5 login attempts
    $this->failLoginAttempts($user, 5);

    // Verify account is locked
    $this->assertAccountLocked($user);

    // Even correct password should fail
    $response = $this->attemptLogin([
        'email' => $user->email,
        'password' => 'password',
    ]);

    $response->assertSessionHasErrors();
}

public function test_account_unlocks_after_timeout()
{
    $user = User::factory()->create();

    $this->lockAccount($user);
    $this->assertAccountLocked($user);

    // Travel forward in time
    $this->travel(31)->minutes();

    $this->assertAccountNotLocked($user);
}
```

## Two-Factor Authentication Testing

### Testing 2FA Setup

```php
use ArtisanPackUI\Security\Testing\Traits\InteractsWithTwoFactor;

class TwoFactorTest extends TestCase
{
    use InteractsWithTwoFactor;

    public function test_user_can_enable_two_factor()
    {
        $user = User::factory()->create();
        $this->actingAs($user);

        $response = $this->enableTwoFactor($user);

        $response->assertOk();
        $this->assertTwoFactorEnabled($user);
        $this->assertRecoveryCodesGenerated($user);
    }

    public function test_two_factor_challenge_required_after_login()
    {
        $user = User::factory()->create();
        $this->enableTwoFactorFor($user);

        $response = $this->attemptLogin([
            'email' => $user->email,
            'password' => 'password',
        ]);

        $response->assertRedirect('/two-factor/challenge');
        $this->assertTwoFactorChallengeRequired();
    }

    public function test_valid_two_factor_code_authenticates()
    {
        $user = User::factory()->create();
        $this->enableTwoFactorFor($user);
        $this->attemptLogin([
            'email' => $user->email,
            'password' => 'password',
        ]);

        $code = $this->generateValidTwoFactorCode($user);

        $response = $this->submitTwoFactorCode($code);

        $response->assertRedirect('/dashboard');
        $this->assertAuthenticated();
    }

    public function test_recovery_code_works_when_code_unavailable()
    {
        $user = User::factory()->create();
        $codes = $this->enableTwoFactorFor($user);
        $this->attemptLogin([
            'email' => $user->email,
            'password' => 'password',
        ]);

        $response = $this->submitRecoveryCode($codes[0]);

        $response->assertRedirect('/dashboard');
        $this->assertAuthenticated();
        $this->assertRecoveryCodeUsed($user, $codes[0]);
    }
}
```

### Testing TOTP Codes

```php
public function test_expired_totp_code_is_rejected()
{
    $user = User::factory()->create();
    $this->enableTwoFactorFor($user);

    // Generate code from 5 minutes ago
    $expiredCode = $this->generateTwoFactorCode($user, now()->subMinutes(5));

    $response = $this->submitTwoFactorCode($expiredCode);

    $response->assertSessionHasErrors('code');
}
```

## Role and Permission Testing

### Testing RBAC

```php
use ArtisanPackUI\Security\Testing\Traits\InteractsWithRoles;

class RoleTest extends TestCase
{
    use InteractsWithRoles;

    public function test_user_with_permission_can_access_resource()
    {
        $user = User::factory()->create();
        $this->givePermission($user, 'edit-posts');

        $this->actingAs($user);

        $response = $this->get('/posts/1/edit');

        $response->assertOk();
    }

    public function test_user_without_permission_is_denied()
    {
        $user = User::factory()->create();

        $this->actingAs($user);

        $response = $this->get('/posts/1/edit');

        $response->assertForbidden();
    }

    public function test_role_grants_permissions()
    {
        $user = User::factory()->create();
        $this->assignRole($user, 'editor');

        $this->assertTrue($user->hasPermission('edit-posts'));
        $this->assertTrue($user->hasPermission('publish-posts'));
    }

    public function test_super_admin_has_all_permissions()
    {
        $user = User::factory()->create();
        $this->assignRole($user, 'super-admin');

        $this->assertTrue($user->hasPermission('any-permission'));
        $this->assertTrue($user->can('anything'));
    }
}
```

### Testing Permission Middleware

```php
public function test_permission_middleware_blocks_unauthorized()
{
    $user = User::factory()->create();
    $this->actingAs($user);

    $response = $this->get('/admin/users');

    $response->assertForbidden();
}

public function test_permission_middleware_allows_authorized()
{
    $user = User::factory()->create();
    $this->givePermission($user, 'manage-users');
    $this->actingAs($user);

    $response = $this->get('/admin/users');

    $response->assertOk();
}
```

## API Token Testing

### Testing Token Authentication

```php
use ArtisanPackUI\Security\Testing\Traits\InteractsWithApiTokens;

class ApiTokenTest extends TestCase
{
    use InteractsWithApiTokens;

    public function test_valid_token_authenticates()
    {
        $user = User::factory()->create();
        $token = $this->createTokenFor($user, 'test-token');

        $response = $this->withToken($token->plainTextToken)
            ->getJson('/api/user');

        $response->assertOk();
        $response->assertJson(['id' => $user->id]);
    }

    public function test_expired_token_is_rejected()
    {
        $user = User::factory()->create();
        $token = $this->createExpiredTokenFor($user);

        $response = $this->withToken($token->plainTextToken)
            ->getJson('/api/user');

        $response->assertUnauthorized();
    }

    public function test_token_abilities_are_enforced()
    {
        $user = User::factory()->create();
        $token = $this->createTokenFor($user, 'read-only', ['read']);

        // Read should work
        $response = $this->withToken($token->plainTextToken)
            ->getJson('/api/posts');
        $response->assertOk();

        // Write should fail
        $response = $this->withToken($token->plainTextToken)
            ->postJson('/api/posts', ['title' => 'Test']);
        $response->assertForbidden();
    }

    public function test_revoked_token_is_rejected()
    {
        $user = User::factory()->create();
        $token = $this->createTokenFor($user, 'test-token');

        $this->revokeToken($token);

        $response = $this->withToken($token->plainTextToken)
            ->getJson('/api/user');

        $response->assertUnauthorized();
    }
}
```

## Session Security Testing

### Testing Session Binding

```php
use ArtisanPackUI\Security\Testing\Traits\InteractsWithSessions;

class SessionSecurityTest extends TestCase
{
    use InteractsWithSessions;

    public function test_session_is_bound_to_ip()
    {
        config(['artisanpack.security.advanced_sessions.binding.ip_address.enabled' => true]);

        $user = User::factory()->create();
        $this->actingAs($user);

        // Make request from different IP
        $response = $this->withServerVariables(['REMOTE_ADDR' => '192.168.1.100'])
            ->get('/dashboard');

        $response->assertRedirect('/login');
    }

    public function test_session_rotation_occurs_on_privilege_change()
    {
        $user = User::factory()->create();
        $this->actingAs($user);

        $originalSessionId = session()->getId();

        // Change role (privilege change)
        $user->assignRole('admin');

        $this->assertNotEquals($originalSessionId, session()->getId());
    }

    public function test_concurrent_sessions_are_limited()
    {
        config(['artisanpack.security.advanced_sessions.concurrent_sessions.max_sessions' => 2]);

        $user = User::factory()->create();

        // Create 2 sessions
        $session1 = $this->createSessionFor($user);
        $session2 = $this->createSessionFor($user);

        // Third session should terminate oldest
        $session3 = $this->createSessionFor($user);

        $this->assertSessionTerminated($session1);
        $this->assertSessionActive($session2);
        $this->assertSessionActive($session3);
    }
}
```

## File Upload Security Testing

### Testing Upload Validation

```php
use ArtisanPackUI\Security\Testing\Traits\InteractsWithFileUploads;
use Illuminate\Http\UploadedFile;

class FileUploadSecurityTest extends TestCase
{
    use InteractsWithFileUploads;

    public function test_valid_file_is_accepted()
    {
        $user = User::factory()->create();
        $this->actingAs($user);

        $file = UploadedFile::fake()->image('photo.jpg');

        $response = $this->postJson('/api/upload', [
            'file' => $file,
        ]);

        $response->assertOk();
    }

    public function test_php_file_is_rejected()
    {
        $user = User::factory()->create();
        $this->actingAs($user);

        $file = $this->createMaliciousFile('malware.php', '<?php system($_GET["cmd"]); ?>');

        $response = $this->postJson('/api/upload', [
            'file' => $file,
        ]);

        $response->assertStatus(422);
        $response->assertJsonValidationErrors('file');
    }

    public function test_double_extension_is_rejected()
    {
        $user = User::factory()->create();
        $this->actingAs($user);

        $file = $this->createFileWithDoubleExtension('image.jpg.php');

        $response = $this->postJson('/api/upload', [
            'file' => $file,
        ]);

        $response->assertStatus(422);
    }

    public function test_spoofed_mime_type_is_detected()
    {
        $user = User::factory()->create();
        $this->actingAs($user);

        // PHP file disguised as image
        $file = $this->createSpoofedFile(
            filename: 'image.jpg',
            actualContent: '<?php echo "malicious"; ?>',
            fakeMimeType: 'image/jpeg'
        );

        $response = $this->postJson('/api/upload', [
            'file' => $file,
        ]);

        $response->assertStatus(422);
    }

    public function test_oversized_file_is_rejected()
    {
        $user = User::factory()->create();
        $this->actingAs($user);

        $file = UploadedFile::fake()->create('large.pdf', 50000); // 50MB

        $response = $this->postJson('/api/upload', [
            'file' => $file,
        ]);

        $response->assertStatus(422);
    }
}
```

### Testing Malware Scanning

```php
public function test_malware_is_detected()
{
    $this->mockMalwareScanner();

    $user = User::factory()->create();
    $this->actingAs($user);

    $file = $this->createFileWithEicar(); // EICAR test file

    $response = $this->postJson('/api/upload', [
        'file' => $file,
    ]);

    $response->assertStatus(422);
    $this->assertMalwareDetected();
}
```

## Security Header Testing

### Testing CSP

```php
use ArtisanPackUI\Security\Testing\Traits\SecurityAssertions;

class SecurityHeaderTest extends TestCase
{
    use SecurityAssertions;

    public function test_csp_header_is_present()
    {
        $response = $this->get('/');

        $this->assertHasSecurityHeader($response, 'Content-Security-Policy');
    }

    public function test_csp_blocks_inline_scripts()
    {
        $response = $this->get('/');

        $this->assertCspBlocksInlineScripts($response);
    }

    public function test_xss_protection_header_present()
    {
        $response = $this->get('/');

        $this->assertHasSecurityHeader($response, 'X-XSS-Protection', '1; mode=block');
    }

    public function test_hsts_header_in_production()
    {
        $this->app['env'] = 'production';

        $response = $this->get('/');

        $this->assertHasSecurityHeader($response, 'Strict-Transport-Security');
    }

    public function test_all_security_headers_present()
    {
        $response = $this->get('/');

        $this->assertSecurityHeaders($response, [
            'X-Frame-Options' => 'SAMEORIGIN',
            'X-Content-Type-Options' => 'nosniff',
            'X-XSS-Protection' => '1; mode=block',
            'Referrer-Policy' => 'strict-origin-when-cross-origin',
        ]);
    }
}
```

## Custom Security Assertions

### Available Assertions

```php
// Authentication
$this->assertAuthenticated();
$this->assertGuest();
$this->assertAuthenticatedAs($user);
$this->assertTwoFactorChallengeRequired();

// Account Status
$this->assertAccountLocked($user);
$this->assertAccountNotLocked($user);
$this->assertPasswordExpired($user);

// Two-Factor
$this->assertTwoFactorEnabled($user);
$this->assertTwoFactorDisabled($user);
$this->assertRecoveryCodesGenerated($user);
$this->assertRecoveryCodeUsed($user, $code);

// Roles and Permissions
$this->assertUserHasRole($user, 'admin');
$this->assertUserHasPermission($user, 'edit-posts');
$this->assertUserDoesNotHavePermission($user, 'delete-posts');

// Sessions
$this->assertSessionActive($session);
$this->assertSessionTerminated($session);
$this->assertSessionCount($user, 2);

// Security Headers
$this->assertHasSecurityHeader($response, 'X-Frame-Options');
$this->assertCspContains($response, 'script-src', "'self'");

// File Security
$this->assertFileQuarantined($file);
$this->assertMalwareDetected();

// API Tokens
$this->assertTokenValid($token);
$this->assertTokenExpired($token);
$this->assertTokenHasAbility($token, 'read');
```

## Mock Services

### Mocking External Services

```php
use ArtisanPackUI\Security\Testing\Mocks\MockHaveIBeenPwnedService;
use ArtisanPackUI\Security\Testing\Mocks\MockMalwareScanner;
use ArtisanPackUI\Security\Testing\Mocks\MockGeoIpService;

class SecurityServiceTest extends TestCase
{
    public function test_breached_password_is_rejected()
    {
        // Mock HIBP to always return breached
        $this->mockHibp()->alwaysBreached();

        $response = $this->post('/register', [
            'email' => 'test@example.com',
            'password' => 'password123',
            'password_confirmation' => 'password123',
        ]);

        $response->assertSessionHasErrors('password');
    }

    public function test_handles_hibp_service_failure()
    {
        // Mock HIBP to fail
        $this->mockHibp()->alwaysFails();

        // Should still allow registration (fail open or fail closed based on config)
        $response = $this->post('/register', [
            'email' => 'test@example.com',
            'password' => 'securePassword123!',
            'password_confirmation' => 'securePassword123!',
        ]);

        // Depends on configuration
        $response->assertRedirect();
    }

    protected function mockHibp()
    {
        return $this->mock(MockHaveIBeenPwnedService::class);
    }
}
```

### Mocking Malware Scanner

```php
public function test_clean_file_is_accepted()
{
    $this->mockMalwareScanner()->returnsClean();

    // Test upload
}

public function test_infected_file_is_quarantined()
{
    $this->mockMalwareScanner()->returnsInfected('Trojan.Generic');

    // Test upload
}
```

## Penetration Testing Support

### Running Security Scans

```bash
# Run full security audit
php artisan security:audit

# Run specific checks
php artisan security:audit --check=headers
php artisan security:audit --check=authentication
php artisan security:audit --check=authorization

# Output in different formats
php artisan security:audit --format=json
php artisan security:audit --format=junit

# Save report
php artisan security:audit --output=security-report.html
```

### Vulnerability Scanning

```bash
# Scan for vulnerable dependencies
php artisan security:scan-dependencies

# Check for common security misconfigurations
php artisan security:check-config

# Test for SQL injection vulnerabilities
php artisan security:test-injection

# Test for XSS vulnerabilities
php artisan security:test-xss
```

### Security Test Suite

```php
use ArtisanPackUI\Security\Testing\SecurityTestSuite;

class FullSecurityTest extends TestCase
{
    public function test_application_security()
    {
        $suite = new SecurityTestSuite($this->app);

        $results = $suite
            ->testHeaders()
            ->testAuthentication()
            ->testAuthorization()
            ->testInputValidation()
            ->testFileUploads()
            ->testApiSecurity()
            ->run();

        $this->assertTrue($results->passed());
    }
}
```

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security Tests

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.2'

      - name: Install dependencies
        run: composer install --no-progress

      - name: Run security audit
        run: php artisan security:audit --format=junit --output=security-report.xml

      - name: Upload security report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-report.xml

      - name: Run security tests
        run: php artisan test --testsuite=Security

      - name: Check dependencies
        run: php artisan security:scan-dependencies
```

### GitLab CI

```yaml
# .gitlab-ci.yml
security:
  stage: test
  script:
    - composer install --no-progress
    - php artisan security:audit --format=junit --output=security-report.xml
    - php artisan test --testsuite=Security
    - php artisan security:scan-dependencies
  artifacts:
    reports:
      junit: security-report.xml
    when: always
```

## Test Data Factories

### Security-Related Factories

```php
// Create user with specific security state
$user = User::factory()
    ->withTwoFactor()
    ->withRole('admin')
    ->lockedAccount()
    ->create();

// Create user with expired password
$user = User::factory()
    ->passwordExpired()
    ->create();

// Create user with multiple sessions
$user = User::factory()
    ->withSessions(3)
    ->create();

// Create user with API tokens
$user = User::factory()
    ->withApiToken('read-token', ['read'])
    ->withApiToken('write-token', ['read', 'write'])
    ->create();
```

## Best Practices

### 1. Test Security Features in Isolation

```php
public function test_authentication_lockout()
{
    // Test only the lockout feature
    $this->withoutMiddleware([RateLimitMiddleware::class]);

    // Focus on lockout logic
}
```

### 2. Use Realistic Test Data

```php
public function test_password_validation()
{
    // Test with realistic weak passwords
    $weakPasswords = [
        'password',
        '123456',
        'qwerty',
        $user->email,  // Email as password
    ];

    foreach ($weakPasswords as $password) {
        $this->assertPasswordRejected($password);
    }
}
```

### 3. Test Edge Cases

```php
public function test_handles_unicode_in_passwords()
{
    $password = 'Pässwörd123!';

    $user = User::factory()->create([
        'password' => bcrypt($password),
    ]);

    $this->attemptLogin([
        'email' => $user->email,
        'password' => $password,
    ]);

    $this->assertAuthenticated();
}
```

### 4. Clean Up Security State

```php
protected function tearDown(): void
{
    $this->clearFailedLoginAttempts();
    $this->clearRateLimits();
    $this->clearSessions();

    parent::tearDown();
}
```

## Related Documentation

- [Implementation Guide](implementation-guide.md)
- [Configuration Reference](configuration-reference.md)
- [Troubleshooting Guide](troubleshooting.md)
- [Security Checklist](security-checklist.md)
