# Security Artisan Commands Suite - Implementation Plan

## Overview

This document outlines the implementation plan for a comprehensive suite of artisan commands for security management and diagnostics. The commands will integrate with the existing security infrastructure in the ArtisanPackUI Security package.

---

## Executive Summary

| Command | Status | Action Required |
|---------|--------|-----------------|
| `security:audit` | **Exists** | Enhancement recommended |
| `security:check-config` | **Exists** | Enhancement recommended |
| `security:generate-csp` | **New** | Full implementation |
| `security:scan-dependencies` | **New** | Full implementation (standalone) |
| `security:test-headers` | **New** | Full implementation |
| `security:user-security` | **New** | Full implementation |

---

## 1. `security:audit` - Comprehensive Security Audit

### Current Implementation
- **File:** `src/Console/Commands/SecurityAudit.php`
- **Signature:** `security:audit {--format=json} {--output=} {--benchmark} {--no-fail}`
- **Scanners Used:** OwaspScanner, DependencyScanner, ConfigurationScanner
- **Features:** Report generation (JSON, HTML, SARIF, JUnit, Markdown), Security Gate evaluation

### Recommended Enhancements

#### New Options
```php
protected $signature = 'security:audit
    {--format=json : Output format (json, html, sarif, junit, markdown)}
    {--output= : Output file path}
    {--benchmark : Include performance benchmarks}
    {--no-fail : Do not exit with error code on findings}
    {--scanners= : Comma-separated list of scanners to run (owasp,dependencies,config,headers,user)}
    {--severity= : Minimum severity to report (low, medium, high, critical)}
    {--include-recommendations : Include remediation recommendations}
    {--quiet : Suppress console output, only write to file}';
```

#### Additional Scanners to Integrate
1. **Headers Scanner** - Check security header configuration
2. **User Security Scanner** - Scan for user account security issues
3. **Authentication Scanner** - Check auth configuration
4. **CSP Scanner** - Validate CSP policy

#### Implementation Steps
1. Add scanner selection logic based on `--scanners` option
2. Implement severity filtering on findings
3. Add summary recommendations section
4. Integrate with new scanner classes

---

## 2. `security:check-config` - Configuration Validation

### Current Implementation
- **File:** `src/Console/Commands/CheckSecurityConfiguration.php`
- **Signature:** `security:check-config`
- **Service:** `EnvironmentValidationService`

### Recommended Enhancements

#### New Options
```php
protected $signature = 'security:check-config
    {--category= : Specific category to check (env, session, database, cache, mail, filesystem, security)}
    {--fix : Attempt to suggest or apply fixes}
    {--json : Output results as JSON}
    {--strict : Treat warnings as errors}
    {--ignore= : Comma-separated list of check IDs to ignore}';
```

#### Additional Validation Categories
1. **API Security Configuration** - Token expiration, rate limits
2. **RBAC Configuration** - Role/permission setup validation
3. **CSP Configuration** - CSP policy validation
4. **Password Policy Configuration** - Strength requirements
5. **File Upload Configuration** - Malware scanner, allowed types
6. **Compliance Configuration** - GDPR/CCPA settings

#### Implementation Steps
1. Extend `EnvironmentValidationService` with category support
2. Add JSON output mode
3. Implement `--fix` suggestions
4. Create check ID system for `--ignore` option

---

## 3. `security:generate-csp` - CSP Policy Generation (NEW)

### Purpose
Generate and export Content Security Policy configurations based on application analysis and presets.

### Command Signature
```php
protected $signature = 'security:generate-csp
    {--preset=livewire : Base preset (livewire, strict, relaxed)}
    {--analyze : Analyze application for required sources}
    {--output= : Output file path for generated policy}
    {--format=config : Output format (config, header, meta, nginx, apache)}
    {--interactive : Interactive mode to build policy step-by-step}
    {--report-only : Generate as report-only policy}
    {--include-report-uri : Include violation reporting endpoint}';
```

### Features
1. **Preset Selection** - Choose from livewire, strict, or relaxed presets
2. **Application Analysis** - Scan blade/view files for inline scripts/styles
3. **Multi-Format Output**
   - `config` - PHP array for config file
   - `header` - Raw HTTP header string
   - `meta` - HTML meta tag
   - `nginx` - Nginx configuration snippet
   - `apache` - Apache .htaccess snippet
4. **Interactive Mode** - Step-by-step policy builder
5. **Report URI Integration** - Auto-configure violation reporting

### Implementation Details

#### File Structure
```
src/Console/Commands/GenerateCspPolicy.php
```

#### Dependencies
- `CspPolicyService` - For preset access and policy building
- `CspPolicyBuilder` - For constructing policies
- Blade/View file analysis (new functionality)

#### Key Methods
```php
public function handle(CspPolicyInterface $csp): int
{
    // 1. Load base preset
    // 2. If --analyze, scan application
    // 3. Build policy with CspPolicyBuilder
    // 4. Format output based on --format
    // 5. Write to file or display
}

protected function analyzeApplication(): array
{
    // Scan resources/views for:
    // - Inline scripts (suggest nonce)
    // - External script sources
    // - Inline styles
    // - External style sources
    // - Font sources
    // - Image sources
    // - Frame sources
}

protected function formatAsNginx(string $policy): string
{
    return "add_header Content-Security-Policy \"{$policy}\" always;";
}

protected function formatAsApache(string $policy): string
{
    return "Header always set Content-Security-Policy \"{$policy}\"";
}
```

#### Application Analysis Logic
1. Glob for `resources/views/**/*.blade.php`
2. Parse for `<script>`, `<style>`, `<link>`, `<img>`, `<iframe>` tags
3. Extract `src`, `href` attributes
4. Categorize by directive
5. Suggest policy directives

---

## 4. `security:scan-dependencies` - Vulnerability Scanning (NEW)

### Purpose
Standalone command for scanning Composer and NPM dependencies for known vulnerabilities.

### Command Signature
```php
protected $signature = 'security:scan-dependencies
    {--composer : Only scan Composer dependencies}
    {--npm : Only scan NPM dependencies}
    {--severity= : Minimum severity (low, medium, high, critical)}
    {--format=table : Output format (table, json, sarif)}
    {--output= : Output file path}
    {--advisories= : Path to local advisory database}
    {--update-advisories : Update local advisory database}
    {--fail-on= : Fail on severity level (none, low, medium, high, critical)}';
```

### Features
1. **Selective Scanning** - Composer-only or NPM-only
2. **Severity Filtering** - Report only above threshold
3. **Multiple Output Formats** - Table, JSON, SARIF
4. **Advisory Management** - Local database support
5. **CI/CD Integration** - Configurable failure thresholds

### Implementation Details

#### File Structure
```
src/Console/Commands/ScanDependencies.php
```

#### Dependencies
- `DependencyScanner` - Existing scanner (src/Testing/Scanners/DependencyScanner.php)

#### Key Methods
```php
public function handle(): int
{
    $scanner = new DependencyScanner(
        $this->option('composer') ? base_path('composer.lock') : null,
        $this->option('npm') ? base_path('package-lock.json') : null
    );

    if ($advisories = $this->option('advisories')) {
        $scanner->useLocalAdvisories($advisories);
    }

    $findings = $scanner->scan();

    // Filter by severity
    $findings = $this->filterBySeverity($findings);

    // Output results
    $this->outputResults($findings);

    // Determine exit code
    return $this->determineExitCode($findings);
}
```

#### Enhanced Output
```
Dependency Vulnerability Scan Results
=====================================

Composer Dependencies
---------------------
 ✗ symfony/http-foundation@5.4.18
   CVE-2022-24894 (HIGH): Cookie Parsing Vulnerability
   Affected: <5.4.20
   Fix: Update to 5.4.20 or later

 ✗ guzzlehttp/guzzle@7.4.4
   CVE-2022-31090 (HIGH): CURLOPT_HTTPAUTH leak
   Affected: >=7.0.0 <7.4.5
   Fix: Update to 7.4.5 or later

NPM Dependencies
----------------
 ✓ No vulnerabilities found

Summary
-------
 Critical: 0
 High: 2
 Medium: 0
 Low: 0
 Outdated: 3 packages over 2 years old
```

---

## 5. `security:test-headers` - Security Headers Testing (NEW)

### Purpose
Test and validate security headers implementation against best practices and OWASP recommendations.

### Command Signature
```php
protected $signature = 'security:test-headers
    {url? : URL to test (defaults to APP_URL)}
    {--live : Make actual HTTP request to test headers}
    {--config-only : Only check configuration, no HTTP request}
    {--format=table : Output format (table, json)}
    {--strict : Use strict security requirements}
    {--include-csp : Include detailed CSP analysis}';
```

### Features
1. **Configuration Analysis** - Check `config/artisanpack/security.php` headers
2. **Live Testing** - Make HTTP request to verify actual headers
3. **Best Practice Grading** - A-F scoring system
4. **OWASP Compliance** - Check against OWASP secure headers recommendations
5. **CSP Integration** - Detailed CSP directive analysis

### Implementation Details

#### File Structure
```
src/Console/Commands/TestSecurityHeaders.php
```

#### Headers to Validate
| Header | Requirement | Severity |
|--------|-------------|----------|
| Strict-Transport-Security | Required (HTTPS) | High |
| X-Frame-Options | Required | High |
| X-Content-Type-Options | Required (nosniff) | Medium |
| X-XSS-Protection | Recommended | Low |
| Referrer-Policy | Recommended | Medium |
| Content-Security-Policy | Required | High |
| Permissions-Policy | Recommended | Medium |
| Cross-Origin-Opener-Policy | Recommended | Medium |
| Cross-Origin-Resource-Policy | Recommended | Medium |
| Cross-Origin-Embedder-Policy | Optional | Low |

#### Key Methods
```php
public function handle(): int
{
    $this->info('Security Headers Test');

    if ($this->option('config-only')) {
        return $this->analyzeConfiguration();
    }

    if ($this->option('live')) {
        return $this->performLiveTest();
    }

    // Default: analyze both
    $this->analyzeConfiguration();
    $this->performLiveTest();

    return $this->displayResults();
}

protected function analyzeConfiguration(): void
{
    $headers = config('artisanpack.security.security-headers', []);

    foreach ($this->getRequiredHeaders() as $header => $requirements) {
        $this->validateHeader($header, $headers[$header] ?? null, $requirements);
    }
}

protected function performLiveTest(): void
{
    $url = $this->argument('url') ?? config('app.url');

    $response = Http::get($url);
    $headers = $response->headers();

    foreach ($this->getRequiredHeaders() as $header => $requirements) {
        $this->validateHeader($header, $headers[$header][0] ?? null, $requirements);
    }
}

protected function gradeSecurityHeaders(): string
{
    // A: All required headers present with recommended values
    // B: All required headers present
    // C: Missing some recommended headers
    // D: Missing required headers
    // F: Critical security headers missing
}
```

#### Sample Output
```
Security Headers Analysis
=========================

URL: https://example.com

Header                        | Status  | Value                            | Grade
------------------------------|---------|----------------------------------|-------
Strict-Transport-Security     | ✓ PASS  | max-age=31536000; includeSubD... | A
X-Frame-Options               | ✓ PASS  | SAMEORIGIN                       | A
X-Content-Type-Options        | ✓ PASS  | nosniff                          | A
Content-Security-Policy       | ⚠ WARN  | (present but uses unsafe-inline) | C
X-XSS-Protection              | ✓ PASS  | 1; mode=block                    | A
Referrer-Policy               | ✓ PASS  | no-referrer-when-downgrade       | B
Permissions-Policy            | ✗ MISS  | (not configured)                 | D
Cross-Origin-Opener-Policy    | ✗ MISS  | (not configured)                 | D

Overall Grade: B

Recommendations:
1. Add Permissions-Policy header to control browser features
2. Consider using stricter CSP without 'unsafe-inline'
3. Add Cross-Origin-Opener-Policy for additional isolation
```

---

## 6. `security:user-security` - User Account Security Status (NEW)

### Purpose
Check and report on user account security status, identifying accounts with security issues.

### Command Signature
```php
protected $signature = 'security:user-security
    {user? : Specific user ID or email to check}
    {--all : Check all users (may be slow)}
    {--issues-only : Only show users with security issues}
    {--format=table : Output format (table, json)}
    {--export= : Export results to file}
    {--check= : Specific checks to run (comma-separated)}
    {--fix : Attempt to fix issues (force password reset, etc.)}
    {--notify : Send notification to users with issues}';
```

### Security Checks
1. **Password Security**
   - Compromised password (HaveIBeenPwned)
   - Password age
   - Password not meeting current policy
2. **Two-Factor Authentication**
   - 2FA not enabled
   - 2FA methods configured
3. **Session Security**
   - Active session count
   - Sessions from multiple locations
   - Suspicious sessions
4. **Account Status**
   - Account lockouts (current/history)
   - Failed login attempts
   - Suspicious activity flags
5. **Device Security**
   - Untrusted devices
   - New device logins
6. **API Token Security**
   - Expired tokens
   - Tokens with excessive permissions
   - Never-expiring tokens

### Implementation Details

#### File Structure
```
src/Console/Commands/CheckUserSecurity.php
```

#### Dependencies
- `PasswordSecurityService` - Password compromise checking
- `AccountLockout` model - Lockout status
- `UserSession` model - Session analysis
- `UserDevice` model - Device tracking
- `SuspiciousActivity` model - Activity flags
- `ApiToken` model - Token management
- `SecurityEvent` model - Event history

#### Key Methods
```php
public function handle(
    PasswordSecurityService $passwordService
): int {
    if ($userId = $this->argument('user')) {
        return $this->checkSingleUser($userId);
    }

    if ($this->option('all')) {
        return $this->checkAllUsers();
    }

    // Default: show summary statistics
    return $this->showSecuritySummary();
}

protected function checkSingleUser(string $identifier): int
{
    $user = $this->findUser($identifier);

    $issues = collect();

    // Check password security
    $issues = $issues->merge($this->checkPasswordSecurity($user));

    // Check 2FA status
    $issues = $issues->merge($this->check2FAStatus($user));

    // Check sessions
    $issues = $issues->merge($this->checkSessionSecurity($user));

    // Check lockouts
    $issues = $issues->merge($this->checkLockoutStatus($user));

    // Check suspicious activity
    $issues = $issues->merge($this->checkSuspiciousActivity($user));

    // Check API tokens
    $issues = $issues->merge($this->checkApiTokenSecurity($user));

    return $this->displayUserReport($user, $issues);
}

protected function showSecuritySummary(): int
{
    // Aggregate statistics
    $stats = [
        'total_users' => User::count(),
        'without_2fa' => User::whereDoesntHave('twoFactorAuth')->count(),
        'locked_accounts' => AccountLockout::active()->distinct('user_id')->count(),
        'suspicious_activity' => SuspiciousActivity::unresolved()->distinct('user_id')->count(),
        'expiring_tokens' => ApiToken::where('expires_at', '<=', now()->addDays(7))->count(),
        'never_expiring_tokens' => ApiToken::whereNull('expires_at')->count(),
    ];

    $this->displaySummaryTable($stats);
}
```

#### Sample Output (Single User)
```
User Security Report: john@example.com (ID: 42)
==============================================

Account Status
--------------
 Created: 2024-01-15
 Last Login: 2024-12-28
 Status: Active

Security Score: 72/100 (Good)

Issues Found: 3
--------------

 ⚠ [MEDIUM] Two-Factor Authentication not enabled
   Recommendation: Enable 2FA for enhanced account security
   Action: --fix will send 2FA setup reminder

 ⚠ [LOW] Password is 89 days old
   Recommendation: Consider rotating password (policy: 90 days)

 ⚠ [MEDIUM] 2 API tokens never expire
   Tokens: "Mobile App", "CI/CD Pipeline"
   Recommendation: Set expiration dates for long-lived tokens

Sessions (3 active)
-------------------
 • Chrome/Windows - New York, US (current)
 • Safari/iOS - New York, US (2 hours ago)
 • Firefox/Linux - Los Angeles, US (1 day ago)

Recent Security Events (last 7 days)
------------------------------------
 • 2024-12-27: Successful login from new device
 • 2024-12-25: Failed login attempt (wrong password)
 • 2024-12-20: Password changed
```

#### Sample Output (Summary)
```
User Security Summary
=====================

Total Users: 1,247

Security Overview
-----------------
 Category                    | Count  | Percentage
-----------------------------|--------|------------
 Users without 2FA           | 423    | 33.9%
 Locked accounts             | 12     | 1.0%
 Users with suspicious activity | 8   | 0.6%
 Compromised passwords       | 0      | 0.0%
 Expiring tokens (7 days)    | 45     | -
 Never-expiring tokens       | 156    | -

High-Risk Users (5)
-------------------
 1. user@example.com - Locked (brute force), no 2FA
 2. admin@example.com - 3 suspicious activities, no 2FA
 3. dev@example.com - 12 failed logins today

Run 'security:user-security --issues-only' for full list
```

---

## Implementation Order & Timeline

### Phase 1: New Commands (Priority)
1. **`security:generate-csp`** - High value, no existing implementation
2. **`security:scan-dependencies`** - Standalone version of existing scanner
3. **`security:test-headers`** - New capability, high security value
4. **`security:user-security`** - Comprehensive user security overview

### Phase 2: Enhancements
5. **`security:audit`** - Add new scanners and options
6. **`security:check-config`** - Add categories and JSON output

---

## File Structure

```
src/Console/Commands/
├── SecurityAudit.php              (existing, enhance)
├── CheckSecurityConfiguration.php (existing, enhance)
├── GenerateCspPolicy.php          (NEW)
├── ScanDependencies.php           (NEW)
├── TestSecurityHeaders.php        (NEW)
└── CheckUserSecurity.php          (NEW)
```

---

## Service Provider Registration

Add to `SecurityServiceProvider::registerCommands()`:

```php
protected function registerCommands(): void
{
    $this->commands([
        // Existing commands...

        // New Security Suite Commands
        \ArtisanPackUI\Security\Console\Commands\GenerateCspPolicy::class,
        \ArtisanPackUI\Security\Console\Commands\ScanDependencies::class,
        \ArtisanPackUI\Security\Console\Commands\TestSecurityHeaders::class,
        \ArtisanPackUI\Security\Console\Commands\CheckUserSecurity::class,
    ]);
}
```

---

## Testing Requirements

### Unit Tests
Each command should have comprehensive unit tests covering:
- All command options and arguments
- Edge cases (empty data, missing configuration)
- Output format variations
- Exit code correctness

### Integration Tests
- Test scanner integration
- Test actual HTTP requests for header testing
- Test database queries for user security

### Test Files
```
tests/Console/
├── GenerateCspPolicyTest.php
├── ScanDependenciesTest.php
├── TestSecurityHeadersTest.php
└── CheckUserSecurityTest.php
```

---

## Configuration Additions

Add to `config/security.php`:

```php
'commands' => [
    'user_security' => [
        'password_max_age_days' => 90,
        'notify_on_issues' => false,
        'checks' => [
            'password' => true,
            '2fa' => true,
            'sessions' => true,
            'lockouts' => true,
            'suspicious_activity' => true,
            'api_tokens' => true,
        ],
    ],

    'headers_test' => [
        'strict_mode' => false,
        'required_headers' => [
            'Strict-Transport-Security',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Content-Security-Policy',
        ],
    ],

    'dependency_scan' => [
        'fail_on_severity' => 'high',
        'include_outdated' => true,
        'outdated_threshold_years' => 2,
    ],
],
```

---

## Acceptance Criteria Checklist

- [ ] `security:audit` - Run comprehensive security audit *(exists, enhancements recommended)*
- [ ] `security:check-config` - Validate security configuration *(exists, enhancements recommended)*
- [ ] `security:generate-csp` - Generate CSP policies *(new implementation)*
- [ ] `security:scan-dependencies` - Check for vulnerable dependencies *(new implementation)*
- [ ] `security:test-headers` - Test security headers implementation *(new implementation)*
- [ ] `security:user-security` - Check user account security status *(new implementation)*

---

## Notes

### Existing Infrastructure to Leverage
- `DependencyScanner` - Already scans Composer and NPM
- `CspPolicyService` - Full CSP building capabilities
- `SecurityHeadersMiddleware` - Header configuration
- `PasswordSecurityService` - HaveIBeenPwned integration
- Security models: `AccountLockout`, `UserSession`, `UserDevice`, `SuspiciousActivity`, `ApiToken`, `SecurityEvent`
- `EnvironmentValidationService` - Configuration validation

### Considerations
1. All commands should support `--quiet` mode for CI/CD
2. JSON output should be parseable for automation
3. Exit codes should follow conventions (0=success, 1=failure, 2=warnings)
4. Commands should be efficient for large user bases (pagination, chunking)
5. Sensitive data should never be logged or displayed (passwords, tokens)
