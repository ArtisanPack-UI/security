# ArtisanPack UI Security Package 2.0 Release Plan

## Overview

This document outlines the audit findings and recommended changes for the `artisanpack-ui/security` package 2.0 release. The package has grown significantly beyond its original scope and requires restructuring for maintainability, usability, and performance.

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Current State Analysis](#current-state-analysis)
3. [Critical Issues](#critical-issues)
4. [Recommended Architecture](#recommended-architecture)
5. [Migration Strategy](#migration-strategy)
6. [Implementation Phases](#implementation-phases)
7. [Breaking Changes](#breaking-changes)
8. [Deprecation Timeline](#deprecation-timeline)

---

## Executive Summary

### The Problem

The security package has evolved from a focused sanitization/escaping library into an enterprise security suite containing:

- **100+ PHP classes**
- **42+ Eloquent models**
- **51 Artisan commands**
- **49 database migrations**
- **1,600+ line ServiceProvider**
- **1,655 line configuration file**

This violates the Single Responsibility Principle and creates several problems:

1. **Performance**: All services register on every request, even if unused
2. **Complexity**: Difficult for users to understand what features are available
3. **Maintenance**: Hard to maintain and test such a large codebase
4. **Dependencies**: Forces users to install dependencies for features they don't use
5. **Migrations**: 49 migrations run even for features not being used

### The Solution

Split the package into focused, composable packages that users can install as needed.

---

## Current State Analysis

### Package Metrics

| Metric | Count | Assessment |
|--------|-------|------------|
| PHP Classes | 100+ | Too many for one package |
| Eloquent Models | 42 | Excessive |
| Migrations | 49 | Excessive |
| Artisan Commands | 51 | Excessive |
| Livewire Components | 13 | Acceptable if split |
| Middleware Classes | 20 | Excessive |
| Events | 30+ | Acceptable if split |
| Config Lines | 1,655 | Too large |
| ServiceProvider Lines | 1,684 | Far too large |

### Feature Domains Identified

| Domain | Description | Files | Migrations |
|--------|-------------|-------|------------|
| Core Security | Sanitization, escaping, KSES | ~5 | 0 |
| Two-Factor Auth | Email/TOTP 2FA | ~10 | 1 |
| RBAC | Roles and permissions | ~15 | 4 |
| API Security | Sanctum extensions, token management | ~8 | 1 |
| File Upload Security | Validation, malware scanning, storage | ~12 | 1 |
| CSP | Content Security Policy | ~8 | 1 |
| Password Security | Complexity, history, breach checking | ~8 | 2 |
| Security Analytics | SIEM, anomaly detection, threat intel | ~31 | 9 |
| Compliance | GDPR, CCPA, consent, erasure | ~48 | 17 |
| Advanced Auth | WebAuthn, SSO, social, biometric | ~31 | 9 |

---

## Critical Issues

### Issue 1: Migration Column Existence Check (Bug)

**Priority**: Critical
**Status**: Causes errors in production

**Problem**: The 2FA migration doesn't check if columns exist before adding them.

**File**: `database/migrations/2025_09_28_205614_add_two_factor_to_users_table.php`

**Current Code**:
```php
public function up(): void
{
    Schema::table('users', function (Blueprint $table) {
        $table->text('two_factor_secret')
              ->after('password')
              ->nullable();

        $table->text('two_factor_recovery_codes')
              ->after('two_factor_secret')
              ->nullable();

        $table->timestamp('two_factor_enabled_at')
              ->after('two_factor_recovery_codes')
              ->nullable();
    });
}
```

**Fixed Code**:
```php
public function up(): void
{
    if (!Schema::hasTable('users')) {
        return;
    }

    Schema::table('users', function (Blueprint $table) {
        if (!Schema::hasColumn('users', 'two_factor_secret')) {
            $table->text('two_factor_secret')
                  ->after('password')
                  ->nullable();
        }

        if (!Schema::hasColumn('users', 'two_factor_recovery_codes')) {
            $table->text('two_factor_recovery_codes')
                  ->after('two_factor_secret')
                  ->nullable();
        }

        if (!Schema::hasColumn('users', 'two_factor_enabled_at')) {
            $table->timestamp('two_factor_enabled_at')
                  ->after('two_factor_recovery_codes')
                  ->nullable();
        }
    });
}

public function down(): void
{
    if (!Schema::hasTable('users')) {
        return;
    }

    Schema::table('users', function (Blueprint $table) {
        $columns = ['two_factor_secret', 'two_factor_recovery_codes', 'two_factor_enabled_at'];

        foreach ($columns as $column) {
            if (Schema::hasColumn('users', $column)) {
                $table->dropColumn($column);
            }
        }
    });
}
```

### Issue 2: ServiceProvider Complexity

**Priority**: High
**Status**: Technical debt

The `SecurityServiceProvider` is 1,684 lines and registers everything on every request. This needs to be split into multiple providers with deferred loading.

### Issue 3: Inconsistent Migration Patterns

**Priority**: Medium
**Status**: Inconsistency

Some migrations check for table/column existence, others don't:

| Migration | Has Checks |
|-----------|------------|
| `add_two_factor_to_users_table.php` | ❌ No |
| `add_password_security_columns_to_users_table.php` | ✅ Yes |
| `add_metadata_to_personal_access_tokens_table.php` | ✅ Yes |

All migrations modifying existing tables should have existence checks.

### Issue 4: Composer Description Mismatch

**Priority**: Low
**Status**: Documentation

The `composer.json` description says:
> "Provides escaping and sanitation functions to provide security for Digital Shopfront CMS."

This doesn't reflect the package's current scope.

---

## Recommended Architecture

### Package Split Strategy

Split the monolithic package into 7 focused packages:

```
artisanpack-ui/
├── security                 # Core (sanitization, escaping, headers)
├── security-auth           # 2FA, password security, sessions
├── security-advanced-auth  # WebAuthn, SSO, social, biometric
├── rbac                    # Roles and permissions
├── secure-uploads          # File validation, malware scanning
├── security-analytics      # SIEM, anomaly detection, incidents
└── compliance              # GDPR, CCPA, consent management
```

### Package 1: `artisanpack-ui/security` (Core)

**Purpose**: Core security utilities that every Laravel application needs.

**Features**:
- Input sanitization functions (`sanitizeEmail`, `sanitizeText`, etc.)
- Output escaping functions (`escHtml`, `escAttr`, `escJs`, etc.)
- KSES HTML filtering
- Security headers middleware
- XSS protection middleware
- Basic rate limiting configuration
- CSP support (headers and nonce generation)

**Dependencies**:
- `illuminate/support`
- `laminas/laminas-escaper`
- `artisanpack-ui/core`

**Migrations**: 1 (CSP violation reports)

**Config Lines**: ~200

### Package 2: `artisanpack-ui/security-auth`

**Purpose**: Authentication security features.

**Features**:
- Two-factor authentication (Email, TOTP)
- Password security (complexity, history, expiration, breach checking)
- Account lockout
- Advanced session management
- Step-up authentication

**Dependencies**:
- `artisanpack-ui/security`
- `pragmarx/google2fa-laravel`

**Migrations**: 4

**Config Lines**: ~300

### Package 3: `artisanpack-ui/security-advanced-auth`

**Purpose**: Enterprise authentication methods.

**Features**:
- WebAuthn/FIDO2 passwordless authentication
- Social authentication (Google, Microsoft, GitHub, etc.)
- SSO (SAML 2.0, OIDC, LDAP)
- Biometric authentication
- Device fingerprinting and trust

**Dependencies**:
- `artisanpack-ui/security-auth`
- WebAuthn library (TBD)

**Migrations**: 9

**Config Lines**: ~400

### Package 4: `artisanpack-ui/rbac`

**Purpose**: Role-based access control.

**Features**:
- Role model with hierarchy support
- Permission model
- HasRoles trait for User model
- Middleware for permission checks
- Blade directives (@role, @permission)
- Gate integration
- Artisan commands for role/permission management

**Dependencies**:
- `illuminate/support`

**Migrations**: 4

**Config Lines**: ~50

### Package 5: `artisanpack-ui/secure-uploads`

**Purpose**: Secure file upload handling.

**Features**:
- File type validation (MIME, extension, content)
- Malware scanning (ClamAV, VirusTotal)
- Secure storage with hashed filenames
- Signed URL generation
- Upload rate limiting
- Quarantine management

**Dependencies**:
- `artisanpack-ui/security`

**Migrations**: 1

**Config Lines**: ~150

### Package 6: `artisanpack-ui/security-analytics`

**Purpose**: Enterprise security monitoring.

**Features**:
- Security event logging
- Anomaly detection (statistical, behavioral, rule-based)
- Threat intelligence integration
- SIEM export (Splunk, Datadog, etc.)
- Incident response workflows
- Alert management
- Security dashboards
- Scheduled reports

**Dependencies**:
- `artisanpack-ui/security`

**Migrations**: 9

**Config Lines**: ~300

### Package 7: `artisanpack-ui/compliance`

**Purpose**: Regulatory compliance support.

**Features**:
- Multi-regulation support (GDPR, CCPA, LGPD, PIPEDA, POPIA, PDPA)
- Consent management
- Data portability (right to export)
- Right to erasure (right to be forgotten)
- Data Protection Impact Assessments (DPIA)
- Processing activity records
- Compliance monitoring and reporting
- Data minimization (anonymization, pseudonymization)

**Dependencies**:
- `artisanpack-ui/security`

**Migrations**: 17

**Config Lines**: ~400

---

## Migration Strategy

### For Existing Users

Provide a migration path for users upgrading from 1.x to 2.0.

#### Option A: Compatibility Layer

Create a meta-package that requires all split packages:

```json
{
    "name": "artisanpack-ui/security-full",
    "require": {
        "artisanpack-ui/security": "^2.0",
        "artisanpack-ui/security-auth": "^2.0",
        "artisanpack-ui/security-advanced-auth": "^2.0",
        "artisanpack-ui/rbac": "^2.0",
        "artisanpack-ui/secure-uploads": "^2.0",
        "artisanpack-ui/security-analytics": "^2.0",
        "artisanpack-ui/compliance": "^2.0"
    }
}
```

#### Option B: Feature Detection

The core package detects if tables exist and only enables features accordingly:

```php
// In SecurityServiceProvider
if (Schema::hasTable('roles')) {
    // RBAC features available
}
```

### Database Migration Handling

Each package should:

1. **Only auto-load migrations for new tables** it creates
2. **Publish migrations for existing table modifications** (users table, etc.)
3. **Check for column/table existence** in all migrations

Example install command:

```bash
# Install core security
composer require artisanpack-ui/security

# Install 2FA support
composer require artisanpack-ui/security-auth
php artisan vendor:publish --tag=security-auth-migrations
php artisan migrate
```

---

## Implementation Phases

### Phase 1: Critical Bug Fixes (Week 1)

**Goal**: Fix blocking issues for 1.x users.

- [ ] Fix 2FA migration column existence checks
- [ ] Add existence checks to any other migrations missing them
- [ ] Release as 1.0.4 patch

### Phase 2: Package Restructuring (Weeks 2-4)

**Goal**: Create the new package structure.

- [ ] Create new package repositories:
  - [ ] `artisanpack-ui/security` (core)
  - [ ] `artisanpack-ui/security-auth`
  - [ ] `artisanpack-ui/security-advanced-auth`
  - [ ] `artisanpack-ui/rbac`
  - [ ] `artisanpack-ui/secure-uploads`
  - [ ] `artisanpack-ui/security-analytics`
  - [ ] `artisanpack-ui/compliance`

- [ ] Move code to appropriate packages
- [ ] Split ServiceProvider into package-specific providers
- [ ] Split configuration files
- [ ] Update namespace references

### Phase 3: Testing & Documentation (Weeks 5-6)

**Goal**: Ensure quality and usability.

- [ ] Write/migrate tests for each package
- [ ] Update CLAUDE.md rules for each package
- [ ] Create installation guides
- [ ] Create migration guide from 1.x to 2.0
- [ ] Update README files

### Phase 4: Release (Week 7)

**Goal**: Release 2.0.

- [ ] Tag 2.0.0 releases for all packages
- [ ] Publish to Packagist
- [ ] Announce deprecation of monolithic package
- [ ] Create `artisanpack-ui/security-full` meta-package

---

## Breaking Changes

### Namespace Changes

| 1.x Namespace | 2.0 Namespace |
|---------------|---------------|
| `ArtisanPackUI\Security\*` | `ArtisanPackUI\Security\*` (core only) |
| `ArtisanPackUI\Security\TwoFactor\*` | `ArtisanPackUI\SecurityAuth\TwoFactor\*` |
| `ArtisanPackUI\Security\Authentication\*` | `ArtisanPackUI\SecurityAdvancedAuth\*` |
| `ArtisanPackUI\Security\Models\Role` | `ArtisanPackUI\Rbac\Models\Role` |
| `ArtisanPackUI\Security\Models\Permission` | `ArtisanPackUI\Rbac\Models\Permission` |
| `ArtisanPackUI\Security\FileUpload\*` | `ArtisanPackUI\SecureUploads\*` |
| `ArtisanPackUI\Security\Analytics\*` | `ArtisanPackUI\SecurityAnalytics\*` |
| `ArtisanPackUI\Security\Compliance\*` | `ArtisanPackUI\Compliance\*` |

### Configuration Changes

| 1.x Config Key | 2.0 Config Key |
|----------------|----------------|
| `artisanpack.security.*` | `artisanpack.security.*` (core only) |
| `artisanpack.security.two_factor` | `artisanpack.security-auth.two_factor` |
| `artisanpack.security.rbac` | `artisanpack.rbac` |
| `artisanpack.security.fileUpload` | `artisanpack.secure-uploads` |
| `artisanpack.security.analytics` | `artisanpack.security-analytics` |
| `security-compliance` | `artisanpack.compliance` |

### Facade Changes

| 1.x Facade | 2.0 Facade |
|------------|------------|
| `Security` | `Security` (unchanged) |
| `TwoFactor` | `TwoFactor` (from security-auth) |
| `Csp` | `Csp` (unchanged, in core) |

### Removed Features from Core

The following will no longer be in the core `artisanpack-ui/security` package:

- Two-factor authentication (use `security-auth`)
- RBAC (use `rbac`)
- API security (use `security-auth` or `security-advanced-auth`)
- File upload security (use `secure-uploads`)
- Analytics (use `security-analytics`)
- Compliance (use `compliance`)
- Advanced authentication (use `security-advanced-auth`)

---

## Deprecation Timeline

| Date | Action |
|------|--------|
| 2.0.0 Release | Monolithic package deprecated, new packages available |
| +3 months | Security-only updates for 1.x |
| +6 months | End of life for 1.x |

---

## Appendix A: File Inventory

### Files Moving to `security` (core)

```
src/Security.php
src/SecurityServiceProvider.php (refactored)
src/helpers.php
src/HTMLawed.php
src/Facades/Security.php
src/Facades/Csp.php
src/Http/Middleware/EnsureSessionIsEncrypted.php
src/Http/Middleware/SecurityHeadersMiddleware.php
src/Http/Middleware/XssProtection.php
src/Http/Middleware/ContentSecurityPolicy.php
src/Services/Csp/*
src/Models/CspViolationReport.php
src/Rules/NoHtml.php
src/Rules/SecureUrl.php
config/security.php (reduced)
```

### Files Moving to `security-auth`

```
src/TwoFactor/*
src/Facades/TwoFactor.php
src/Http/Middleware/TwoFactorMiddleware.php
src/Authentication/Lockout/*
src/Authentication/Session/*
src/Services/PasswordSecurityService.php
src/Services/HaveIBeenPwnedService.php
src/Rules/PasswordComplexity.php
src/Rules/PasswordHistoryRule.php
src/Rules/PasswordPolicy.php
src/Rules/NotCompromised.php
src/Models/PasswordHistory.php
src/Models/AccountLockout.php
src/Livewire/PasswordStrengthMeter.php
src/Livewire/AccountLockoutStatus.php
src/Livewire/SessionManager.php
src/Livewire/StepUpAuthenticationModal.php
database/migrations/2025_09_28_205614_add_two_factor_to_users_table.php
database/migrations/password/*
database/migrations/authentication/2025_12_24_000007_create_user_sessions_table.php
database/migrations/authentication/2025_12_24_000009_create_account_lockouts_table.php
```

### Files Moving to `security-advanced-auth`

```
src/Authentication/Biometric/*
src/Authentication/Device/*
src/Authentication/Detection/*
src/Authentication/Social/*
src/Authentication/Sso/*
src/Authentication/WebAuthn/*
src/Models/DeviceFingerprint.php
src/Models/SocialIdentity.php
src/Models/SsoConfiguration.php
src/Models/SsoIdentity.php
src/Models/WebAuthnCredential.php
src/Models/UserDevice.php
src/Models/SuspiciousActivity.php
src/Livewire/BiometricManager.php
src/Livewire/DeviceManager.php
src/Livewire/SocialAccountsManager.php
src/Livewire/SuspiciousActivityList.php
src/Livewire/WebAuthnCredentialsManager.php
database/migrations/authentication/* (except sessions and lockouts)
```

### Files Moving to `rbac`

```
src/Models/Role.php
src/Models/Permission.php
src/Concerns/HasRoles.php
src/Concerns/HasPermissions.php
src/Http/Middleware/CheckPermission.php
src/Observers/RoleObserver.php
src/Observers/PermissionObserver.php
src/Console/Commands/CreateRole.php
src/Console/Commands/CreatePermission.php
src/Console/Commands/AssignRole.php
src/Console/Commands/RevokeRole.php
database/migrations/2025_11_30_164015_create_roles_table.php
database/migrations/2025_11_30_164016_create_permissions_table.php
database/migrations/2025_11_30_164017_create_permission_role_table.php
database/migrations/2025_11_30_164018_create_role_user_table.php
```

### Files Moving to `secure-uploads`

```
src/FileUpload/*
src/Services/FileValidationService.php
src/Services/FileUploadRateLimiter.php
src/Services/SecureFileStorageService.php
src/Services/Scanners/*
src/Contracts/FileValidatorInterface.php
src/Contracts/MalwareScannerInterface.php
src/Contracts/SecureFileStorageInterface.php
src/Http/Middleware/ValidateFileUpload.php
src/Http/Middleware/ScanUploadedFiles.php
src/Models/SecureUploadedFile.php
src/Rules/SafeFilename.php
src/Rules/SecureFile.php
database/migrations/uploads/*
```

### Files Moving to `security-analytics`

```
src/Analytics/*
src/Models/SecurityEvent.php
src/Models/SecurityMetric.php
src/Models/Anomaly.php
src/Models/UserBehaviorProfile.php
src/Models/ThreatIndicator.php
src/Models/ResponsePlaybook.php
src/Models/SecurityIncident.php
src/Models/AlertRule.php
src/Models/AlertHistory.php
src/Models/ScheduledReport.php
src/Services/SecurityEventLogger.php
src/Contracts/SecurityEventLoggerInterface.php
src/Livewire/SecurityDashboard.php
src/Livewire/SecurityEventList.php
src/Livewire/SecurityStats.php
src/Livewire/CspDashboard.php
database/migrations/2025_12_22_000001_create_security_events_table.php
database/migrations/analytics/*
```

### Files Moving to `compliance`

```
src/Compliance/*
src/Models/ProcessingActivity.php
src/Models/DataProtectionAssessment.php
src/Models/AssessmentRisk.php
src/Models/RiskMitigation.php
src/Models/ConsentPolicy.php
src/Models/ConsentRecord.php
src/Models/ConsentAuditLog.php
src/Models/ErasureRequest.php
src/Models/ErasureLog.php
src/Models/PortabilityRequest.php
src/Models/ExportSchema.php
src/Models/RetentionPolicy.php
src/Models/CollectionPolicy.php
src/Models/ComplianceViolation.php
src/Models/ComplianceCheckResult.php
src/Models/ComplianceScore.php
src/Models/ScheduledComplianceReport.php
config/security-compliance.php
database/migrations/compliance/*
```

---

## Appendix B: Decision Log

| Decision | Rationale | Date |
|----------|-----------|------|
| Split package into 7 packages | Single Responsibility Principle, performance, maintainability | 2026-01-01 |
| Keep CSP in core | Directly related to security headers | 2026-01-01 |
| Separate RBAC package | Common need, often used without other security features | 2026-01-01 |
| Create meta-package for full suite | Ease migration for existing users | 2026-01-01 |

---

## Next Steps

1. Review and approve this plan
2. Begin Phase 1 (critical bug fixes)
3. Schedule Phase 2 work
4. Communicate timeline to stakeholders
