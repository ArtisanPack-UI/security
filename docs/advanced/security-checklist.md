---
title: Security Checklist
---

# Security Checklist

Pre-launch security checklist for applications using the ArtisanPack Security package.

## How to Use This Checklist

Review each item before deploying to production. Items are categorized by priority:

- **Critical**: Must be completed before launch
- **Important**: Should be completed before launch
- **Recommended**: Best practices for enhanced security

---

## Authentication

### Critical

- [ ] **Strong password policy enabled**
  ```php
  'complexity' => [
      'minLength' => 8,
      'requireUppercase' => true,
      'requireNumbers' => true,
      'requireSymbols' => true,
  ],
  ```

- [ ] **Breached password checking enabled**
  ```php
  'breachChecking' => ['enabled' => true],
  ```

- [ ] **Account lockout configured**
  ```php
  'lockout' => [
      'enabled' => true,
      'threshold' => 5,
      'duration_minutes' => 30,
  ],
  ```

- [ ] **Secure password hashing** (bcrypt or Argon2id)

- [ ] **Login throttling enabled**

### Important

- [ ] **Two-factor authentication available** for users
- [ ] **2FA required for admin accounts**
  ```php
  'enforcement' => [
      'mode' => 'role_based',
      'required_roles' => ['admin', 'super-admin'],
  ],
  ```

- [ ] **Recovery codes generated** for 2FA users

- [ ] **Device fingerprinting enabled** for suspicious login detection

### Recommended

- [ ] **WebAuthn/Passkeys enabled** for passwordless authentication
- [ ] **Biometric authentication available** for mobile users
- [ ] **Remember me expiration** set appropriately
- [ ] **Login notification emails** enabled for new device logins

---

## Sessions

### Critical

- [ ] **Secure session driver** (database or Redis, not file)
  ```env
  SESSION_DRIVER=database
  ```

- [ ] **Session encryption enabled**
  ```env
  SESSION_ENCRYPT=true
  ```

- [ ] **Secure cookie settings**
  ```env
  SESSION_SECURE_COOKIE=true
  SESSION_HTTP_ONLY=true
  SESSION_SAME_SITE=lax
  ```

- [ ] **Reasonable session lifetime** set

### Important

- [ ] **Session binding enabled**
  ```php
  'binding' => [
      'enabled' => true,
      'ip_address' => ['enabled' => true],
      'user_agent' => ['enabled' => true],
  ],
  ```

- [ ] **Concurrent session limits** configured

- [ ] **Session rotation enabled**
  ```php
  'rotation' => [
      'enabled' => true,
      'interval_minutes' => 15,
  ],
  ```

- [ ] **Idle timeout configured**

### Recommended

- [ ] **Absolute session timeout** set (e.g., 8 hours)
- [ ] **Session hijacking detection** enabled
- [ ] **Step-up authentication** for sensitive actions

---

## API Security

### Critical

- [ ] **Token expiration set**
  ```php
  'tokens' => ['expiration_days' => 365],
  ```

- [ ] **Rate limiting enabled**
  ```php
  'rate_limiting' => [
      'enabled' => true,
      'default_limit' => 60,
  ],
  ```

- [ ] **Token abilities** properly defined and enforced

- [ ] **HTTPS required** for all API endpoints

### Important

- [ ] **Token prefix configured** for easy identification
- [ ] **Maximum tokens per user** limited
- [ ] **Ability-based route protection**

### Recommended

- [ ] **Request signing** for sensitive endpoints
- [ ] **IP allowlisting** for server-to-server tokens
- [ ] **Token usage logging** enabled

---

## Authorization (RBAC)

### Critical

- [ ] **Roles and permissions defined** for all access levels
- [ ] **Default user role** configured
- [ ] **Super admin role** properly configured
- [ ] **Permission checks** on all protected routes

### Important

- [ ] **RBAC caching enabled** for performance
  ```php
  'rbac' => ['cache' => true],
  ```

- [ ] **Middleware applied** to protected routes
- [ ] **Blade directives used** for UI elements

### Recommended

- [ ] **Role hierarchy** defined for inheritance
- [ ] **Permission groups** organized logically
- [ ] **Regular audit** of role assignments

---

## Content Security Policy

### Critical

- [ ] **CSP enabled**
  ```php
  'csp' => ['enabled' => true],
  ```

- [ ] **Report-only mode disabled** in production
  ```php
  'report_only' => false,
  ```

- [ ] **Restrictive default-src**
  ```php
  'default-src' => ["'self'"],
  ```

- [ ] **Object-src set to none**
  ```php
  'object-src' => ["'none'"],
  ```

### Important

- [ ] **Nonces used** for inline scripts
  ```blade
  <script nonce="{{ cspNonce() }}">
  ```

- [ ] **External sources explicitly listed**
- [ ] **frame-ancestors configured** to prevent clickjacking

### Recommended

- [ ] **Violation reporting enabled**
- [ ] **Regular review** of CSP violations
- [ ] **Strict-dynamic** for trusted script chains

---

## Security Headers

### Critical

- [ ] **Security headers enabled**
- [ ] **HSTS enabled** (for HTTPS sites)
  ```php
  'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
  ```

- [ ] **X-Frame-Options** set
  ```php
  'X-Frame-Options' => 'SAMEORIGIN',
  ```

- [ ] **X-Content-Type-Options** set
  ```php
  'X-Content-Type-Options' => 'nosniff',
  ```

### Important

- [ ] **Referrer-Policy** configured
- [ ] **Permissions-Policy** configured
- [ ] **X-XSS-Protection** set (for older browsers)

### Recommended

- [ ] **HSTS preload** considered for long-term deployment
- [ ] **Regular header testing**
  ```bash
  php artisan security:test-headers
  ```

---

## File Uploads

### Critical

- [ ] **File type validation enabled**
  ```php
  'validateMimeByContent' => true,
  ```

- [ ] **Dangerous extensions blocked**
  ```php
  'blockedExtensions' => ['php', 'exe', 'sh', ...],
  ```

- [ ] **File size limits configured**

- [ ] **Files stored outside web root**
  ```php
  'storage' => ['disk' => 'local'],  // Not 'public'
  ```

### Important

- [ ] **Double extension detection** enabled
- [ ] **Null byte detection** enabled
- [ ] **EXIF stripping** for images
- [ ] **Signed URLs** for file serving

### Recommended

- [ ] **Malware scanning enabled**
- [ ] **Upload rate limiting** configured
- [ ] **Quarantine system** for suspicious files

---

## Input Validation & Output Encoding

### Critical

- [ ] **All user input validated**
- [ ] **SQL injection prevention** (use Eloquent/Query Builder)
- [ ] **XSS prevention** (escape output)
  ```blade
  {{ $userInput }}  {{-- Escaped --}}
  ```

- [ ] **CSRF protection enabled**

### Important

- [ ] **Input sanitization helpers used**
  ```php
  $email = sanitizeEmail($input);
  $text = sanitizeText($input);
  ```

- [ ] **HTML filtering** for rich text
  ```blade
  {!! kses($html) !!}
  ```

### Recommended

- [ ] **Request validation** in all controllers
- [ ] **Strong typing** for API responses

---

## Compliance

### Critical

- [ ] **Audit logging enabled**
  ```php
  'audit_logging' => ['enabled' => true],
  ```

- [ ] **Security event logging enabled**

### Important

- [ ] **Data retention policies** configured
- [ ] **GDPR features enabled** (if applicable)
  ```php
  'gdpr' => ['enabled' => true],
  ```

- [ ] **Consent management** implemented (if needed)

### Recommended

- [ ] **Compliance reports** scheduled
- [ ] **Data export functionality** tested
- [ ] **Right to erasure** functionality tested

---

## Monitoring & Alerting

### Critical

- [ ] **Security event logging** enabled
- [ ] **Error logging** configured (not exposing sensitive data)

### Important

- [ ] **Security alerts configured**
  ```php
  'alerts' => [
      'enabled' => true,
      'channels' => ['mail', 'slack'],
  ],
  ```

- [ ] **Threat detection enabled**
- [ ] **Failed login monitoring**

### Recommended

- [ ] **Security dashboard** accessible to admins
- [ ] **Regular security reports** scheduled
- [ ] **Real-time monitoring** for critical events

---

## Environment & Infrastructure

### Critical

- [ ] **DEBUG mode disabled** in production
  ```env
  APP_DEBUG=false
  ```

- [ ] **APP_ENV set to production**
  ```env
  APP_ENV=production
  ```

- [ ] **Strong APP_KEY** generated

- [ ] **HTTPS enforced**
  ```env
  FORCE_HTTPS=true
  ```

- [ ] **Sensitive env vars** not in version control

### Important

- [ ] **.env file secured** (not web-accessible)
- [ ] **Storage directory secured**
- [ ] **Config cached** for production
  ```bash
  php artisan config:cache
  ```

### Recommended

- [ ] **Dependency vulnerabilities scanned**
  ```bash
  php artisan security:scan-dependencies
  ```

- [ ] **Regular security updates** applied
- [ ] **Server hardening** completed

---

## Pre-Launch Final Checks

Run these commands before going live:

```bash
# Check security configuration
php artisan security:check-config --env=production

# Verify session security
php artisan security:check-session

# Test CSP configuration
php artisan security:csp:test

# Check API security settings
php artisan api:security:check
```

All commands should pass without critical issues.

---

## Post-Launch

### First Week

- [ ] Monitor security logs for anomalies
- [ ] Review CSP violation reports
- [ ] Verify alerting is working
- [ ] Test incident response procedures

### Ongoing

- [ ] Weekly review of security alerts
- [ ] Monthly compliance reports
- [ ] Quarterly security audits
- [ ] Annual penetration testing

---

## Related Documentation

- [Implementation Guide](implementation-guide.md)
- [Configuration Reference](configuration-reference.md)
- [Troubleshooting Guide](troubleshooting.md)
