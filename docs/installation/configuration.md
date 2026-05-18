---
title: Configuration Reference
---

# Configuration Reference

Complete reference for all configuration options in the ArtisanPack Security package.

## Configuration File

The main configuration file is located at `config/artisanpack/security.php`. Publish it with:

```bash
php artisan vendor:publish --provider="ArtisanPackUI\Security\SecurityServiceProvider" --tag="config"
```

## Configuration Sections

- [Authentication](#authentication)
- [Two-Factor Authentication](#two-factor-authentication)
- [Password Security](#password-security)
- [API Security](#api-security)
- [Session Security](#session-security)
- [Content Security Policy](#content-security-policy)
- [Security Headers](#security-headers)
- [File Upload Security](#file-upload-security)
- [RBAC](#rbac)
- [Compliance](#compliance)
- [Analytics](#analytics)
- [Logging](#logging)

---

## Authentication

```php
'authentication' => [
    // Enable/disable authentication features
    'enabled' => env('SECURITY_AUTH_ENABLED', true),

    // Login settings
    'login' => [
        'throttle' => [
            'enabled' => true,
            'max_attempts' => 5,
            'decay_minutes' => 1,
        ],
        'remember_me' => [
            'enabled' => true,
            'expiration_days' => 30,
        ],
    ],

    // Account lockout settings
    'lockout' => [
        'enabled' => true,
        'threshold' => 5,               // Failed attempts before lockout
        'duration_minutes' => 30,       // Lockout duration
        'progressive' => true,          // Increase duration on repeated lockouts
        'notify_user' => true,          // Email user on lockout
        'notify_admin' => true,         // Alert admins on lockout
    ],

    // Device fingerprinting
    'device_fingerprinting' => [
        'enabled' => env('SECURITY_DEVICE_FINGERPRINTING_ENABLED', true),
        'require_trusted_device' => false,
        'max_devices_per_user' => 10,
        'fingerprint_components' => [
            'user_agent',
            'accept_language',
            'screen_resolution',
            'timezone',
            'plugins',
        ],
    ],

    // Social authentication
    'social' => [
        'enabled' => env('SECURITY_SOCIAL_AUTH_ENABLED', false),
        'providers' => [
            'google' => [
                'enabled' => env('SECURITY_SOCIAL_GOOGLE_ENABLED', false),
                'client_id' => env('GOOGLE_CLIENT_ID'),
                'client_secret' => env('GOOGLE_CLIENT_SECRET'),
            ],
            'microsoft' => [
                'enabled' => env('SECURITY_SOCIAL_MICROSOFT_ENABLED', false),
                'client_id' => env('MICROSOFT_CLIENT_ID'),
                'client_secret' => env('MICROSOFT_CLIENT_SECRET'),
                'tenant' => env('MICROSOFT_TENANT', 'common'),
            ],
            'github' => [
                'enabled' => env('SECURITY_SOCIAL_GITHUB_ENABLED', false),
                'client_id' => env('GITHUB_CLIENT_ID'),
                'client_secret' => env('GITHUB_CLIENT_SECRET'),
            ],
            'facebook' => [
                'enabled' => env('SECURITY_SOCIAL_FACEBOOK_ENABLED', false),
                'client_id' => env('FACEBOOK_CLIENT_ID'),
                'client_secret' => env('FACEBOOK_CLIENT_SECRET'),
            ],
            'apple' => [
                'enabled' => env('SECURITY_SOCIAL_APPLE_ENABLED', false),
                'client_id' => env('APPLE_CLIENT_ID'),
                'client_secret' => env('APPLE_CLIENT_SECRET'),
                'team_id' => env('APPLE_TEAM_ID'),
                'key_id' => env('APPLE_KEY_ID'),
            ],
            'linkedin' => [
                'enabled' => env('SECURITY_SOCIAL_LINKEDIN_ENABLED', false),
                'client_id' => env('LINKEDIN_CLIENT_ID'),
                'client_secret' => env('LINKEDIN_CLIENT_SECRET'),
            ],
        ],
        'auto_register' => true,
        'link_existing_accounts' => true,
    ],

    // SSO authentication
    'sso' => [
        'enabled' => env('SECURITY_SSO_ENABLED', false),

        'saml' => [
            'enabled' => env('SECURITY_SAML_ENABLED', false),
            'idp_entity_id' => env('SAML_IDP_ENTITY_ID'),
            'idp_sso_url' => env('SAML_IDP_SSO_URL'),
            'idp_slo_url' => env('SAML_IDP_SLO_URL'),
            'idp_certificate' => env('SAML_IDP_CERTIFICATE'),
            'sp_entity_id' => env('SAML_SP_ENTITY_ID'),
            'sp_acs_url' => env('SAML_SP_ACS_URL'),
            'sp_sls_url' => env('SAML_SP_SLS_URL'),
            'sp_certificate' => env('SAML_SP_CERTIFICATE'),
            'sp_private_key' => env('SAML_SP_PRIVATE_KEY'),
            'name_id_format' => 'emailAddress',
            'authn_context' => 'PasswordProtectedTransport',
            'sign_authn_requests' => true,
            'want_assertions_signed' => true,
            'want_assertions_encrypted' => false,
        ],

        'oidc' => [
            'enabled' => env('SECURITY_OIDC_ENABLED', false),
            'issuer' => env('OIDC_ISSUER'),
            'client_id' => env('OIDC_CLIENT_ID'),
            'client_secret' => env('OIDC_CLIENT_SECRET'),
            'redirect_uri' => env('OIDC_REDIRECT_URI'),
            'scopes' => ['openid', 'profile', 'email'],
            'response_type' => 'code',
            'use_pkce' => true,
        ],

        'ldap' => [
            'enabled' => env('SECURITY_LDAP_ENABLED', false),
            'hosts' => [env('LDAP_HOST', 'ldap.example.com')],
            'port' => env('LDAP_PORT', 389),
            'base_dn' => env('LDAP_BASE_DN'),
            'username' => env('LDAP_USERNAME'),
            'password' => env('LDAP_PASSWORD'),
            'use_ssl' => env('LDAP_SSL', false),
            'use_tls' => env('LDAP_TLS', true),
            'user_filter' => '(&(objectClass=user)(sAMAccountName={username}))',
            'sync_attributes' => [
                'email' => 'mail',
                'name' => 'displayName',
            ],
        ],
    ],

    // WebAuthn/Passkeys
    'webauthn' => [
        'enabled' => env('SECURITY_WEBAUTHN_ENABLED', false),
        'relying_party_name' => env('APP_NAME'),
        'relying_party_id' => env('WEBAUTHN_RP_ID'),
        'origin' => env('APP_URL'),
        'timeout' => 60000,
        'attestation_conveyance' => 'none',
        'authenticator_attachment' => null,
        'user_verification' => 'preferred',
        'resident_key' => 'preferred',
        'algorithms' => [-7, -257],  // ES256, RS256
    ],

    // Biometric authentication
    'biometric' => [
        'enabled' => env('SECURITY_BIOMETRIC_ENABLED', false),
        'require_strong_biometric' => true,
        'fallback_to_pin' => false,
        'max_attempts' => 3,
    ],
],
```

### Option Reference

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `authentication.enabled` | bool | `true` | Enable authentication features |
| `authentication.login.throttle.max_attempts` | int | `5` | Max login attempts before throttling |
| `authentication.login.throttle.decay_minutes` | int | `1` | Throttle decay time |
| `authentication.lockout.threshold` | int | `5` | Failed attempts before lockout |
| `authentication.lockout.duration_minutes` | int | `30` | Lockout duration |
| `authentication.lockout.progressive` | bool | `true` | Increase duration on repeated lockouts |
| `authentication.device_fingerprinting.enabled` | bool | `true` | Enable device tracking |
| `authentication.device_fingerprinting.max_devices_per_user` | int | `10` | Max devices per user |

---

## Two-Factor Authentication

```php
'twoFactor' => [
    'enabled' => env('SECURITY_2FA_ENABLED', true),

    // Enforcement settings
    'enforcement' => [
        'mode' => 'optional',           // 'disabled', 'optional', 'required', 'role_based'
        'required_roles' => ['admin'],  // Roles that require 2FA
        'grace_period_days' => 7,       // Days before 2FA becomes required
    ],

    // TOTP settings
    'totp' => [
        'enabled' => true,
        'issuer' => env('APP_NAME'),
        'algorithm' => 'sha1',
        'digits' => 6,
        'period' => 30,
        'window' => 1,                  // Allow codes from adjacent periods
    ],

    // SMS backup codes
    'sms' => [
        'enabled' => false,
        'driver' => 'twilio',
        'from' => env('TWILIO_FROM'),
    ],

    // Email backup codes
    'email' => [
        'enabled' => true,
        'expiration_minutes' => 10,
    ],

    // Recovery codes
    'recovery_codes' => [
        'count' => 8,
        'length' => 10,
        'regenerate_on_use' => false,
    ],

    // Remember device
    'remember_device' => [
        'enabled' => true,
        'expiration_days' => 30,
    ],
],
```

### Option Reference

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `twoFactor.enabled` | bool | `true` | Enable 2FA features |
| `twoFactor.enforcement.mode` | string | `'optional'` | 2FA enforcement mode |
| `twoFactor.enforcement.grace_period_days` | int | `7` | Grace period before required |
| `twoFactor.totp.digits` | int | `6` | TOTP code length |
| `twoFactor.totp.period` | int | `30` | TOTP code validity period |
| `twoFactor.recovery_codes.count` | int | `8` | Number of recovery codes |

---

## Password Security

```php
'passwordSecurity' => [
    'enabled' => env('SECURITY_PASSWORD_ENABLED', true),

    // Complexity requirements
    'complexity' => [
        'minLength' => 8,
        'maxLength' => 128,
        'requireUppercase' => true,
        'requireLowercase' => true,
        'requireNumbers' => true,
        'requireSymbols' => true,
        'minUniqueChars' => 4,
        'disallowCommonPasswords' => true,
        'disallowUserInfo' => true,     // Disallow name, email in password
    ],

    // Password history
    'history' => [
        'enabled' => true,
        'count' => 5,                   // Remember last N passwords
    ],

    // Password expiration
    'expiration' => [
        'enabled' => false,
        'days' => 90,
        'warn_days_before' => 14,
        'exclude_roles' => ['service-account'],
    ],

    // Breach checking (Have I Been Pwned)
    'breachChecking' => [
        'enabled' => env('SECURITY_HIBP_ENABLED', true),
        'onRegistration' => true,
        'onPasswordChange' => true,
        'threshold' => 1,               // Block if seen N+ times
        'failOpen' => true,             // Allow if service unavailable
    ],

    // Password strength meter
    'strengthMeter' => [
        'enabled' => true,
        'minScore' => 3,                // zxcvbn score (0-4)
    ],
],
```

### Option Reference

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `passwordSecurity.complexity.minLength` | int | `8` | Minimum password length |
| `passwordSecurity.complexity.requireUppercase` | bool | `true` | Require uppercase letter |
| `passwordSecurity.complexity.requireSymbols` | bool | `true` | Require special character |
| `passwordSecurity.history.count` | int | `5` | Passwords to remember |
| `passwordSecurity.expiration.days` | int | `90` | Days until expiration |
| `passwordSecurity.breachChecking.enabled` | bool | `true` | Check HIBP database |

---

## API Security

```php
'api' => [
    'enabled' => env('SECURITY_API_ENABLED', true),

    // Token settings
    'tokens' => [
        'expiration_days' => env('SECURITY_API_TOKEN_EXPIRATION', 365),
        'hash_algorithm' => 'sha256',
        'prefix' => 'apt_',
        'max_tokens_per_user' => 10,
    ],

    // Token abilities
    'abilities' => [
        'read' => 'Read data',
        'write' => 'Create and update data',
        'delete' => 'Delete data',
        'admin' => 'Administrative access',
    ],

    // Ability groups (presets)
    'ability_groups' => [
        'read_only' => ['read'],
        'standard' => ['read', 'write'],
        'full' => ['read', 'write', 'delete'],
        'admin' => ['read', 'write', 'delete', 'admin'],
    ],

    // Rate limiting
    'rate_limiting' => [
        'enabled' => true,
        'default_limit' => 60,          // Requests per minute
        'by_ability' => [
            'read' => 120,
            'write' => 30,
            'delete' => 10,
        ],
    ],

    // Request signing
    'signing' => [
        'enabled' => false,
        'algorithm' => 'hmac-sha256',
        'timestamp_tolerance' => 300,   // Seconds
    ],

    // IP allowlist
    'ip_allowlist' => [
        'enabled' => false,
        'addresses' => [],
        'per_token' => true,            // Allow per-token IP restrictions
    ],
],
```

### Option Reference

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `api.tokens.expiration_days` | int | `365` | Token expiration in days |
| `api.tokens.max_tokens_per_user` | int | `10` | Max tokens per user |
| `api.rate_limiting.default_limit` | int | `60` | Default rate limit |
| `api.signing.enabled` | bool | `false` | Require signed requests |

---

## Session Security

```php
'advanced_sessions' => [
    'enabled' => env('SECURITY_ADVANCED_SESSIONS_ENABLED', true),

    // Session binding
    'binding' => [
        'enabled' => true,
        'ip_address' => [
            'enabled' => true,
            'strictness' => 'subnet',   // 'none', 'subnet', 'exact'
        ],
        'user_agent' => [
            'enabled' => true,
            'strictness' => 'exact',    // 'none', 'browser_only', 'exact'
        ],
        'bind_to_device' => true,
    ],

    // Concurrent sessions
    'concurrent_sessions' => [
        'enabled' => true,
        'max_sessions' => 5,
        'strategy' => 'oldest',         // 'oldest', 'newest'
    ],

    // Session rotation
    'rotation' => [
        'enabled' => true,
        'interval_minutes' => 15,
        'on_privilege_change' => true,
    ],

    // Timeouts
    'timeouts' => [
        'idle_minutes' => 30,
        'idle_warning_minutes' => 25,
        'absolute_minutes' => 480,      // 8 hours
        'extend_on_activity' => true,
    ],

    // Hijacking detection
    'hijacking_detection' => [
        'enabled' => true,
        'action' => 'terminate',        // 'terminate', 'require_reauth', 'notify'
    ],
],

// Step-up authentication
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

### Option Reference

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `advanced_sessions.binding.ip_address.strictness` | string | `'subnet'` | IP binding strictness |
| `advanced_sessions.concurrent_sessions.max_sessions` | int | `5` | Max concurrent sessions |
| `advanced_sessions.rotation.interval_minutes` | int | `15` | Session rotation interval |
| `advanced_sessions.timeouts.idle_minutes` | int | `30` | Idle timeout |
| `advanced_sessions.timeouts.absolute_minutes` | int | `480` | Absolute session timeout |

---

## Content Security Policy

```php
'csp' => [
    'enabled' => env('SECURITY_CSP_ENABLED', true),
    'report_only' => env('SECURITY_CSP_REPORT_ONLY', false),

    // CSP directives
    'directives' => [
        'default-src' => ["'self'"],
        'script-src' => ["'self'", "'nonce'"],
        'style-src' => ["'self'", "'nonce'", "'unsafe-inline'"],
        'img-src' => ["'self'", 'data:', 'https:'],
        'font-src' => ["'self'", 'https://fonts.gstatic.com'],
        'connect-src' => ["'self'"],
        'media-src' => ["'self'"],
        'object-src' => ["'none'"],
        'frame-src' => ["'self'"],
        'frame-ancestors' => ["'self'"],
        'form-action' => ["'self'"],
        'base-uri' => ["'self'"],
        'upgrade-insecure-requests' => true,
    ],

    // Nonce settings
    'nonce' => [
        'enabled' => true,
        'directives' => ['script-src', 'style-src'],
        'length' => 32,
    ],

    // Violation reporting
    'report' => [
        'enabled' => true,
        'endpoint' => '/csp-report',
        'log_violations' => true,
        'store_violations' => true,
        'notify_on_violation' => false,
    ],
],
```

### Option Reference

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `csp.enabled` | bool | `true` | Enable CSP headers |
| `csp.report_only` | bool | `false` | Use report-only mode |
| `csp.nonce.enabled` | bool | `true` | Enable nonce generation |
| `csp.report.enabled` | bool | `true` | Enable violation reporting |

---

## Security Headers

```php
'security_headers' => [
    'enabled' => env('SECURITY_HEADERS_ENABLED', true),

    'headers' => [
        'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
        'X-Frame-Options' => 'SAMEORIGIN',
        'X-Content-Type-Options' => 'nosniff',
        'X-XSS-Protection' => '1; mode=block',
        'Referrer-Policy' => 'strict-origin-when-cross-origin',
        'Permissions-Policy' => 'geolocation=(), microphone=(), camera=()',
    ],

    // HSTS settings
    'hsts' => [
        'enabled' => true,
        'max_age' => 31536000,
        'include_subdomains' => true,
        'preload' => false,
    ],
],
```

---

## File Upload Security

```php
'fileUpload' => [
    'enabled' => env('SECURITY_FILE_UPLOAD_ENABLED', true),

    // Allowed file types
    'allowedMimeTypes' => [
        'image/jpeg', 'image/png', 'image/gif', 'image/webp',
        'application/pdf', 'text/plain', 'text/csv',
    ],

    'allowedExtensions' => [
        'jpg', 'jpeg', 'png', 'gif', 'webp', 'pdf', 'txt', 'csv',
    ],

    // Blocked file types
    'blockedExtensions' => [
        'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps',
        'exe', 'com', 'bat', 'cmd', 'sh', 'bash',
        'js', 'jsx', 'ts', 'tsx',
        'asp', 'aspx', 'jsp', 'cgi', 'pl', 'py', 'rb',
        'htaccess', 'htpasswd', 'svg',
    ],

    'blockedMimeTypes' => [
        'application/x-httpd-php', 'application/x-php',
        'application/x-executable', 'application/javascript',
        'image/svg+xml',
    ],

    // Size restrictions
    'maxFileSize' => 10 * 1024 * 1024,  // 10 MB
    'maxFileSizePerType' => [
        'image/*' => 5 * 1024 * 1024,
        'application/pdf' => 20 * 1024 * 1024,
    ],

    // Content validation
    'validateMimeByContent' => true,
    'checkForDoubleExtensions' => true,
    'checkForNullBytes' => true,
    'stripExifData' => true,

    // Malware scanning
    'malwareScanning' => [
        'enabled' => env('SECURITY_MALWARE_SCANNING_ENABLED', false),
        'driver' => env('SECURITY_MALWARE_DRIVER', 'null'),
        'failOnScanError' => true,
        'async' => false,
        'quarantinePath' => storage_path('app/quarantine'),

        'clamav' => [
            'socketPath' => '/var/run/clamav/clamd.sock',
            'binaryPath' => '/usr/bin/clamscan',
            'timeout' => 30,
        ],

        'virustotal' => [
            'apiKey' => env('VIRUSTOTAL_API_KEY'),
            'timeout' => 60,
        ],
    ],

    // Rate limiting
    'rateLimiting' => [
        'enabled' => true,
        'maxUploadsPerMinute' => 10,
        'maxUploadsPerHour' => 100,
        'maxTotalSizePerHour' => 100 * 1024 * 1024,
    ],

    // Storage
    'storage' => [
        'disk' => 'local',
        'path' => 'secure-uploads',
        'hashFilenames' => true,
        'preserveOriginalName' => true,
        'organizeByDate' => true,
    ],

    // Serving
    'serving' => [
        'useSignedUrls' => true,
        'signedUrlExpiration' => 60,
        'forceDownload' => false,
    ],
],
```

---

## RBAC

```php
'rbac' => [
    'enabled' => env('SECURITY_RBAC_ENABLED', true),

    // Role settings
    'roles' => [
        'cache' => true,
        'cache_ttl' => 3600,
        'super_admin_role' => 'super-admin',
    ],

    // Permission settings
    'permissions' => [
        'cache' => true,
        'cache_ttl' => 3600,
        'wildcard' => true,             // Allow permission.*
    ],

    // Default roles
    'default_roles' => [
        'user',
    ],

    // Role hierarchy
    'hierarchy' => [
        'super-admin' => ['admin'],
        'admin' => ['editor', 'moderator'],
        'editor' => ['user'],
    ],
],
```

---

## Compliance

```php
'compliance' => [
    'enabled' => env('SECURITY_COMPLIANCE_ENABLED', true),

    'gdpr' => [
        'enabled' => true,
        'data_portability' => true,
        'right_to_erasure' => true,
        'consent_required' => true,
    ],

    'consent' => [
        'enabled' => true,
        'categories' => [
            'necessary' => [
                'name' => 'Necessary',
                'required' => true,
            ],
            'analytics' => [
                'name' => 'Analytics',
                'required' => false,
            ],
            'marketing' => [
                'name' => 'Marketing',
                'required' => false,
            ],
        ],
        'version' => '1.0',
        'expiry_days' => 365,
    ],

    'data_retention' => [
        'enabled' => true,
        'policies' => [
            'security_logs' => 90,
            'audit_logs' => 365,
            'session_data' => 30,
            'failed_logins' => 30,
            'api_logs' => 90,
        ],
        'auto_cleanup' => true,
        'cleanup_schedule' => 'daily',
    ],

    'audit_logging' => [
        'enabled' => true,
        'log_reads' => false,
        'log_writes' => true,
        'log_deletions' => true,
        'log_exports' => true,
        'include_ip' => true,
        'include_user_agent' => true,
    ],

    'anonymization' => [
        'enabled' => true,
        'method' => 'pseudonymize',
        'retain_analytics' => true,
    ],
],
```

---

## Analytics

```php
'analytics' => [
    'enabled' => env('SECURITY_ANALYTICS_ENABLED', true),

    'metrics' => [
        'enabled' => true,
        'driver' => 'database',
        'retention_days' => 90,
        'sample_rate' => 1.0,
        'collect' => [
            'authentication' => true,
            'authorization' => true,
            'api_requests' => true,
            'security_events' => true,
            'performance' => true,
        ],
    ],

    'dashboard' => [
        'enabled' => true,
        'refresh_interval' => 60,
        'default_period' => '7d',
    ],

    'alerts' => [
        'enabled' => true,
        'channels' => ['database', 'mail'],
        'throttle_minutes' => 15,
        'thresholds' => [
            'failed_logins_per_hour' => 50,
            'blocked_requests_per_hour' => 100,
            'suspicious_activities_per_day' => 10,
        ],
    ],

    'threat_detection' => [
        'enabled' => true,
        'rules' => [
            'brute_force' => true,
            'credential_stuffing' => true,
            'session_hijacking' => true,
            'privilege_escalation' => true,
        ],
    ],
],
```

---

## Logging

```php
'logging' => [
    'enabled' => env('SECURITY_LOGGING_ENABLED', true),

    'channel' => env('SECURITY_LOG_CHANNEL', 'security'),

    'events' => [
        'authentication' => true,
        'authorization' => true,
        'password_changes' => true,
        'two_factor' => true,
        'api_tokens' => true,
        'sessions' => true,
        'file_uploads' => true,
        'suspicious_activity' => true,
    ],

    'include' => [
        'ip_address' => true,
        'user_agent' => true,
        'request_id' => true,
        'user_id' => true,
    ],

    'sensitive_fields' => [
        'password',
        'password_confirmation',
        'current_password',
        'token',
        'secret',
    ],
],
```

---

## Related Documentation

- [Environment Variables](environment-variables.md)
- [Implementation Guide](implementation-guide.md)
- [Troubleshooting Guide](troubleshooting.md)
