<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| ArtisanPack UI Security — Core
|--------------------------------------------------------------------------
|
| Core security toolkit: input sanitization, output escaping, KSES
| filtering, security headers, XSS protection, basic rate limiting,
| and Content Security Policy. Authentication / 2FA / RBAC / file
| uploads / analytics / compliance live in the sibling packages now:
|
|   security-auth, security-advanced-auth, rbac, secure-uploads,
|   security-analytics, compliance
|
| Accessed throughout the package as `config('artisanpack.security.X')`.
|
*/

return [
    /*
    |--------------------------------------------------------------------------
    | Master toggle
    |--------------------------------------------------------------------------
    */
    'enabled' => env('SECURITY_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Default middleware group
    |--------------------------------------------------------------------------
    */
    'middleware' => 'web',

    /*
    |--------------------------------------------------------------------------
    | Enforce session encryption
    |--------------------------------------------------------------------------
    |
    | When true, the package verifies SESSION_ENCRYPT is enabled in
    | production environments.
    |
    */
    'encrypt' => env('SESSION_ENCRYPT', true),

    /*
    |--------------------------------------------------------------------------
    | Security response headers
    |--------------------------------------------------------------------------
    |
    | Toggles the SecurityHeadersMiddleware alias. Headers themselves
    | are configured by middleware defaults; override at the
    | middleware level when needed.
    |
    */
    'headers' => [
        'enabled' => env('SECURITY_HEADERS_ENABLED', true),
    ],

    'rateLimiting' => [
        'enabled' => env('SECURITY_RATE_LIMITING_ENABLED', true),

        'limiters' => [
            'web' => [
                'maxAttempts' => 60,
                'decayMinutes' => 1,
            ],
            'api' => [
                'maxAttempts' => 60,
                'decayMinutes' => 1,
            ],
            'login' => [
                'maxAttempts' => 5,
                'decayMinutes' => 1,
            ],
            'password_reset' => [
                'maxAttempts' => 5,
                'decayMinutes' => 1,
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | XSS Protection
    |--------------------------------------------------------------------------
    |
    | Here you may configure the XSS protection settings for your application.
    | When enabled, all incoming request data will be sanitized to prevent
    | cross-site scripting attacks.
    |
    */

    'xss' => [
        'enabled' => env('SECURITY_XSS_PROTECTION_ENABLED', false),
    ],

    /*
    |--------------------------------------------------------------------------
    | API Security Layer
    |--------------------------------------------------------------------------
    |
    | Configures the core API security middleware shipped with this package
    | (`api.security` + `api.rate_limit`). API-specific rate limiting splits
    | the budget between authenticated and guest callers so a flood of guest
    | traffic can't starve real users.
    |
    | Token CRUD, abilities, ability groups, and the token-management route
    | scaffolding moved to `artisanpack-ui/security-auth`. If you need any of
    | that, pull in the sibling package — its config wires those features.
    |
    */

    'api' => [
        'enabled' => env('SECURITY_API_ENABLED', true),

        /*
         * API-specific rate limiting consumed by the api.rate_limit middleware.
         */
        'rate_limiting' => [
            'enabled' => env('API_RATE_LIMITING_ENABLED', true),

            /*
             * Default rate limit for authenticated API requests.
             */
            'authenticated' => [
                'max_attempts' => env('API_RATE_LIMIT_AUTHENTICATED', 60),
                'decay_minutes' => 1,
            ],

            /*
             * Rate limit for unauthenticated/guest API requests.
             */
            'guest' => [
                'max_attempts' => env('API_RATE_LIMIT_GUEST', 30),
                'decay_minutes' => 1,
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Security Event Logging
    |--------------------------------------------------------------------------
    |
    | Configure comprehensive security event logging for monitoring and
    | audit purposes. Events can be stored in the database and/or logged
    | to a specific log channel.
    |
    */

    'csp' => [
        /*
         * Master toggle for CSP functionality.
         */
        'enabled' => env('SECURITY_CSP_ENABLED', true),

        /*
         * When true, violations are reported but not enforced.
         * Useful for testing new policies without breaking functionality.
         */
        'reportOnly' => env('SECURITY_CSP_REPORT_ONLY', false),

        /*
         * Default preset to use for CSP policy generation.
         * Available presets: livewire, strict, relaxed
         */
        'preset' => env('SECURITY_CSP_PRESET', 'livewire'),

        /*
         * Length of the nonce in bytes (base64 encoded).
         * 16 bytes = 22 base64 characters, recommended minimum.
         */
        'nonceLength' => 16,

        /*
         * Additional trusted external sources by directive.
         * These are merged with the preset defaults.
         */
        'additionalSources' => [
            'scriptSrc' => [
                // 'https://cdn.example.com',
            ],
            'styleSrc' => [
                'https://fonts.googleapis.com',
                'https://fonts.bunny.net',
            ],
            'fontSrc' => [
                'https://fonts.gstatic.com',
                'https://fonts.bunny.net',
            ],
            'imgSrc' => [
                'data:',
                'https:',
            ],
            'connectSrc' => [
                // 'https://api.example.com',
            ],
            'frameSrc' => [
                // 'https://www.youtube.com',
            ],
            'mediaSrc' => [
                // 'https://media.example.com',
            ],
        ],

        /*
         * Custom directives to override or extend the preset.
         * Format: 'directive-name' => ['value1', 'value2']
         */
        'customDirectives' => [
            // 'base-uri' => ["'self'"],
            // 'form-action' => ["'self'"],
        ],

        /*
         * Route patterns to exclude from CSP headers.
         * Supports wildcards: 'api/*', 'webhook/*'
         */
        'excludedRoutes' => [
            'api/*',
            'livewire/*',
        ],

        /*
         * Violation reporting configuration.
         */
        'reporting' => [
            /*
             * Enable violation reporting endpoint.
             */
            'enabled' => env('SECURITY_CSP_REPORTING_ENABLED', true),

            /*
             * URI for browsers to send violation reports.
             * This route is automatically registered by the package.
             */
            'uri' => '/csp-violation',

            /*
             * Store violations in the database for analysis.
             */
            'storeViolations' => env('SECURITY_CSP_STORE_VIOLATIONS', true),

            /*
             * Log violations to the security event logger.
             */
            'logToSecurityEvents' => true,

            /*
             * Maximum number of stored violations before pruning.
             */
            'maxStoredViolations' => 10000,

            /*
             * Days to retain violation reports.
             */
            'retentionDays' => 30,
        ],

        /*
         * Apply CSP via meta tag in addition to HTTP header.
         * Useful as a fallback but has some limitations.
         */
        'useMetaTag' => false,

        /*
         * Add upgrade-insecure-requests directive.
         * Automatically upgrades HTTP requests to HTTPS.
         */
        'upgradeInsecureRequests' => env('SECURITY_CSP_UPGRADE_INSECURE', true),

        /*
         * Add block-all-mixed-content directive.
         * Prevents loading any HTTP content on HTTPS pages.
         */
        'blockAllMixedContent' => false,
    ],

    /*
    |--------------------------------------------------------------------------
    | Security Testing Framework
    |--------------------------------------------------------------------------
    |
    | Configure the security testing framework for automated vulnerability
    | scanning, penetration testing, and performance benchmarking.
    |
    */

    'testing' => [
        'enabled' => env('SECURITY_TESTING_ENABLED', true),

        /*
         * Scanner configuration
         */
        'scanners' => [
            'owasp' => [
                'enabled' => true,
                'categories' => ['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10'],
            ],
            'dependencies' => [
                'enabled' => true,
                'composerLock' => base_path('composer.lock'),
                'packageLock' => base_path('package-lock.json'),
            ],
            'configuration' => [
                'enabled' => true,
            ],
            'headers' => [
                'enabled' => true,
            ],
        ],

        /*
         * Security gate thresholds for CI/CD
         */
        'gate' => [
            'maxCritical' => 0,
            'maxHigh' => 0,
            'maxMedium' => 10,
            'maxOverheadPercent' => 15.0,
        ],

        /*
         * Report settings
         */
        'reporting' => [
            'defaultFormat' => 'json',
            'outputPath' => storage_path('security-reports'),
            'retentionDays' => 90,
        ],

        /*
         * Baseline for differential scanning
         */
        'baseline' => [
            'path' => base_path('.security-baseline.json'),
            'autoUpdate' => false,
        ],

        /*
         * Performance benchmark settings
         */
        'benchmarks' => [
            'enabled' => true,
            'iterations' => 1000,
            'hashingIterations' => 50, // Fewer for intentionally slow operations
            'maxOverheadPercent' => 15.0,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Social Authentication (OAuth2/OIDC)
    |--------------------------------------------------------------------------
    |
    | Configure social login providers for OAuth2 and OpenID Connect
    | authentication. Each provider can be individually enabled/disabled.
    |
    */

    'logging' => [
        'channel' => env('SECURITY_LOG_CHANNEL', 'security'),
        'level' => env('SECURITY_LOG_LEVEL', 'info'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Security Commands Configuration
    |--------------------------------------------------------------------------
    |
    | Configure the security artisan commands behavior and defaults.
    |
    */

    'commands' => [
        /*
         * Security headers test command configuration.
         */
        'headers_test' => [
            /*
             * Use strict security requirements by default.
             */
            'strict_mode' => false,

            /*
             * Required headers that must be present.
             */
            'required_headers' => [
                'Strict-Transport-Security',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'Content-Security-Policy',
            ],

            /*
             * Recommended headers (warnings if missing).
             */
            'recommended_headers' => [
                'Referrer-Policy',
                'Permissions-Policy',
                'Cross-Origin-Opener-Policy',
                'Cross-Origin-Resource-Policy',
            ],
        ],

        /*
         * Dependency scan command configuration.
         */
        'dependency_scan' => [
            /*
             * Severity level that causes command to fail.
             */
            'fail_on_severity' => 'high',

            /*
             * Include outdated package warnings.
             */
            'include_outdated' => true,

            /*
             * How old a package can be before considered outdated (in years).
             */
            'outdated_threshold_years' => 2,
        ],

        /*
         * CSP generation command configuration.
         */
        'csp_generate' => [
            /*
             * Default preset for generated CSP policies.
             */
            'default_preset' => 'livewire',

            /*
             * Include violation reporting by default.
             */
            'include_report_uri' => true,
        ],

        /*
         * Security audit command configuration.
         */
        'audit' => [
            /*
             * Default output format.
             */
            'default_format' => 'json',

            /*
             * Scanners to run by default.
             */
            'default_scanners' => [
                'owasp',
                'dependencies',
                'config',
            ],
        ],
    ],
];
