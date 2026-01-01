<?php

use ArtisanPackUI\Security\TwoFactor\Providers\EmailProvider;

return [
    /*
     |--------------------------------------------------------------------------
     | Enable Two-Factor Authentication
     |--------------------------------------------------------------------------
     |
     | This option controls whether the two-factor authentication feature is
     | enabled globally. When set to false, the package will not register
     | its routes or middleware, effectively disabling the feature.
     |
     */
    'enabled' => false,

    /*
     |--------------------------------------------------------------------------
     | Middleware
     |--------------------------------------------------------------------------
     |
     | This option controls the middleware that will be used for the routes.
     | By default, the 'web' middleware is used.
     |
     */
    'middleware' => 'web',

    /*
    |--------------------------------------------------------------------------
    | Enforce Session Encryption
    |--------------------------------------------------------------------------
    |
    | This option determines whether the package should enforce that the
    | application's session cookie is encrypted. When enabled, this
    | package will verify that session encryption is not disabled
    | in production environments.
    |
    */
    'encrypt' => env('SESSION_ENCRYPT', true),

	'routes' => [
		/*
		 * The route name where users will be redirected to enter their 2FA code.
		 * The consuming application is responsible for creating this route and view.
		 */
		'verify' => 'two-factor.challenge',
	],

	'two_factor' => [
		/*
		 * The default two-factor authentication provider. This provider will be
		 * used for all 2FA operations unless a different provider is specified.
		 *
		 * Supported: "email"
		 */
		'default'   => env( 'TWO_FACTOR_PROVIDER', 'email' ),

		/*
		 * Here you may configure the providers for two-factor authentication.
		 * You can add your own providers here, but they must implement the
		 * `TwoFactorProvider` interface.
		 */
		'providers' => [

			'email' => [
				'driver' => EmailProvider::class,
			],

		],
	],

    /*
    |--------------------------------------------------------------------------
    | Security Headers
    |--------------------------------------------------------------------------
    |
    | Here you may define the security headers that will be applied to all
    | responses. You can override these values in your application's
    | config/artisanpack/security.php file.
    |
    | Note: For Livewire/Alpine.js applications, the CSP policy below includes:
    |   - 'unsafe-eval' for Alpine.js expression evaluation
    |   - 'unsafe-inline' for Livewire's dynamic inline styles
    |   - External font sources (fonts.bunny.net, fonts.gstatic.com)
    |   - Data URIs for inline images/SVGs
    |
    | For production, consider implementing CSP nonces instead of 'unsafe-inline'
    | and 'unsafe-eval' for enhanced security.
    |
    */
    'security-headers' => [
        'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
        'X-Frame-Options' => 'SAMEORIGIN',
        'X-Content-Type-Options' => 'nosniff',
        'X-XSS-Protection' => '1; mode=block',
        'Referrer-Policy' => 'no-referrer-when-downgrade',
        'Content-Security-Policy' => implode('; ', [
            "default-src 'self'",
            "script-src 'self' 'unsafe-eval' 'unsafe-inline'",
            "style-src 'self' 'unsafe-inline' https://fonts.bunny.net https://fonts.googleapis.com",
            "font-src 'self' https://fonts.bunny.net https://fonts.gstatic.com data:",
            "img-src 'self' data: https:",
            "connect-src 'self'",
            "frame-ancestors 'self'",
        ]),
    ],

    /*
    |--------------------------------------------------------------------------
    | Role-Based Access Control (RBAC)
    |--------------------------------------------------------------------------
    |
    | Here you may configure the RBAC settings for your application.
    | When enabled, all RBAC features will be available.
    |
    */
    'rbac' => [
        'enabled' => env('SECURITY_RBAC_ENABLED', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | Rate Limiting
    |--------------------------------------------------------------------------
    |
    | Here you may configure the rate limiting settings for your application.
    | You can define different limiters for various parts of your
    | application, such as the API, web routes, or specific actions
    | like login attempts and password resets.
    |
    */
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
    | Here you may configure the API security settings for your application.
    | This feature extends Laravel Sanctum with additional token management,
    | expiration, revocation, and API-specific rate limiting.
    |
    | Note: This feature requires Laravel Sanctum to be installed.
    |
    */
    'api' => [
        'enabled' => env('SECURITY_API_ENABLED', true),

        /*
         * Authentication driver configuration.
         * Sanctum is the default and recommended driver.
         */
        'driver' => 'sanctum',

        /*
         * Token configuration for Sanctum.
         */
        'tokens' => [
            /*
             * Default token expiration in minutes.
             * Set to null for non-expiring tokens.
             */
            'expiration' => env('API_TOKEN_EXPIRATION', 60 * 24 * 7), // 7 days

            /*
             * Prefix for token names to identify tokens created by this package.
             */
            'prefix' => env('API_TOKEN_PREFIX', 'artisanpack'),
        ],

        /*
         * Define available token abilities/scopes.
         * These can be assigned when creating tokens.
         */
        'abilities' => [
            'read' => 'Read-only access to resources',
            'write' => 'Create and update resources',
            'delete' => 'Delete resources',
            'admin' => 'Full administrative access',
        ],

        /*
         * Ability groups for convenience.
         * Assign a group name to get all included abilities.
         */
        'ability_groups' => [
            'readonly' => ['read'],
            'standard' => ['read', 'write'],
            'full' => ['read', 'write', 'delete'],
            'admin' => ['read', 'write', 'delete', 'admin'],
        ],

        /*
         * API-specific rate limiting configuration.
         * These override the general rate limiting settings for API routes.
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

            /*
             * Rate limit for token creation/authentication endpoints.
             */
            'token_requests' => [
                'max_attempts' => env('API_RATE_LIMIT_TOKEN', 5),
                'decay_minutes' => 1,
            ],
        ],

        /*
         * Routes configuration for token management endpoints.
         * Set enabled to true to register built-in token management routes.
         */
        'routes' => [
            'enabled' => env('API_ROUTES_ENABLED', false),
            'prefix' => 'api/auth',
            'middleware' => ['api'],
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
    'eventLogging' => [
        /*
         * Master toggle for security event logging.
         */
        'enabled' => env('SECURITY_EVENT_LOGGING_ENABLED', true),

        /*
         * Storage options for security events.
         */
        'storage' => [
            /*
             * Store events in the database.
             */
            'database' => env('SECURITY_EVENTS_STORE_DB', true),

            /*
             * Log channel to use for event logging.
             * Set to null to use the default log channel.
             */
            'logChannel' => env('SECURITY_LOG_CHANNEL', null),
        ],

        /*
         * Configure which event types to log.
         */
        'events' => [
            'authentication' => [
                'enabled' => true,
                'logLevel' => 'info',
                'events' => [
                    'loginSuccess' => true,
                    'loginFailed' => true,
                    'logout' => true,
                    'lockout' => true,
                    'passwordReset' => true,
                    'registered' => true,
                    'emailVerified' => true,
                    'otherDeviceLogout' => true,
                    'twoFactorSuccess' => true,
                    'twoFactorFailed' => true,
                ],
            ],
            'authorization' => [
                'enabled' => true,
                'logLevel' => 'warning',
                'events' => [
                    'permissionDenied' => true,
                    'roleCheckFailed' => true,
                ],
            ],
            'apiAccess' => [
                'enabled' => true,
                'logLevel' => 'info',
                'events' => [
                    'tokenCreated' => true,
                    'tokenRevoked' => true,
                    'tokenExpiredAccess' => true,
                    'invalidToken' => true,
                    'abilityDenied' => true,
                ],
            ],
            'securityViolations' => [
                'enabled' => true,
                'logLevel' => 'error',
                'events' => [
                    'cspViolation' => true,
                    'rateLimitExceeded' => true,
                    'invalidSignature' => true,
                ],
            ],
            'roleChanges' => [
                'enabled' => true,
                'logLevel' => 'info',
            ],
            'permissionChanges' => [
                'enabled' => true,
                'logLevel' => 'info',
            ],
            'tokenManagement' => [
                'enabled' => true,
                'logLevel' => 'info',
            ],
        ],

        /*
         * Retention policy for security events.
         */
        'retention' => [
            'enabled' => env('SECURITY_EVENTS_RETENTION_ENABLED', true),
            'days' => env('SECURITY_EVENTS_RETENTION_DAYS', 90),
            'keepCritical' => true,
        ],

        /*
         * Suspicious activity detection configuration.
         */
        'suspiciousActivity' => [
            'enabled' => env('SECURITY_SUSPICIOUS_DETECTION_ENABLED', true),
            'thresholds' => [
                'failedLoginsPerIp' => 5,
                'failedLoginsPerUser' => 3,
                'apiErrorsPerToken' => 10,
                'permissionDenialsPerUser' => 5,
            ],
            'windowMinutes' => 15,
        ],

        /*
         * Alerting configuration for suspicious activities.
         */
        'alerting' => [
            'enabled' => env('SECURITY_ALERTS_ENABLED', false),
            'channels' => ['mail'],
            'recipients' => env('SECURITY_ALERT_RECIPIENTS', ''),
            'throttleMinutes' => 15,
        ],

        /*
         * Security dashboard configuration.
         *
         * By default, the dashboard requires the 'viewSecurityDashboard' gate.
         * You can customize this by defining the gate in your AuthServiceProvider
         * or by changing the middleware below to use your own authorization.
         *
         * Example gate definition in AuthServiceProvider::boot():
         *   Gate::define('viewSecurityDashboard', fn ($user) => $user->hasRole('admin'));
         */
        'dashboard' => [
            'enabled' => env('SECURITY_DASHBOARD_ENABLED', true),
            'routePrefix' => 'security',
            'middleware' => ['web', 'auth', 'can:viewSecurityDashboard'],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Password Security
    |--------------------------------------------------------------------------
    |
    | Configure enhanced password security features including complexity
    | validation, history tracking, expiration policies, strength metering,
    | and breach checking via HaveIBeenPwned.
    |
    */
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

    /*
    |--------------------------------------------------------------------------
    | File Upload Security
    |--------------------------------------------------------------------------
    |
    | Configure secure file upload handling with comprehensive validation,
    | threat protection, malware scanning, rate limiting, and secure storage.
    |
    */
    'fileUpload' => [
        'enabled' => env('SECURITY_FILE_UPLOAD_ENABLED', true),

        /*
         * File type validation - allowlists
         */
        'allowedMimeTypes' => [
            'image/jpeg',
            'image/png',
            'image/gif',
            'image/webp',
            'application/pdf',
            'text/plain',
            'text/csv',
        ],

        'allowedExtensions' => [
            'jpg', 'jpeg', 'png', 'gif', 'webp',
            'pdf', 'txt', 'csv',
        ],

        /*
         * Blocked patterns - always rejected regardless of allowlists
         */
        'blockedExtensions' => [
            'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps',
            'exe', 'com', 'bat', 'cmd', 'sh', 'bash',
            'js', 'jsx', 'ts', 'tsx',
            'asp', 'aspx', 'jsp', 'cgi', 'pl', 'py', 'rb',
            'htaccess', 'htpasswd',
            'svg', // Can contain embedded scripts
        ],

        'blockedMimeTypes' => [
            'application/x-httpd-php',
            'application/x-php',
            'text/x-php',
            'application/x-executable',
            'application/x-msdownload',
            'application/javascript',
            'text/javascript',
            'image/svg+xml', // Can contain embedded scripts
        ],

        /*
         * Size restrictions
         */
        'maxFileSize' => 10 * 1024 * 1024, // 10 MB default (in bytes)
        'maxFileSizePerType' => [
            'image/*' => 5 * 1024 * 1024,         // 5 MB for images
            'application/pdf' => 20 * 1024 * 1024, // 20 MB for PDFs
        ],

        /*
         * Content validation
         */
        'validateMimeByContent' => true,   // Inspect actual file content, not just extension
        'checkForDoubleExtensions' => true, // Detect file.php.jpg tricks
        'checkForNullBytes' => true,       // Detect file.php%00.jpg tricks
        'stripExifData' => true,           // Remove EXIF metadata from images

        /*
         * Malware scanning integration
         */
        'malwareScanning' => [
            'enabled' => env('SECURITY_MALWARE_SCANNING_ENABLED', false),
            'driver' => env('SECURITY_MALWARE_DRIVER', 'null'), // null, clamav, virustotal
            'failOnScanError' => true,      // Reject upload if scanner is unavailable
            'async' => false,               // Scan asynchronously (quarantine until scanned)
            'quarantinePath' => storage_path('app/quarantine'),

            // ClamAV configuration
            'clamav' => [
                'socketPath' => env('CLAMAV_SOCKET_PATH', '/var/run/clamav/clamd.sock'),
                'binaryPath' => env('CLAMAV_BINARY_PATH', '/usr/bin/clamscan'),
                'timeout' => 30,
            ],

            // VirusTotal configuration
            'virustotal' => [
                'apiKey' => env('VIRUSTOTAL_API_KEY'),
                'timeout' => 60,
            ],
        ],

        /*
         * Rate limiting for uploads
         */
        'rateLimiting' => [
            'enabled' => env('SECURITY_UPLOAD_RATE_LIMITING_ENABLED', true),
            'maxUploadsPerMinute' => 10,
            'maxUploadsPerHour' => 100,
            'maxTotalSizePerHour' => 100 * 1024 * 1024, // 100 MB per hour
        ],

        /*
         * Secure storage settings
         */
        'storage' => [
            'disk' => env('SECURITY_UPLOAD_DISK', 'local'),
            'path' => 'secure-uploads',
            'hashFilenames' => true,        // Store with hashed names
            'preserveOriginalName' => true, // Store original name in metadata
            'organizeByDate' => true,       // Store in YYYY/MM/DD subdirectories
        ],

        /*
         * Secure file serving
         */
        'serving' => [
            'useSignedUrls' => true,
            'signedUrlExpiration' => 60,    // minutes
            'forceDownload' => false,       // Force Content-Disposition: attachment
            'allowedReferrers' => [],       // Empty = allow all, or list of allowed domains
        ],

        /*
         * Event logging
         */
        'logging' => [
            'uploads' => true,
            'rejections' => true,
            'malwareDetections' => true,
            'downloads' => true,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Content Security Policy (CSP)
    |--------------------------------------------------------------------------
    |
    | Configure Content Security Policy for your application. CSP helps prevent
    | XSS attacks by specifying which dynamic resources are allowed to load.
    | This implementation is optimized for Livewire applications using nonces
    | and strict-dynamic for enhanced security.
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
    'social_auth' => [
        'enabled' => env('SECURITY_SOCIAL_AUTH_ENABLED', true),

        /*
         * Allow users to register via social login.
         * When false, users must already have an account.
         */
        'allow_registration' => env('SECURITY_SOCIAL_REGISTRATION_ENABLED', true),

        /*
         * Allow users to link multiple social accounts.
         */
        'allow_linking' => true,

        /*
         * Require email verification for social logins.
         */
        'require_email_verification' => true,

        /*
         * Automatically link social accounts to existing users with the same email.
         */
        'auto_link_by_email' => true,

        /*
         * Social authentication providers configuration.
         */
        'providers' => [
            'google' => [
                'enabled' => env('SOCIAL_GOOGLE_ENABLED', false),
                'client_id' => env('SOCIAL_GOOGLE_CLIENT_ID'),
                'client_secret' => env('SOCIAL_GOOGLE_CLIENT_SECRET'),
                'scopes' => ['openid', 'email', 'profile'],
            ],
            'microsoft' => [
                'enabled' => env('SOCIAL_MICROSOFT_ENABLED', false),
                'client_id' => env('SOCIAL_MICROSOFT_CLIENT_ID'),
                'client_secret' => env('SOCIAL_MICROSOFT_CLIENT_SECRET'),
                'tenant' => env('SOCIAL_MICROSOFT_TENANT', 'common'),
                'scopes' => ['openid', 'email', 'profile', 'User.Read'],
            ],
            'github' => [
                'enabled' => env('SOCIAL_GITHUB_ENABLED', false),
                'client_id' => env('SOCIAL_GITHUB_CLIENT_ID'),
                'client_secret' => env('SOCIAL_GITHUB_CLIENT_SECRET'),
                'scopes' => ['user:email'],
            ],
            'facebook' => [
                'enabled' => env('SOCIAL_FACEBOOK_ENABLED', false),
                'client_id' => env('SOCIAL_FACEBOOK_CLIENT_ID'),
                'client_secret' => env('SOCIAL_FACEBOOK_CLIENT_SECRET'),
                'scopes' => ['email', 'public_profile'],
            ],
            'apple' => [
                'enabled' => env('SOCIAL_APPLE_ENABLED', false),
                'client_id' => env('SOCIAL_APPLE_CLIENT_ID'),
                'team_id' => env('SOCIAL_APPLE_TEAM_ID'),
                'key_id' => env('SOCIAL_APPLE_KEY_ID'),
                'private_key_path' => env('SOCIAL_APPLE_PRIVATE_KEY_PATH'),
                'scopes' => ['name', 'email'],
            ],
            'linkedin' => [
                'enabled' => env('SOCIAL_LINKEDIN_ENABLED', false),
                'client_id' => env('SOCIAL_LINKEDIN_CLIENT_ID'),
                'client_secret' => env('SOCIAL_LINKEDIN_CLIENT_SECRET'),
                'scopes' => ['openid', 'profile', 'email'],
            ],
        ],

        /*
         * Routes configuration.
         */
        'routes' => [
            'enabled' => true,
            'prefix' => 'auth/social',
            'middleware' => ['web'],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Single Sign-On (SSO)
    |--------------------------------------------------------------------------
    |
    | Configure enterprise SSO using SAML 2.0, OpenID Connect, or LDAP.
    | SSO configurations are stored in the database for dynamic management.
    |
    */
    'sso' => [
        'enabled' => env('SECURITY_SSO_ENABLED', true),

        /*
         * Allow JIT (Just-In-Time) user provisioning from SSO.
         */
        'jit_provisioning' => env('SECURITY_SSO_JIT_PROVISIONING', true),

        /*
         * Default role to assign to JIT-provisioned users.
         */
        'default_role' => env('SECURITY_SSO_DEFAULT_ROLE', null),

        /*
         * SAML 2.0 Service Provider configuration.
         */
        'saml' => [
            'entity_id' => env('SAML_ENTITY_ID', env('APP_URL').'/saml/metadata'),
            'acs_url' => env('SAML_ACS_URL', env('APP_URL').'/auth/sso/{idp}/acs'),
            'sls_url' => env('SAML_SLS_URL', env('APP_URL').'/auth/sso/{idp}/sls'),
            'name_id_format' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
            'want_assertions_signed' => true,
            'want_messages_signed' => true,
            'sp_certificate' => env('SAML_SP_CERTIFICATE_PATH'),
            'sp_private_key' => env('SAML_SP_PRIVATE_KEY_PATH'),
        ],

        /*
         * OIDC client defaults.
         */
        'oidc' => [
            'response_type' => 'code',
            'scopes' => ['openid', 'email', 'profile'],
        ],

        /*
         * LDAP defaults.
         */
        'ldap' => [
            'port' => 389,
            'use_ssl' => false,
            'use_tls' => true,
            'timeout' => 5,
            'user_dn_format' => 'uid=%s,ou=users,dc=example,dc=com',
            'user_filter' => '(&(objectClass=person)(uid=%s))',
            'group_filter' => '(&(objectClass=groupOfNames)(member=%s))',
        ],

        /*
         * Routes configuration.
         */
        'routes' => [
            'enabled' => true,
            'prefix' => 'auth/sso',
            'middleware' => ['web'],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | WebAuthn/FIDO2 Passwordless Authentication
    |--------------------------------------------------------------------------
    |
    | Configure WebAuthn for passwordless authentication using security keys,
    | platform authenticators (Touch ID, Face ID, Windows Hello), and passkeys.
    |
    */
    'webauthn' => [
        'enabled' => env('SECURITY_WEBAUTHN_ENABLED', true),

        /*
         * Relying Party (RP) configuration.
         */
        'relying_party' => [
            'name' => env('WEBAUTHN_RP_NAME', null), // null = use app.name at runtime
            'id' => env('WEBAUTHN_RP_ID', null), // null = use request host
            'origin' => env('WEBAUTHN_RP_ORIGIN', null), // null = use request origin
        ],

        /*
         * Authenticator selection preferences for registration.
         */
        'authenticator_selection' => [
            /*
             * Preferred authenticator attachment.
             * Options: 'platform', 'cross-platform', null (any)
             */
            'authenticator_attachment' => null,

            /*
             * Require resident key (discoverable credential).
             * Required for passkeys and usernameless authentication.
             */
            'resident_key' => 'preferred', // 'required', 'preferred', 'discouraged'

            /*
             * User verification requirement.
             * Options: 'required', 'preferred', 'discouraged'
             */
            'user_verification' => 'preferred',
        ],

        /*
         * Attestation conveyance preference.
         * Options: 'none', 'indirect', 'direct', 'enterprise'
         */
        'attestation' => 'none',

        /*
         * Supported public key algorithms (COSE identifiers).
         */
        'algorithms' => [
            -7,   // ES256 (ECDSA with P-256 and SHA-256)
            -257, // RS256 (RSASSA-PKCS1-v1_5 with SHA-256)
        ],

        /*
         * Challenge timeout in milliseconds.
         */
        'timeout' => 60000, // 60 seconds

        /*
         * Allow users to register multiple credentials.
         */
        'allow_multiple_credentials' => true,

        /*
         * Maximum number of credentials per user.
         */
        'max_credentials_per_user' => 10,

        /*
         * Routes configuration.
         */
        'routes' => [
            'enabled' => true,
            'prefix' => 'auth/webauthn',
            'middleware' => ['web', 'auth'],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Biometric Authentication
    |--------------------------------------------------------------------------
    |
    | Configure biometric authentication using platform authenticators
    | (Touch ID, Face ID, Windows Hello, Android Biometrics).
    |
    */
    'biometric' => [
        'enabled' => env('SECURITY_BIOMETRIC_ENABLED', true),

        /*
         * Available biometric providers.
         */
        'providers' => [
            'webauthn' => [
                'enabled' => true,
                'driver' => \ArtisanPackUI\Security\Authentication\Biometric\WebAuthnBiometricProvider::class,
            ],
        ],

        /*
         * Default biometric provider.
         */
        'default' => 'webauthn',

        /*
         * Allow biometric as primary authentication method.
         */
        'allow_primary_auth' => true,

        /*
         * Require biometric re-verification for sensitive actions.
         */
        'require_for_sensitive_actions' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Device Fingerprinting
    |--------------------------------------------------------------------------
    |
    | Configure device fingerprinting for tracking and trust management.
    | Helps detect suspicious activity and new device logins.
    |
    */
    'device_fingerprinting' => [
        'enabled' => env('SECURITY_DEVICE_FINGERPRINTING_ENABLED', true),

        /*
         * Components to include in device fingerprint.
         */
        'components' => [
            'user_agent' => true,
            'accept_language' => true,
            'accept_encoding' => true,
            'timezone' => true,
            'screen_resolution' => true,
            'color_depth' => true,
            'platform' => true,
            'plugins' => false, // Deprecated in modern browsers
            'canvas' => true,
            'webgl' => true,
            'fonts' => false, // Privacy concerns
        ],

        /*
         * Trust score thresholds.
         */
        'trust_thresholds' => [
            'suspicious' => 30,  // Below this is suspicious
            'trusted' => 70,     // Above this is trusted
        ],

        /*
         * Auto-trust devices after N successful logins.
         */
        'auto_trust_after_logins' => 3,

        /*
         * Maximum devices per user.
         */
        'max_devices_per_user' => 10,

        /*
         * Device inactivity cleanup (days).
         */
        'cleanup_after_days' => 180,

        /*
         * Notify user on new device detection.
         */
        'notify_on_new_device' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Advanced Session Security
    |--------------------------------------------------------------------------
    |
    | Configure advanced session management with binding, concurrency limits,
    | rotation policies, and hijacking detection.
    |
    */
    'advanced_sessions' => [
        'enabled' => env('SECURITY_ADVANCED_SESSIONS_ENABLED', true),

        /*
         * Session binding configuration.
         * Bind sessions to specific client attributes.
         */
        'binding' => [
            'enabled' => true,
            'ip_address' => [
                'enabled' => true,
                'strictness' => 'subnet', // 'none', 'subnet', 'exact'
            ],
            'user_agent' => [
                'enabled' => true,
                'strictness' => 'exact', // 'none', 'browser_only', 'exact'
            ],
            'bind_to_device' => true, // Requires device fingerprinting
        ],

        /*
         * Concurrent session limits.
         */
        'concurrent_sessions' => [
            'enabled' => true,
            'max_sessions' => 5,
            'strategy' => 'oldest', // 'oldest', 'newest'
        ],

        /*
         * Session rotation policy.
         */
        'rotation' => [
            'enabled' => true,
            'interval_minutes' => 15, // Rotate session ID every N minutes
            'on_privilege_change' => true, // Rotate after login, role change, etc.
        ],

        /*
         * Session timeouts.
         */
        'timeouts' => [
            'idle_minutes' => 30,           // Expire after N minutes of inactivity
            'idle_warning_minutes' => 25,   // Warn user before idle expiration
            'absolute_minutes' => 480,      // Maximum session lifetime (8 hours)
            'extend_on_activity' => true,   // Reset idle timeout on activity
        ],

        /*
         * Session hijacking detection.
         */
        'hijacking_detection' => [
            'enabled' => true,
            'action' => 'terminate', // 'terminate', 'require_reauth', 'notify'
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Suspicious Activity Detection
    |--------------------------------------------------------------------------
    |
    | Configure advanced suspicious activity detection beyond basic rate limiting.
    | Includes impossible travel detection, behavioral analysis, and risk scoring.
    |
    */
    'suspicious_activity' => [
        'enabled' => env('SECURITY_SUSPICIOUS_ACTIVITY_ENABLED', true),

        /*
         * Detection types to enable.
         */
        'detectors' => [
            'impossible_travel' => [
                'enabled' => true,
                'max_speed_kmh' => 1000, // Max realistic travel speed
            ],
            'brute_force' => [
                'enabled' => true,
                'threshold_per_ip' => 10,
                'threshold_per_user' => 5,
                'window_minutes' => 15,
            ],
            'credential_stuffing' => [
                'enabled' => true,
                'unique_users_threshold' => 5, // Same IP trying multiple users
                'window_minutes' => 10,
            ],
            'unusual_location' => [
                'enabled' => true,
                'use_geolocation' => true,
            ],
            'unusual_device' => [
                'enabled' => true,
            ],
            'unusual_time' => [
                'enabled' => true,
                'normal_hours_start' => 6,
                'normal_hours_end' => 22,
            ],
            'rapid_requests' => [
                'enabled' => true,
                'threshold' => 100,
                'window_seconds' => 60,
            ],
            'bot_behavior' => [
                'enabled' => true,
                'check_user_agent' => true,
                'check_request_patterns' => true,
            ],
        ],

        /*
         * Risk scoring configuration.
         */
        'risk_scoring' => [
            'weights' => [
                'impossible_travel' => 40,
                'brute_force' => 35,
                'credential_stuffing' => 35,
                'unusual_location' => 20,
                'unusual_device' => 15,
                'unusual_time' => 10,
                'rapid_requests' => 25,
                'bot_behavior' => 30,
            ],
            'thresholds' => [
                'low' => 20,
                'medium' => 40,
                'high' => 60,
                'critical' => 80,
            ],
        ],

        /*
         * Actions based on severity.
         */
        'actions' => [
            'low' => 'notify',        // Log and optionally notify
            'medium' => 'captcha',    // Require CAPTCHA
            'high' => 'step_up',      // Require re-authentication
            'critical' => 'block',    // Block the request
        ],

        /*
         * Geolocation settings.
         */
        'geolocation' => [
            'enabled' => true,
            'provider' => 'maxmind', // 'maxmind', 'ip2location', 'ipinfo'
            'database_path' => storage_path('app/geoip/GeoLite2-City.mmdb'),
            'cache_results' => true,
            'cache_ttl' => 86400, // 24 hours
        ],

        /*
         * Retention for suspicious activity records.
         */
        'retention_days' => 90,
    ],

    /*
    |--------------------------------------------------------------------------
    | Account Lockout Policies
    |--------------------------------------------------------------------------
    |
    | Configure account lockout policies for preventing brute force attacks.
    | Supports progressive lockouts, soft lockouts, and permanent bans.
    |
    */
    'account_lockout' => [
        'enabled' => env('SECURITY_ACCOUNT_LOCKOUT_ENABLED', true),

        /*
         * Base lockout configuration.
         */
        'max_attempts' => 5,
        'lockout_duration' => 15, // Minutes

        /*
         * Progressive lockout multiplier.
         * Each subsequent lockout increases duration by this factor.
         */
        'progressive' => [
            'enabled' => true,
            'multiplier' => 2.0,
            'max_duration' => 1440, // Maximum lockout duration in minutes (24 hours)
        ],

        /*
         * Soft lockout (CAPTCHA) settings.
         * Applied before hard lockout.
         */
        'soft_lockout' => [
            'enabled' => true,
            'attempts_threshold' => 3, // Require CAPTCHA after N failed attempts
        ],

        /*
         * Permanent lockout for severe violations.
         */
        'permanent_lockout' => [
            'enabled' => true,
            'consecutive_lockouts' => 5, // Lock permanently after N lockouts
            'require_admin_unlock' => true,
        ],

        /*
         * IP-based lockout.
         */
        'ip_lockout' => [
            'enabled' => true,
            'max_attempts_per_ip' => 20,
            'lockout_duration' => 60, // Minutes
        ],

        /*
         * Notification settings.
         */
        'notifications' => [
            'notify_user' => true,
            'notify_admin' => true,
            'admin_threshold' => 'high', // Notify admin on high+ severity
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Step-Up Authentication
    |--------------------------------------------------------------------------
    |
    | Configure step-up authentication for sensitive actions.
    | Requires re-authentication after a period of inactivity.
    |
    */
    'step_up_authentication' => [
        'enabled' => env('SECURITY_STEP_UP_ENABLED', true),

        /*
         * Timeout in minutes before requiring re-authentication.
         */
        'timeout_minutes' => 15,

        /*
         * Available authentication methods for step-up.
         */
        'methods' => [
            'password' => true,
            '2fa' => true,
            'webauthn' => true,
            'biometric' => true,
        ],

        /*
         * Routes that require step-up authentication.
         */
        'protected_routes' => [
            // 'user/security/*',
            // 'admin/*',
        ],

        /*
         * Actions that trigger step-up authentication.
         */
        'protected_actions' => [
            'password_change',
            'email_change',
            'two_factor_disable',
            'delete_account',
            'download_data',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Security Notifications
    |--------------------------------------------------------------------------
    |
    | Configure security-related notifications sent to users and admins.
    |
    */
    'notifications' => [
        'enabled' => env('SECURITY_NOTIFICATIONS_ENABLED', true),

        /*
         * Notification toggles.
         */
        'new_device_login' => true,
        'suspicious_activity' => true,
        'account_locked' => true,
        'webauthn_credential' => true,
        'social_account' => true,
        'session_hijacking' => true,

        /*
         * SMS notifications for critical events.
         */
        'sms_for_critical' => false,

        /*
         * Admin email addresses for security alerts.
         */
        'admin_emails' => env('SECURITY_ADMIN_EMAILS', ''),

        /*
         * Custom notification classes (optional overrides).
         */
        'classes' => [
            'new_device' => \ArtisanPackUI\Security\Notifications\NewDeviceLogin::class,
            'suspicious_activity' => \ArtisanPackUI\Security\Notifications\SuspiciousLoginAttempt::class,
            'account_locked' => \ArtisanPackUI\Security\Notifications\AccountLockedNotification::class,
            'webauthn_added' => \ArtisanPackUI\Security\Notifications\WebAuthnCredentialAdded::class,
            'webauthn_removed' => \ArtisanPackUI\Security\Notifications\WebAuthnCredentialRemoved::class,
            'social_linked' => \ArtisanPackUI\Security\Notifications\SocialAccountLinkedNotification::class,
            'social_unlinked' => \ArtisanPackUI\Security\Notifications\SocialAccountUnlinkedNotification::class,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Authentication Routes
    |--------------------------------------------------------------------------
    |
    | Configure the routes for advanced authentication features.
    |
    */
    'auth_routes' => [
        'enabled' => env('SECURITY_AUTH_ROUTES_ENABLED', true),
        'prefix' => 'auth',
        'middleware' => ['web'],
    ],

    /*
    |--------------------------------------------------------------------------
    | Logging
    |--------------------------------------------------------------------------
    |
    | Configure security-specific logging.
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
         * User security check command configuration.
         */
        'user_security' => [
            /*
             * Maximum password age in days before warning.
             */
            'password_max_age_days' => 90,

            /*
             * Send notifications to users with security issues.
             */
            'notify_on_issues' => false,

            /*
             * Security checks to run by default.
             */
            'checks' => [
                'password' => true,
                '2fa' => true,
                'sessions' => true,
                'lockouts' => true,
                'suspicious_activity' => true,
                'api_tokens' => true,
            ],
        ],

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
    