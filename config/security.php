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
];
    