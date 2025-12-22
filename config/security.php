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
];
    