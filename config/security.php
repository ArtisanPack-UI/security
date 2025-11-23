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
    */
    'security-headers' => [
        'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
        'X-Frame-Options' => 'SAMEORIGIN',
        'X-Content-Type-Options' => 'nosniff',
        'X-XSS-Protection' => '1; mode=block',
        'Referrer-Policy' => 'no-referrer-when-downgrade',
        'Content-Security-Policy' => "default-src 'self'",
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
];