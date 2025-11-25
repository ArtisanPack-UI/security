<?php

namespace ArtisanPackUI\Security;

use ArtisanPackUI\Security\Console\Commands\CheckSecurityConfiguration;
use ArtisanPackUI\Security\Console\Commands\CheckSessionSecurity;
use ArtisanPackUI\Security\Console\Commands\ClearRateLimits;
use ArtisanPackUI\Security\Http\Middleware\EnsureSessionIsEncrypted;
use ArtisanPackUI\Security\Http\Middleware\SecurityHeadersMiddleware;
use ArtisanPackUI\Security\Http\Middleware\XssProtection;
use ArtisanPackUI\Security\Rules\NoHtml;
use ArtisanPackUI\Security\Rules\PasswordPolicy;
use ArtisanPackUI\Security\Rules\SecureFile;
use ArtisanPackUI\Security\Rules\SecureUrl;
use ArtisanPackUI\Security\Services\EnvironmentValidationService;
use ArtisanPackUI\Security\TwoFactor\TwoFactorManager;
use Exception;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\ServiceProvider;

class SecurityServiceProvider extends ServiceProvider
{

	public function register(): void
	{
		$this->app->singleton( 'security', function ( $app ) {
			return new Security();
		} );

		$this->app->singleton( TwoFactorManager::class, function () {
			return new TwoFactorManager();
		} );

		$this->mergeConfigFrom(
			__DIR__ . '/../config/security.php', 'artisanpack-security-temp'
		);
	}

	/**
	 * Perform post-registration booting of services.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public function boot(Kernel $kernel): void
	{
		$this->mergeConfiguration();

		$this->loadViewsFrom( __DIR__ . '/../resources/views', 'artisanpack-ui-security' );

		if ( $this->app->runningInConsole() ) {
			$this->publishes( [
				__DIR__ . '/../config/security.php' => config_path( 'artisanpack/security.php' ),
			], 'artisanpack-package-config' );

            $this->commands([
                CheckSessionSecurity::class,
                ClearRateLimits::class,
                CheckSecurityConfiguration::class,
            ]);
		}

        $kernel->pushMiddleware(EnsureSessionIsEncrypted::class);
        $kernel->pushMiddleware(SecurityHeadersMiddleware::class);
        $kernel->pushMiddleware(XssProtection::class);

		$this->bootTwoFactorAuthentication();

		$this->bootRateLimiting();

        $this->bootProductionValidations();

        Validator::extend('password_policy', function ($attribute, $value, $parameters, $validator) {
            return (new PasswordPolicy)->passes($attribute, $value);
        });

        Validator::extend('secure_url', function ($attribute, $value, $parameters, $validator) {
            return (new SecureUrl)->passes($attribute, $value);
        });

        Validator::extend('no_html', function ($attribute, $value, $parameters, $validator) {
            return (new NoHtml)->passes($attribute, $value);
        });

        Validator::extend('secure_file', function ($attribute, $value, $parameters, $validator) {
            $allowedMimeTypes = $parameters[0] ?? [];
            $maxSize = $parameters[1] ?? null;
            return (new SecureFile($allowedMimeTypes, $maxSize))->passes($attribute, $value);
        });
	}

	/**
	 * Merges the package's default configuration with the user's customizations.
	 *
	 * This method ensures that the user's settings in `config/artisanpack.php`
	 * take precedence over the package's default values.
	 *
	 * @since 2.0.0
	 * @return void
	 */
	protected function mergeConfiguration(): void
	{
		// Get the package's default configuration.
		$packageDefaults = config( 'artisanpack-security-temp', [] );

		// Get the user's custom configuration from config/artisanpack.php.
		$userConfig = config( 'artisanpack.security', [] );

		// Merge them, with the user's config overwriting the defaults.
		$mergedConfig = array_replace_recursive( $packageDefaults, $userConfig );

		// Set the final, correctly merged configuration.
		config( [ 'artisanpack.security' => $mergedConfig ] );
	}

	/**
	 * Boots the two-factor authentication services.
	 *
	 * Checks if the feature is enabled in the configuration, and if so,
	 * registers the necessary routes and performs development-time checks.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	protected function bootTwoFactorAuthentication(): void
	{
		if ( $this->app->runningInConsole() ) {
			if ( ! class_exists( 'AddTwoFactorToUsersTable' ) ) {
				$this->publishes( [
									  __DIR__ . '/../database/migrations/2025_09_28_205614_add_two_factor_to_users_table.php' => database_path( 'migrations/' . date( 'Y_m_d_His', time() ) . '_add_two_factor_to_users_table.php' ),
								  ], 'artisanpack-ui-security-migrations' );
			}
		}

		// If the entire 2FA feature is disabled, do not register any of its components.
		if ( ! config( 'artisanpack.security.enabled' ) ) {
			return;
		}

		$this->loadRoutesFrom( __DIR__ . '/../routes/web.php' );

		$this->loadViewsFrom( __DIR__ . '/../resources/views', 'artisanpack-ui-security' );

		// Defer route check until routes are fully loaded
		Route::matched( function () {
			static $checked = false;
			if ( ! $checked ) {
				$this->ensureTwoFactorChallengeRouteExists();
				$checked = true;
			}
		} );

	}

	/**
	 * Ensures that the required two-factor challenge route has been defined
	 * by the consuming application.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 * @throws Exception If the route is not defined.
	 */
	protected function ensureTwoFactorChallengeRouteExists(): void
	{
		$routeName = config( 'artisanpack.security.routes.verify' );

		if ( ! Route::has( $routeName ) ) {
			throw new Exception(
				"ArtisanPack UI Security: The named route '{$routeName}' is not defined. " .
				"Please ensure you have created this route in your application's web routes file as required by the package configuration."
			);
		}
	}

	/**
	 * Boots the rate limiting services.
	 *
	 * Configures the named rate limiters based on the package's configuration file.
	 *
	 * @return void
	 */
	protected function bootRateLimiting(): void
	{
		if (!config('artisanpack.security.rateLimiting.enabled')) {
			return;
		}

		$limiters = config('artisanpack.security.rateLimiting.limiters', []);

		foreach ($limiters as $name => $config) {
			$maxAttempts = $config['maxAttempts'] ?? 60;
			$decayMinutes = $config['decayMinutes'] ?? 1;

			RateLimiter::for($name, function (Request $request) use ($maxAttempts, $decayMinutes) {
				$key = optional($request->user())->id ?: $request->ip();
				return Limit::perMinutes($decayMinutes, $maxAttempts)->by($key);
			});
		}
	}

    /**
     * Boot production validations.
     *
     * @return void
     */
    protected function bootProductionValidations(): void
    {
        if ($this->app->isProduction()) {
            $validator = app(EnvironmentValidationService::class);
            $results = $validator->validate('production');

            if (!empty($results['errors'])) {
                foreach ($results['errors'] as $error) {
                    Log::critical('Security configuration error: ' . $error);
                }
            }

            if (!empty($results['warnings'])) {
                foreach ($results['warnings'] as $warning) {
                    Log::warning('Security configuration warning: ' . $warning);
                }
            }
        }
    }
}

