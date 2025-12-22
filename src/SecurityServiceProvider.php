<?php

namespace ArtisanPackUI\Security;

use ArtisanPackUI\Security\Console\Commands\CheckSecurityConfiguration;
use ArtisanPackUI\Security\Console\Commands\CheckSessionSecurity;
use ArtisanPackUI\Security\Console\Commands\ClearRateLimits;
use ArtisanPackUI\Security\Console\Commands\CreateRole;
use ArtisanPackUI\Security\Console\Commands\CreatePermission;
use ArtisanPackUI\Security\Console\Commands\AssignRole;
use ArtisanPackUI\Security\Console\Commands\RevokeRole;
use ArtisanPackUI\Security\Console\Commands\CreateApiToken;
use ArtisanPackUI\Security\Console\Commands\ListApiTokens;
use ArtisanPackUI\Security\Console\Commands\RevokeApiToken;
use ArtisanPackUI\Security\Console\Commands\PruneApiTokens;
use ArtisanPackUI\Security\Console\Commands\CheckApiSecurity;
use ArtisanPackUI\Security\Http\Middleware\EnsureSessionIsEncrypted;
use ArtisanPackUI\Security\Http\Middleware\SecurityHeadersMiddleware;
use ArtisanPackUI\Security\Http\Middleware\XssProtection;
use ArtisanPackUI\Security\Http\Middleware\CheckPermission;
use ArtisanPackUI\Security\Http\Middleware\ApiSecurity;
use ArtisanPackUI\Security\Http\Middleware\ApiRateLimiting;
use ArtisanPackUI\Security\Http\Middleware\CheckTokenAbility;
use ArtisanPackUI\Security\Http\Middleware\CheckTokenAbilityAny;
use ArtisanPackUI\Security\Models\ApiToken;
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
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Blade;
use ArtisanPackUI\Security\Models\Permission;
use ArtisanPackUI\Security\Models\Role;
use Illuminate\Contracts\Auth\Authenticatable as User;

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

        $this->bootRbac();

        $this->bootApiSecurity();

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

    /**
     * Boot the RBAC services.
     *
     * @return void
     */
    protected function bootRbac(): void
    {
        if (config('artisanpack.security.rbac.enabled')) {
            $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');

            if ($this->app->runningInConsole()) {
                $this->commands([
                    CreateRole::class,
                    CreatePermission::class,
                    AssignRole::class,
                    RevokeRole::class,
                ]);
            }

            $this->app['router']->aliasMiddleware('permission', CheckPermission::class);

            // RBAC Gate integration: Only grant access when user has explicit permission.
            // Returns null for unmatched abilities so normal Gate/Policy checks can proceed.
            // Permission names are cached to avoid DB queries on every authorization check.
            Gate::before(function ($user, $ability) {
                if (! method_exists($user, 'hasPermission')) {
                    return null;
                }

                // Check against cached permission names instead of querying DB each time
                $permissionNames = $this->getCachedPermissionNames();
                if (in_array($ability, $permissionNames, true) && $user->hasPermission($ability)) {
                    return true;
                }

                return null;
            });

            // Register model events to invalidate permission cache when permissions change
            Permission::created(fn () => $this->flushPermissionNamesCache());
            Permission::updated(fn () => $this->flushPermissionNamesCache());
            Permission::deleted(fn () => $this->flushPermissionNamesCache());

            Blade::directive('role', function ($role) {
                return "<?php if(auth()->check() && auth()->user()->hasRole({$role})): ?>";
            });

            Blade::directive('endrole', function () {
                return "<?php endif; ?>";
            });

            Blade::directive('permission', function ($permission) {
                return "<?php if(auth()->check() && auth()->user()->can({$permission})): ?>";
            });

            Blade::directive('endpermission', function () {
                return "<?php endif; ?>";
            });
        }
    }

    /**
     * Get cached permission names for Gate checks.
     *
     * @return array
     */
    protected function getCachedPermissionNames(): array
    {
        $cacheKey = 'rbac_permission_names';

        if (Cache::getStore() instanceof \Illuminate\Cache\TaggableStore) {
            return Cache::tags(['rbac'])->remember($cacheKey, 3600, function () {
                return Permission::pluck('name')->toArray();
            });
        }

        return Cache::remember($cacheKey, 3600, function () {
            return Permission::pluck('name')->toArray();
        });
    }

    /**
     * Flush the cached permission names.
     *
     * @return void
     */
    protected function flushPermissionNamesCache(): void
    {
        $cacheKey = 'rbac_permission_names';

        if (Cache::getStore() instanceof \Illuminate\Cache\TaggableStore) {
            Cache::tags(['rbac'])->forget($cacheKey);
        } else {
            Cache::forget($cacheKey);
        }
    }

    /**
     * Boot the API security services.
     *
     * This method implements graceful degradation when Sanctum is not installed.
     * When SECURITY_API_ENABLED=true but Sanctum is missing:
     * - In production: Logs a critical error but continues without API features
     * - In development: Logs a warning for visibility
     *
     * @return void
     */
    protected function bootApiSecurity(): void
    {
        if (! config('artisanpack.security.api.enabled')) {
            return;
        }

        // Check if Sanctum is installed - graceful degradation if missing
        if (! class_exists(\Laravel\Sanctum\Sanctum::class)) {
            $message = 'ArtisanPack Security: API Security Layer is enabled (SECURITY_API_ENABLED=true) ' .
                'but Laravel Sanctum is not installed. API features will be disabled. ' .
                'Install Sanctum with: composer require laravel/sanctum';

            if ($this->app->isProduction()) {
                // In production, log critical as this is likely a configuration/deployment issue
                Log::critical($message);
            } else {
                // In development, warn so developers are aware
                Log::warning($message);
            }

            return;
        }

        // Configure Sanctum to use our extended token model
        $this->configureSanctum();

        // Register API rate limiters
        $this->registerApiRateLimiters();

        // Register middleware aliases
        $this->app['router']->aliasMiddleware('api.security', ApiSecurity::class);
        $this->app['router']->aliasMiddleware('api.throttle', ApiRateLimiting::class);
        $this->app['router']->aliasMiddleware('token.ability', CheckTokenAbility::class);
        $this->app['router']->aliasMiddleware('token.ability.any', CheckTokenAbilityAny::class);

        // Load API migrations
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations/api');

        // Register console commands
        if ($this->app->runningInConsole()) {
            $this->commands([
                CreateApiToken::class,
                ListApiTokens::class,
                RevokeApiToken::class,
                PruneApiTokens::class,
                CheckApiSecurity::class,
            ]);
        }
    }

    /**
     * Configure Laravel Sanctum for our extended functionality.
     *
     * @return void
     */
    protected function configureSanctum(): void
    {
        // Set custom token model
        \Laravel\Sanctum\Sanctum::usePersonalAccessTokenModel(ApiToken::class);
    }

    /**
     * Register API-specific rate limiters.
     *
     * @return void
     */
    protected function registerApiRateLimiters(): void
    {
        if (! config('artisanpack.security.api.rate_limiting.enabled')) {
            return;
        }

        // Authenticated API limiter
        RateLimiter::for('api-authenticated', function (Request $request) {
            $config = config('artisanpack.security.api.rate_limiting.authenticated', [
                'max_attempts' => 60,
                'decay_minutes' => 1,
            ]);

            return Limit::perMinutes($config['decay_minutes'], $config['max_attempts'])
                ->by($request->user()?->id ?: $request->ip());
        });

        // Guest API limiter
        RateLimiter::for('api-guest', function (Request $request) {
            $config = config('artisanpack.security.api.rate_limiting.guest', [
                'max_attempts' => 30,
                'decay_minutes' => 1,
            ]);

            return Limit::perMinutes($config['decay_minutes'], $config['max_attempts'])
                ->by($request->ip());
        });

        // Token request limiter
        RateLimiter::for('api-token-request', function (Request $request) {
            $config = config('artisanpack.security.api.rate_limiting.token_requests', [
                'max_attempts' => 5,
                'decay_minutes' => 1,
            ]);

            return Limit::perMinutes($config['decay_minutes'], $config['max_attempts'])
                ->by($request->ip());
        });
    }
}

