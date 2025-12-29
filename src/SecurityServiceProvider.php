<?php

namespace ArtisanPackUI\Security;

use ArtisanPackUI\Security\Console\Commands\CheckSecurityConfiguration;
use ArtisanPackUI\Security\Console\Commands\CheckSessionSecurity;
use ArtisanPackUI\Security\Console\Commands\CleanupExpiredFiles;
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
use ArtisanPackUI\Security\Console\Commands\ListSecurityEvents;
use ArtisanPackUI\Security\Console\Commands\ClearSecurityEvents;
use ArtisanPackUI\Security\Console\Commands\ExportSecurityEvents;
use ArtisanPackUI\Security\Console\Commands\ScanQuarantinedFiles;
use ArtisanPackUI\Security\Console\Commands\SecurityEventStats;
use ArtisanPackUI\Security\Console\Commands\DetectSuspiciousActivity;
use ArtisanPackUI\Security\Console\Commands\CspPrune;
use ArtisanPackUI\Security\Console\Commands\CspStats;
use ArtisanPackUI\Security\Console\Commands\CspTest;
use ArtisanPackUI\Security\Console\Commands\AnalyticsProcessCommand;
use ArtisanPackUI\Security\Console\Commands\GenerateSecurityReportCommand;
use ArtisanPackUI\Security\Console\Commands\PruneAnalyticsDataCommand;
use ArtisanPackUI\Security\Console\Commands\SyncThreatFeedsCommand;
use ArtisanPackUI\Security\Console\Commands\TestSiemConnectionCommand;
use ArtisanPackUI\Security\Console\Commands\UpdateBehaviorBaselinesCommand;
use ArtisanPackUI\Security\Console\Commands\SecurityAudit;
use ArtisanPackUI\Security\Console\Commands\SecurityAuthAudit;
use ArtisanPackUI\Security\Console\Commands\SecurityBaseline;
use ArtisanPackUI\Security\Console\Commands\SecurityBenchmarkCommand;
use ArtisanPackUI\Security\Console\Commands\SecurityScan;
use ArtisanPackUI\Security\Console\Commands\CleanupExpiredSessions;
use ArtisanPackUI\Security\Console\Commands\CleanupInactiveDevices;
use ArtisanPackUI\Security\Console\Commands\ListWebAuthnCredentials;
use ArtisanPackUI\Security\Console\Commands\ManageAccountLockout;
use ArtisanPackUI\Security\Console\Commands\ManageSsoConfiguration;
use ArtisanPackUI\Security\Console\Commands\PruneSuspiciousActivity;
use ArtisanPackUI\Security\Console\Commands\TerminateUserSessions;
use ArtisanPackUI\Security\Contracts\BreachCheckerInterface;
use ArtisanPackUI\Security\Contracts\CspPolicyInterface;
use ArtisanPackUI\Security\Contracts\FileValidatorInterface;
use ArtisanPackUI\Security\Contracts\MalwareScannerInterface;
use ArtisanPackUI\Security\Contracts\PasswordSecurityServiceInterface;
use ArtisanPackUI\Security\Contracts\SecureFileStorageInterface;
use ArtisanPackUI\Security\Contracts\SecurityEventLoggerInterface;
use ArtisanPackUI\Security\Http\Middleware\ContentSecurityPolicy;
use ArtisanPackUI\Security\Http\Middleware\EnsureSessionIsEncrypted;
use ArtisanPackUI\Security\Http\Middleware\ScanUploadedFiles;
use ArtisanPackUI\Security\Http\Middleware\SecurityHeadersMiddleware;
use ArtisanPackUI\Security\Http\Middleware\ValidateFileUpload;
use ArtisanPackUI\Security\Http\Middleware\XssProtection;
use ArtisanPackUI\Security\Http\Middleware\CheckPermission;
use ArtisanPackUI\Security\Http\Middleware\ApiSecurity;
use ArtisanPackUI\Security\Http\Middleware\ApiRateLimiting;
use ArtisanPackUI\Security\Http\Middleware\CheckTokenAbility;
use ArtisanPackUI\Security\Http\Middleware\CheckTokenAbilityAny;
use ArtisanPackUI\Security\Http\Middleware\EnforcePasswordPolicy;
use ArtisanPackUI\Security\Http\Middleware\RequirePasswordChange;
use ArtisanPackUI\Security\Http\Middleware\CheckAccountLockout;
use ArtisanPackUI\Security\Http\Middleware\DetectSuspiciousActivity as DetectSuspiciousActivityMiddleware;
use ArtisanPackUI\Security\Http\Middleware\EnforceSessionBinding;
use ArtisanPackUI\Security\Http\Middleware\RequireTrustedDevice;
use ArtisanPackUI\Security\Http\Middleware\StepUpAuthentication;
use ArtisanPackUI\Security\Http\Middleware\ValidateDeviceFingerprint;
use ArtisanPackUI\Security\Listeners\LogAdvancedAuthEvents;
use ArtisanPackUI\Security\Listeners\LogAuthenticationEvents;
use ArtisanPackUI\Security\Listeners\HandleSuspiciousActivity;
use ArtisanPackUI\Security\Listeners\SendAccountLockedNotification;
use ArtisanPackUI\Security\Listeners\SendNewDeviceNotification;
use ArtisanPackUI\Security\Listeners\SendSocialAccountNotification;
use ArtisanPackUI\Security\Listeners\SendWebAuthnCredentialNotification;
use ArtisanPackUI\Security\Authentication\Contracts\AccountLockoutInterface;
use ArtisanPackUI\Security\Authentication\Contracts\BiometricProviderInterface;
use ArtisanPackUI\Security\Authentication\Contracts\DeviceFingerprintInterface;
use ArtisanPackUI\Security\Authentication\Contracts\SessionSecurityInterface;
use ArtisanPackUI\Security\Authentication\Contracts\SocialProviderInterface;
use ArtisanPackUI\Security\Authentication\Contracts\SsoProviderInterface;
use ArtisanPackUI\Security\Authentication\Contracts\SuspiciousActivityDetectorInterface;
use ArtisanPackUI\Security\Authentication\Contracts\WebAuthnInterface;
use ArtisanPackUI\Security\Authentication\Biometric\BiometricManager;
use ArtisanPackUI\Security\Authentication\Device\DeviceFingerprintService;
use ArtisanPackUI\Security\Authentication\Detection\SuspiciousActivityService;
use ArtisanPackUI\Security\Authentication\Lockout\AccountLockoutManager;
use ArtisanPackUI\Security\Authentication\Session\AdvancedSessionManager;
use ArtisanPackUI\Security\Authentication\Social\SocialAuthManager;
use ArtisanPackUI\Security\Authentication\Sso\SsoManager;
use ArtisanPackUI\Security\Authentication\WebAuthn\WebAuthnManager;
use ArtisanPackUI\Security\Events\NewDeviceDetected;
use ArtisanPackUI\Security\Events\AccountLocked;
use ArtisanPackUI\Security\Events\SuspiciousActivityDetected;
use ArtisanPackUI\Security\Livewire\AccountLockoutStatus;
use ArtisanPackUI\Security\Livewire\BiometricManager as BiometricManagerComponent;
use ArtisanPackUI\Security\Livewire\CspDashboard;
use ArtisanPackUI\Security\Livewire\DeviceManager;
use ArtisanPackUI\Security\Livewire\PasswordStrengthMeter;
use ArtisanPackUI\Security\Livewire\SecurityDashboard;
use ArtisanPackUI\Security\Livewire\SecurityEventList;
use ArtisanPackUI\Security\Livewire\SecurityStats;
use ArtisanPackUI\Security\Livewire\SessionManager;
use ArtisanPackUI\Security\Livewire\SocialAccountsManager;
use ArtisanPackUI\Security\Livewire\StepUpAuthenticationModal;
use ArtisanPackUI\Security\Livewire\SuspiciousActivityList;
use ArtisanPackUI\Security\Livewire\WebAuthnCredentialsManager;
use ArtisanPackUI\Security\Services\Csp\CspNonceGenerator;
use ArtisanPackUI\Security\Services\Csp\CspPolicyService;
use ArtisanPackUI\Security\Services\Csp\CspViolationHandler;
use ArtisanPackUI\Security\View\Components\CspNonce;
use ArtisanPackUI\Security\Models\ApiToken;
use ArtisanPackUI\Security\Observers\PermissionObserver;
use ArtisanPackUI\Security\Observers\RoleObserver;
use ArtisanPackUI\Security\Rules\NoHtml;
use ArtisanPackUI\Security\Rules\NotCompromised;
use ArtisanPackUI\Security\Rules\PasswordComplexity;
use ArtisanPackUI\Security\Rules\PasswordHistoryRule;
use ArtisanPackUI\Security\Rules\PasswordPolicy;
use ArtisanPackUI\Security\Rules\SafeFilename;
use ArtisanPackUI\Security\Rules\SecureFile;
use ArtisanPackUI\Security\Rules\SecureUrl;
use ArtisanPackUI\Security\Services\EnvironmentValidationService;
use ArtisanPackUI\Security\Services\FileUploadRateLimiter;
use ArtisanPackUI\Security\Services\FileValidationService;
use ArtisanPackUI\Security\Services\HaveIBeenPwnedService;
use ArtisanPackUI\Security\Services\PasswordSecurityService;
use ArtisanPackUI\Security\Services\Scanners\ClamAvScanner;
use ArtisanPackUI\Security\Services\Scanners\NullScanner;
use ArtisanPackUI\Security\Services\Scanners\VirusTotalScanner;
use ArtisanPackUI\Security\Services\SecureFileStorageService;
use ArtisanPackUI\Security\Services\SecurityEventLogger;
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
use Livewire\Livewire;

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

		$this->app->singleton(SecurityEventLoggerInterface::class, function ($app) {
			return new SecurityEventLogger();
		});

		$this->app->alias(SecurityEventLoggerInterface::class, 'security-events');

		// Register breach checker service
		$this->app->singleton(BreachCheckerInterface::class, function ($app) {
			return new HaveIBeenPwnedService();
		});

		// Register password security service
		$this->app->singleton(PasswordSecurityServiceInterface::class, function ($app) {
			return new PasswordSecurityService(
				$app->make(BreachCheckerInterface::class)
			);
		});

		// Register file upload security services
		$this->app->singleton(FileValidatorInterface::class, FileValidationService::class);

		$this->app->singleton(MalwareScannerInterface::class, function ($app) {
			$driver = config('artisanpack.security.fileUpload.malwareScanning.driver', 'null');

			return match ($driver) {
				'clamav' => new ClamAvScanner(),
				'virustotal' => new VirusTotalScanner(),
				default => new NullScanner(),
			};
		});

		$this->app->singleton(FileUploadRateLimiter::class, function ($app) {
			return new FileUploadRateLimiter($app->make(\Illuminate\Cache\RateLimiter::class));
		});

		$this->app->singleton(SecureFileStorageInterface::class, function ($app) {
			return new SecureFileStorageService(
				$app->make(\Illuminate\Filesystem\FilesystemManager::class),
				$app->make(FileValidatorInterface::class),
				$app->make(MalwareScannerInterface::class)
			);
		});

		// Register CSP services
		$this->app->scoped(CspNonceGenerator::class, function ($app) {
			return new CspNonceGenerator(
				(int) config('artisanpack.security.csp.nonce.length', 16)
			);
		});

		$this->app->scoped(CspPolicyInterface::class, function ($app) {
			return new CspPolicyService(
				$app->make(CspNonceGenerator::class)
			);
		});

		$this->app->singleton(CspViolationHandler::class, function ($app) {
			$logger = null;
			if (config('artisanpack.security.csp.reporting.logToSecurityEvents', true)) {
				$logger = $app->make(SecurityEventLoggerInterface::class);
			}

			return new CspViolationHandler($logger);
		});

		// Register advanced authentication services
		$this->registerAdvancedAuthenticationServices();

		$this->mergeConfigFrom(
			__DIR__ . '/../config/security.php', 'artisanpack-security-temp'
		);
	}

	/**
	 * Register advanced authentication services.
	 *
	 * @return void
	 */
	protected function registerAdvancedAuthenticationServices(): void
	{
		// Social Authentication Manager
		$this->app->singleton(SocialAuthManager::class, function ($app) {
			return new SocialAuthManager();
		});

		// SSO Manager
		$this->app->singleton(SsoManager::class, function ($app) {
			return new SsoManager();
		});

		// WebAuthn Manager
		$this->app->singleton(WebAuthnManager::class, function ($app) {
			return new WebAuthnManager();
		});

		// Biometric Manager
		$this->app->singleton(BiometricManager::class, function ($app) {
			return new BiometricManager();
		});

		// Device Fingerprint Service
		$this->app->singleton(DeviceFingerprintService::class, function ($app) {
			return new DeviceFingerprintService();
		});

		// Advanced Session Manager
		$this->app->singleton(AdvancedSessionManager::class, function ($app) {
			return new AdvancedSessionManager();
		});

		// Suspicious Activity Service
		$this->app->singleton(SuspiciousActivityService::class, function ($app) {
			return new SuspiciousActivityService();
		});

		// Account Lockout Manager
		$this->app->singleton(AccountLockoutManager::class, function ($app) {
			return new AccountLockoutManager();
		});

		// Bind interfaces to implementations
		$this->app->bind(DeviceFingerprintInterface::class, DeviceFingerprintService::class);
		$this->app->bind(SessionSecurityInterface::class, AdvancedSessionManager::class);
		$this->app->bind(SuspiciousActivityDetectorInterface::class, SuspiciousActivityService::class);
		$this->app->bind(AccountLockoutInterface::class, AccountLockoutManager::class);
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

        $this->bootEventLogging();

        $this->bootPasswordSecurity();

        $this->bootFileUploadSecurity();

        $this->bootCsp();

        $this->bootSecurityTesting();

        $this->bootAdvancedAuthentication();

        $this->bootAnalytics();

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
            return (new SecureFile())->passes($attribute, $value);
        });

        Validator::extend('safe_filename', function ($attribute, $value, $parameters, $validator) {
            return (new SafeFilename())->passes($attribute, $value);
        });

        // Password security validation rules
        // Note: These rules auto-resolve the authenticated user from the request context.
        // For explicit user context, use the rule classes directly in form requests:
        //   new PasswordComplexity($user), new PasswordHistoryRule($user)
        Validator::extend('password_complexity', function ($attribute, $value, $parameters, $validator) {
            $user = request()->user();
            return (new PasswordComplexity($user))->passes($attribute, $value);
        });

        Validator::extend('password_history', function ($attribute, $value, $parameters, $validator) {
            $user = request()->user();
            return (new PasswordHistoryRule($user))->passes($attribute, $value);
        });

        Validator::extend('not_compromised', function ($attribute, $value, $parameters, $validator) {
            $threshold = (int) ($parameters[0] ?? 0);
            return (new NotCompromised($threshold))->passes($attribute, $value);
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

    /**
     * Boot the security event logging services.
     *
     * @return void
     */
    protected function bootEventLogging(): void
    {
        if (! config('artisanpack.security.eventLogging.enabled')) {
            return;
        }

        // Load migrations
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');

        // Load views with namespace
        $this->loadViewsFrom(__DIR__ . '/../resources/views', 'security');

        // Register authentication event listeners
        Event::subscribe(LogAuthenticationEvents::class);

        // Register model observers for RBAC changes if RBAC is enabled
        if (config('artisanpack.security.rbac.enabled')) {
            Role::observe(RoleObserver::class);
            Permission::observe(PermissionObserver::class);
        }

        // Register console commands
        if ($this->app->runningInConsole()) {
            $this->commands([
                ListSecurityEvents::class,
                ClearSecurityEvents::class,
                ExportSecurityEvents::class,
                SecurityEventStats::class,
                DetectSuspiciousActivity::class,
            ]);
        }

        // Register default gate for dashboard authorization
        $this->registerSecurityDashboardGate();

        // Register dashboard routes and Livewire components
        if (config('artisanpack.security.eventLogging.dashboard.enabled')) {
            $this->registerSecurityDashboard();
        }
    }

    /**
     * Register the default gate for security dashboard access.
     *
     * Users should override this gate in their AuthServiceProvider to
     * implement their own authorization logic (e.g., checking for admin role).
     *
     * @return void
     */
    protected function registerSecurityDashboardGate(): void
    {
        // Only define if not already defined by the application
        if (! Gate::has('viewSecurityDashboard')) {
            Gate::define('viewSecurityDashboard', function ($user) {
                // Default: deny access. Applications should define their own gate.
                // Example in AuthServiceProvider:
                //   Gate::define('viewSecurityDashboard', fn ($user) => $user->hasRole('admin'));
                return false;
            });
        }
    }

    /**
     * Register the security dashboard routes and Livewire components.
     *
     * @return void
     */
    protected function registerSecurityDashboard(): void
    {
        // Check if Livewire is available
        if (! class_exists(Livewire::class)) {
            Log::warning(
                'ArtisanPack Security: Dashboard is enabled but Livewire is not installed. ' .
                'Install Livewire with: composer require livewire/livewire'
            );

            return;
        }

        // Register Livewire components
        Livewire::component('security-dashboard', SecurityDashboard::class);
        Livewire::component('security-event-list', SecurityEventList::class);
        Livewire::component('security-stats', SecurityStats::class);

        // Load dashboard routes
        $this->loadRoutesFrom(__DIR__ . '/../routes/security-dashboard.php');
    }

    /**
     * Boot the password security services.
     *
     * @return void
     */
    protected function bootPasswordSecurity(): void
    {
        if (! config('artisanpack.security.passwordSecurity.enabled', true)) {
            return;
        }

        // Load password security migrations
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations/password');

        // Register middleware aliases
        $this->app['router']->aliasMiddleware('password.policy', EnforcePasswordPolicy::class);
        $this->app['router']->aliasMiddleware('password.change', RequirePasswordChange::class);

        // Register Livewire component if Livewire is available
        if (class_exists(Livewire::class)) {
            Livewire::component('password-strength-meter', PasswordStrengthMeter::class);
        }
    }

    /**
     * Boot the file upload security services.
     *
     * @return void
     */
    protected function bootFileUploadSecurity(): void
    {
        if (! config('artisanpack.security.fileUpload.enabled', true)) {
            return;
        }

        // Load file upload migrations
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations/uploads');

        // Register middleware aliases
        $this->app['router']->aliasMiddleware('validate.upload', ValidateFileUpload::class);
        $this->app['router']->aliasMiddleware('scan.upload', ScanUploadedFiles::class);

        // Register console commands
        if ($this->app->runningInConsole()) {
            $this->commands([
                ScanQuarantinedFiles::class,
                CleanupExpiredFiles::class,
            ]);
        }

        // Load secure file serving routes
        $this->loadRoutesFrom(__DIR__ . '/../routes/secure-files.php');
    }

    /**
     * Boot the Content Security Policy services.
     *
     * @return void
     */
    protected function bootCsp(): void
    {
        if (! config('artisanpack.security.csp.enabled', true)) {
            return;
        }

        // Load CSP migrations
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');

        // Register middleware alias
        $this->app['router']->aliasMiddleware('csp', ContentSecurityPolicy::class);

        // Register Blade component
        Blade::component('csp-nonce', CspNonce::class);

        // Register console commands
        if ($this->app->runningInConsole()) {
            $this->commands([
                CspStats::class,
                CspTest::class,
                CspPrune::class,
            ]);
        }

        // Register Livewire component if Livewire is available
        if (class_exists(Livewire::class)) {
            Livewire::component('csp-dashboard', CspDashboard::class);
        }

        // Load CSP routes for violation reporting
        if (config('artisanpack.security.csp.reporting.enabled', true)) {
            $this->loadRoutesFrom(__DIR__ . '/../routes/csp.php');
        }
    }

    /**
     * Boot the security testing services.
     *
     * @return void
     */
    protected function bootSecurityTesting(): void
    {
        if (! config('artisanpack.security.testing.enabled', true)) {
            return;
        }

        // Register console commands
        if ($this->app->runningInConsole()) {
            $this->commands([
                SecurityScan::class,
                SecurityAudit::class,
                SecurityBenchmarkCommand::class,
                SecurityBaseline::class,
            ]);
        }
    }

    /**
     * Boot the advanced authentication services.
     *
     * @return void
     */
    protected function bootAdvancedAuthentication(): void
    {
        // Load authentication migrations
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations/authentication');

        // Register middleware aliases
        $this->registerAuthenticationMiddleware();

        // Register event listeners
        $this->registerAuthenticationEventListeners();

        // Register Livewire components
        $this->registerAuthenticationLivewireComponents();

        // Register console commands
        if ($this->app->runningInConsole()) {
            $this->commands([
                CleanupExpiredSessions::class,
                CleanupInactiveDevices::class,
                ListWebAuthnCredentials::class,
                ManageAccountLockout::class,
                ManageSsoConfiguration::class,
                PruneSuspiciousActivity::class,
                SecurityAuthAudit::class,
                TerminateUserSessions::class,
            ]);
        }

        // Load authentication routes
        if (config('artisanpack.security.auth_routes.enabled', true)) {
            $this->loadRoutesFrom(__DIR__ . '/../routes/authentication.php');
        }
    }

    /**
     * Register authentication middleware aliases.
     *
     * @return void
     */
    protected function registerAuthenticationMiddleware(): void
    {
        $router = $this->app['router'];

        // Account lockout middleware
        if (config('artisanpack.security.account_lockout.enabled', true)) {
            $router->aliasMiddleware('check.lockout', CheckAccountLockout::class);
        }

        // Device fingerprinting middleware
        if (config('artisanpack.security.device_fingerprinting.enabled', true)) {
            $router->aliasMiddleware('device.fingerprint', ValidateDeviceFingerprint::class);
            $router->aliasMiddleware('device.trusted', RequireTrustedDevice::class);
        }

        // Advanced session middleware
        if (config('artisanpack.security.advanced_sessions.enabled', true)) {
            $router->aliasMiddleware('session.binding', EnforceSessionBinding::class);
        }

        // Suspicious activity detection middleware
        if (config('artisanpack.security.suspicious_activity.enabled', true)) {
            $router->aliasMiddleware('detect.suspicious', DetectSuspiciousActivityMiddleware::class);
        }

        // Step-up authentication middleware
        if (config('artisanpack.security.step_up_authentication.enabled', true)) {
            $router->aliasMiddleware('step.up', StepUpAuthentication::class);
        }
    }

    /**
     * Register authentication event listeners.
     *
     * @return void
     */
    protected function registerAuthenticationEventListeners(): void
    {
        // Subscribe to advanced auth event logging
        Event::subscribe(LogAdvancedAuthEvents::class);

        // Register individual event listeners
        if (config('artisanpack.security.notifications.enabled', true)) {
            // New device notifications
            if (config('artisanpack.security.notifications.new_device_login', true)) {
                Event::listen(NewDeviceDetected::class, SendNewDeviceNotification::class);
            }

            // Account locked notifications
            if (config('artisanpack.security.notifications.account_locked', true)) {
                Event::listen(AccountLocked::class, SendAccountLockedNotification::class);
            }

            // WebAuthn credential notifications
            if (config('artisanpack.security.notifications.webauthn_credential', true)) {
                Event::subscribe(SendWebAuthnCredentialNotification::class);
            }

            // Social account notifications
            if (config('artisanpack.security.notifications.social_account', true)) {
                Event::subscribe(SendSocialAccountNotification::class);
            }

            // Suspicious activity handler
            if (config('artisanpack.security.notifications.suspicious_activity', true)) {
                Event::listen(SuspiciousActivityDetected::class, HandleSuspiciousActivity::class);
            }
        }
    }

    /**
     * Register authentication Livewire components.
     *
     * @return void
     */
    protected function registerAuthenticationLivewireComponents(): void
    {
        if (! class_exists(Livewire::class)) {
            return;
        }

        // Social accounts management
        if (config('artisanpack.security.social_auth.enabled', true)) {
            Livewire::component('social-accounts-manager', SocialAccountsManager::class);
        }

        // WebAuthn credentials management
        if (config('artisanpack.security.webauthn.enabled', true)) {
            Livewire::component('webauthn-credentials-manager', WebAuthnCredentialsManager::class);
        }

        // Biometric management
        if (config('artisanpack.security.biometric.enabled', true)) {
            Livewire::component('biometric-manager', BiometricManagerComponent::class);
        }

        // Device management
        if (config('artisanpack.security.device_fingerprinting.enabled', true)) {
            Livewire::component('device-manager', DeviceManager::class);
        }

        // Session management
        if (config('artisanpack.security.advanced_sessions.enabled', true)) {
            Livewire::component('session-manager', SessionManager::class);
        }

        // Suspicious activity list
        if (config('artisanpack.security.suspicious_activity.enabled', true)) {
            Livewire::component('suspicious-activity-list', SuspiciousActivityList::class);
        }

        // Account lockout status
        if (config('artisanpack.security.account_lockout.enabled', true)) {
            Livewire::component('account-lockout-status', AccountLockoutStatus::class);
        }

        // Step-up authentication modal
        if (config('artisanpack.security.step_up_authentication.enabled', true)) {
            Livewire::component('step-up-authentication-modal', StepUpAuthenticationModal::class);
        }
    }

    /**
     * Boot the analytics services.
     *
     * @return void
     */
    protected function bootAnalytics(): void
    {
        if (! config('artisanpack.security.analytics.enabled', false)) {
            return;
        }

        // Load analytics migrations
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations/analytics');

        // Register analytics services
        $this->registerAnalyticsServices();

        // Register console commands
        if ($this->app->runningInConsole()) {
            $this->commands([
                AnalyticsProcessCommand::class,
                GenerateSecurityReportCommand::class,
                PruneAnalyticsDataCommand::class,
                SyncThreatFeedsCommand::class,
                TestSiemConnectionCommand::class,
                UpdateBehaviorBaselinesCommand::class,
            ]);
        }

        // Load analytics routes if dashboard is enabled
        if (config('artisanpack.security.analytics.dashboard.enabled', false)) {
            $this->loadRoutesFrom(__DIR__ . '/../routes/analytics-dashboard.php');
        }
    }

    /**
     * Register analytics services.
     *
     * @return void
     */
    protected function registerAnalyticsServices(): void
    {
        // Metrics Collector
        $this->app->singleton(\ArtisanPackUI\Security\Analytics\Metrics\MetricsCollector::class, function ($app) {
            return new \ArtisanPackUI\Security\Analytics\Metrics\MetricsCollector(
                config('artisanpack.security.analytics.metrics', [])
            );
        });

        // Anomaly Detection Service
        $this->app->singleton(\ArtisanPackUI\Security\Analytics\AnomalyDetection\AnomalyDetectionService::class, function ($app) {
            $service = new \ArtisanPackUI\Security\Analytics\AnomalyDetection\AnomalyDetectionService(
                config('artisanpack.security.analytics.anomaly_detection', [])
            );

            // Register additional detectors
            $this->registerAnomalyDetectors($service);

            return $service;
        });

        // Threat Intelligence Service
        $this->app->singleton(\ArtisanPackUI\Security\Analytics\ThreatIntelligence\ThreatIntelligenceService::class, function ($app) {
            $service = new \ArtisanPackUI\Security\Analytics\ThreatIntelligence\ThreatIntelligenceService(
                config('artisanpack.security.analytics.threat_intelligence', [])
            );

            // Register additional providers
            $this->registerThreatIntelProviders($service);

            return $service;
        });

        // Incident Responder
        $this->app->singleton(\ArtisanPackUI\Security\Analytics\IncidentResponse\IncidentResponder::class, function ($app) {
            $service = new \ArtisanPackUI\Security\Analytics\IncidentResponse\IncidentResponder(
                config('artisanpack.security.analytics.incident_response', [])
            );

            // Register additional response actions
            $this->registerResponseActions($service);

            return $service;
        });

        // Alert Manager
        $this->app->singleton(\ArtisanPackUI\Security\Analytics\Alerting\AlertManager::class, function ($app) {
            $service = new \ArtisanPackUI\Security\Analytics\Alerting\AlertManager(
                config('artisanpack.security.analytics.alerting', [])
            );

            // Register additional alert channels
            $this->registerAlertChannels($service);

            return $service;
        });

        // Dashboard Data Provider
        $this->app->singleton(\ArtisanPackUI\Security\Analytics\Dashboard\DashboardDataProvider::class, function ($app) {
            return new \ArtisanPackUI\Security\Analytics\Dashboard\DashboardDataProvider();
        });

        // Report Generator
        $this->app->singleton(\ArtisanPackUI\Security\Analytics\Reports\ReportGenerator::class, function ($app) {
            return new \ArtisanPackUI\Security\Analytics\Reports\ReportGenerator(
                config('artisanpack.security.analytics.reports', [])
            );
        });

        // SIEM Export Service
        $this->app->singleton(\ArtisanPackUI\Security\Analytics\Siem\SiemExportService::class, function ($app) {
            $service = new \ArtisanPackUI\Security\Analytics\Siem\SiemExportService(
                config('artisanpack.security.analytics.siem', [])
            );

            // Register additional exporters
            $this->registerSiemExporters($service);

            return $service;
        });
    }

    /**
     * Register anomaly detectors.
     *
     * @param  \ArtisanPackUI\Security\Analytics\AnomalyDetection\AnomalyDetectionService  $service
     * @return void
     */
    protected function registerAnomalyDetectors($service): void
    {
        $detectorConfigs = config('artisanpack.security.analytics.anomaly_detection.detectors', []);

        if (! empty($detectorConfigs['geo_velocity'])) {
            $service->registerDetector(new \ArtisanPackUI\Security\Analytics\AnomalyDetection\Detectors\GeoVelocityDetector(
                $detectorConfigs['geo_velocity']
            ));
        }

        if (! empty($detectorConfigs['brute_force'])) {
            $service->registerDetector(new \ArtisanPackUI\Security\Analytics\AnomalyDetection\Detectors\BruteForceDetector(
                $detectorConfigs['brute_force']
            ));
        }

        if (! empty($detectorConfigs['credential_stuffing'])) {
            $service->registerDetector(new \ArtisanPackUI\Security\Analytics\AnomalyDetection\Detectors\CredentialStuffingDetector(
                $detectorConfigs['credential_stuffing']
            ));
        }

        if (! empty($detectorConfigs['privilege_escalation'])) {
            $service->registerDetector(new \ArtisanPackUI\Security\Analytics\AnomalyDetection\Detectors\PrivilegeEscalationDetector(
                $detectorConfigs['privilege_escalation']
            ));
        }

        if (! empty($detectorConfigs['access_pattern'])) {
            $service->registerDetector(new \ArtisanPackUI\Security\Analytics\AnomalyDetection\Detectors\AccessPatternDetector(
                $detectorConfigs['access_pattern']
            ));
        }
    }

    /**
     * Register threat intelligence providers.
     *
     * @param  \ArtisanPackUI\Security\Analytics\ThreatIntelligence\ThreatIntelligenceService  $service
     * @return void
     */
    protected function registerThreatIntelProviders($service): void
    {
        $providerConfigs = config('artisanpack.security.analytics.threat_intelligence.providers', []);

        if (! empty($providerConfigs['ipqualityscore'])) {
            $service->registerProvider(new \ArtisanPackUI\Security\Analytics\ThreatIntelligence\Providers\IpQualityScoreProvider(
                $providerConfigs['ipqualityscore']
            ));
        }

        if (! empty($providerConfigs['google_safe_browsing'])) {
            $service->registerProvider(new \ArtisanPackUI\Security\Analytics\ThreatIntelligence\Providers\GoogleSafeBrowsingProvider(
                $providerConfigs['google_safe_browsing']
            ));
        }

        if (! empty($providerConfigs['custom_feeds'])) {
            foreach ($providerConfigs['custom_feeds'] as $feedConfig) {
                $service->registerProvider(new \ArtisanPackUI\Security\Analytics\ThreatIntelligence\Providers\CustomFeedProvider(
                    $feedConfig
                ));
            }
        }
    }

    /**
     * Register incident response actions.
     *
     * @param  \ArtisanPackUI\Security\Analytics\IncidentResponse\IncidentResponder  $service
     * @return void
     */
    protected function registerResponseActions($service): void
    {
        // Register default response actions
        $service->registerAction(new \ArtisanPackUI\Security\Analytics\IncidentResponse\Actions\LockAccountAction());
        $service->registerAction(new \ArtisanPackUI\Security\Analytics\IncidentResponse\Actions\ForcePasswordResetAction());
        $service->registerAction(new \ArtisanPackUI\Security\Analytics\IncidentResponse\Actions\RateLimitIpAction());
        $service->registerAction(new \ArtisanPackUI\Security\Analytics\IncidentResponse\Actions\TerminateSessionAction());
        $service->registerAction(new \ArtisanPackUI\Security\Analytics\IncidentResponse\Actions\EnableEnhancedLoggingAction());
    }

    /**
     * Register alert channels.
     *
     * @param  \ArtisanPackUI\Security\Analytics\Alerting\AlertManager  $service
     * @return void
     */
    protected function registerAlertChannels($service): void
    {
        $channelConfigs = config('artisanpack.security.analytics.alerting.channels', []);

        if (! empty($channelConfigs['teams'])) {
            $service->registerChannel(new \ArtisanPackUI\Security\Analytics\Alerting\Channels\TeamsChannel(
                $channelConfigs['teams']
            ));
        }

        if (! empty($channelConfigs['opsgenie'])) {
            $service->registerChannel(new \ArtisanPackUI\Security\Analytics\Alerting\Channels\OpsGenieChannel(
                $channelConfigs['opsgenie']
            ));
        }

        if (! empty($channelConfigs['webhook'])) {
            $service->registerChannel(new \ArtisanPackUI\Security\Analytics\Alerting\Channels\WebhookChannel(
                $channelConfigs['webhook']
            ));
        }

        if (! empty($channelConfigs['sms'])) {
            $service->registerChannel(new \ArtisanPackUI\Security\Analytics\Alerting\Channels\SmsChannel(
                $channelConfigs['sms']
            ));
        }

        if (! empty($channelConfigs['database'])) {
            $service->registerChannel(new \ArtisanPackUI\Security\Analytics\Alerting\Channels\DatabaseChannel(
                $channelConfigs['database']
            ));
        }
    }

    /**
     * Register SIEM exporters.
     *
     * @param  \ArtisanPackUI\Security\Analytics\Siem\SiemExportService  $service
     * @return void
     */
    protected function registerSiemExporters($service): void
    {
        $exporterConfigs = config('artisanpack.security.analytics.siem.providers', []);

        if (! empty($exporterConfigs['datadog'])) {
            $service->registerExporter(new \ArtisanPackUI\Security\Analytics\Siem\Exporters\DatadogExporter(
                $exporterConfigs['datadog']
            ));
        }

        if (! empty($exporterConfigs['webhook'])) {
            $service->registerExporter(new \ArtisanPackUI\Security\Analytics\Siem\Exporters\WebhookExporter(
                $exporterConfigs['webhook']
            ));
        }
    }
}

