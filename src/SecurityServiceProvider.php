<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security;

use ArtisanPackUI\Security\Console\Commands\CheckSecurityConfiguration;
use ArtisanPackUI\Security\Console\Commands\ClearRateLimits;
use ArtisanPackUI\Security\Console\Commands\CspPrune;
use ArtisanPackUI\Security\Console\Commands\CspStats;
use ArtisanPackUI\Security\Console\Commands\CspTest;
use ArtisanPackUI\Security\Console\Commands\GenerateCspPolicy;
use ArtisanPackUI\Security\Console\Commands\ScanDependencies;
use ArtisanPackUI\Security\Console\Commands\SecurityAudit;
use ArtisanPackUI\Security\Console\Commands\SecurityBaseline;
use ArtisanPackUI\Security\Console\Commands\SecurityBenchmarkCommand;
use ArtisanPackUI\Security\Console\Commands\SecurityScan;
use ArtisanPackUI\Security\Console\Commands\TestSecurityHeaders;
use ArtisanPackUI\Security\Contracts\CspPolicyInterface;
use ArtisanPackUI\Security\Http\Middleware\ApiRateLimiting;
use ArtisanPackUI\Security\Http\Middleware\ApiSecurity;
use ArtisanPackUI\Security\Http\Middleware\ContentSecurityPolicy;
use ArtisanPackUI\Security\Http\Middleware\SecurityHeadersMiddleware;
use ArtisanPackUI\Security\Http\Middleware\XssProtection;
use ArtisanPackUI\Security\Services\Csp\CspNonceGenerator;
use ArtisanPackUI\Security\Services\Csp\CspPolicyService;
use ArtisanPackUI\Security\Services\Csp\CspViolationHandler;
use ArtisanPackUI\Security\View\Components\CspNonce;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Livewire\Livewire;

/**
 * Service provider for the artisanpack-ui/security core package.
 *
 * Wires the Security 2.0 core surface — sanitization / output escaping,
 * KSES filtering, security headers, XSS protection, basic rate
 * limiting, and Content Security Policy (nonces, headers, violation
 * reporting). Authentication / 2FA / RBAC / file uploads / analytics /
 * compliance live in the sibling packages now (`security-auth`,
 * `security-advanced-auth`, `rbac`, `secure-uploads`,
 * `security-analytics`, `compliance`).
 */
class SecurityServiceProvider extends ServiceProvider
{
    /**
     * Register container bindings.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/security.php',
            'artisanpack.security',
        );

        $this->app->singleton('security', fn () => new Security);

        $this->registerCspServices();
    }

    /**
     * Bootstrap package services.
     */
    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../config/security.php' => config_path('artisanpack/security.php'),
        ], 'security-config');

        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');

        $this->loadViewsFrom(__DIR__.'/../resources/views', 'artisanpack-ui-security');

        $this->registerMiddleware();
        $this->registerBladeDirectives();
        $this->registerLivewireComponents();
        $this->bootRateLimiting();

        if (config('artisanpack.security.csp.routes.enabled', true)) {
            $this->loadRoutesFrom(__DIR__.'/../routes/csp.php');
        }

        if ($this->app->runningInConsole()) {
            $this->commands([
                CheckSecurityConfiguration::class,
                ClearRateLimits::class,
                CspPrune::class,
                CspStats::class,
                CspTest::class,
                GenerateCspPolicy::class,
                ScanDependencies::class,
                SecurityAudit::class,
                SecurityBaseline::class,
                SecurityBenchmarkCommand::class,
                SecurityScan::class,
                TestSecurityHeaders::class,
            ]);
        }
    }

    /**
     * Bind the CSP services + the policy contract.
     */
    protected function registerCspServices(): void
    {
        $this->app->scoped(CspNonceGenerator::class, function ($app): CspNonceGenerator {
            return new CspNonceGenerator(
                (int) config('artisanpack.security.csp.nonce.length', 16),
            );
        });

        $this->app->singleton(CspPolicyService::class, function ($app): CspPolicyService {
            return new CspPolicyService(
                $app->make(CspNonceGenerator::class),
            );
        });

        $this->app->bind(CspPolicyInterface::class, CspPolicyService::class);

        $this->app->singleton(CspViolationHandler::class, fn () => new CspViolationHandler);
    }

    /**
     * Register middleware aliases (gated by config so apps can opt out).
     */
    protected function registerMiddleware(): void
    {
        $router = $this->app['router'];

        if (config('artisanpack.security.csp.enabled', true)) {
            $router->aliasMiddleware('csp', ContentSecurityPolicy::class);
        }

        if (config('artisanpack.security.headers.enabled', true)) {
            $router->aliasMiddleware('security.headers', SecurityHeadersMiddleware::class);
        }

        if (config('artisanpack.security.xss.enabled', true)) {
            $router->aliasMiddleware('xss.protection', XssProtection::class);
        }

        if (config('artisanpack.security.api.enabled', true)) {
            $router->aliasMiddleware('api.security', ApiSecurity::class);
        }

        if (config('artisanpack.security.rateLimiting.enabled', true)) {
            $router->aliasMiddleware('api.rate_limit', ApiRateLimiting::class);
        }
    }

    /**
     * Register named rate limiters defined in config.
     */
    protected function bootRateLimiting(): void
    {
        if (! config('artisanpack.security.rateLimiting.enabled', true)) {
            return;
        }

        foreach ((array) config('artisanpack.security.rateLimiting.limiters', []) as $name => $config) {
            $maxAttempts  = (int) ($config['maxAttempts'] ?? 60);
            $decayMinutes = (int) ($config['decayMinutes'] ?? 1);

            RateLimiter::for($name, function (Request $request) use ($maxAttempts, $decayMinutes) {
                $key = optional($request->user())->id ?: $request->ip();

                return Limit::perMinutes($decayMinutes, $maxAttempts)->by($key);
            });
        }
    }

    /**
     * @csp_nonce Blade directive for CSP nonce injection.
     */
    protected function registerBladeDirectives(): void
    {
        Blade::directive('csp_nonce', function (): string {
            return "<?php echo 'nonce=\"' . app(\\ArtisanPackUI\\Security\\Services\\Csp\\CspNonceGenerator::class)->getNonce() . '\"'; ?>";
        });

        Blade::component('csp-nonce', CspNonce::class);
    }

    /**
     * Register the CSP dashboard Livewire component (skipped if Livewire isn't installed).
     */
    protected function registerLivewireComponents(): void
    {
        if (! class_exists(Livewire::class) || ! $this->app->bound('livewire')) {
            return;
        }

        Livewire::component('csp-dashboard', \ArtisanPackUI\Security\Livewire\CspDashboard::class);
    }
}
