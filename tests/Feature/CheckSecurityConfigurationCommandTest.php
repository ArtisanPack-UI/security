<?php

namespace Tests\Feature;

use ArtisanPackUI\Security\SecurityServiceProvider;
use Illuminate\Support\Facades\Config;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\Test;

class CheckSecurityConfigurationCommandTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [
            SecurityServiceProvider::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        // Set up base security configuration
        $app['config']->set('artisanpack.security.security-headers', [
            'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
            'X-Frame-Options' => 'SAMEORIGIN',
            'X-Content-Type-Options' => 'nosniff',
            'Content-Security-Policy' => "default-src 'self'",
        ]);
        $app['config']->set('artisanpack.security.xss.enabled', true);
        $app['config']->set('artisanpack.security.rateLimiting.enabled', true);
        $app['config']->set('artisanpack.security.rbac.enabled', true);
        $app['config']->set('artisanpack.security.api.enabled', true);
        $app['config']->set('artisanpack.security.api.tokens.expiration', 10080);
        $app['config']->set('artisanpack.security.passwordSecurity.enabled', true);
        $app['config']->set('artisanpack.security.passwordSecurity.hibpCheck.enabled', true);
        $app['config']->set('artisanpack.security.passwordSecurity.history.enabled', true);
        $app['config']->set('artisanpack.security.fileUpload.enabled', true);
        $app['config']->set('artisanpack.security.fileUpload.malware.driver', 'clamav');
        $app['config']->set('artisanpack.security.fileUpload.quarantine.enabled', true);
        $app['config']->set('artisanpack.security.fileUpload.validation.blockedExtensions', ['php', 'phtml', 'php3', 'php4', 'php5', 'exe', 'sh', 'bat']);
        $app['config']->set('artisanpack.security.csp.reporting.enabled', true);
        $app['config']->set('session.driver', 'database');
        $app['config']->set('session.secure', true);
        $app['config']->set('session.http_only', true);
        $app['config']->set('session.same_site', 'lax');
    }

    #[Test]
    public function it_shows_no_errors_or_warnings_for_a_valid_configuration()
    {
        Config::set('app.debug', false);
        Config::set('artisanpack.security.encrypt', true);
        Config::set('artisanpack.security.enabled', true);

        $this->artisan('security:check-config')
            ->expectsOutputToContain("Checking security configuration for 'testing' environment...")
            ->expectsOutputToContain('Security configuration check PASSED')
            ->assertExitCode(0);
    }

    #[Test]
    public function it_shows_an_error_when_debug_is_enabled_in_production()
    {
        $this->app->detectEnvironment(fn() => 'production');

        Config::set('app.debug', true);
        Config::set('artisanpack.security.encrypt', true);
        Config::set('artisanpack.security.enabled', true);

        $this->artisan('security:check-config')
            ->expectsOutputToContain("Checking security configuration for 'production' environment...")
            ->expectsOutputToContain('app.debug is enabled')
            ->assertExitCode(1);
    }

    #[Test]
    public function it_shows_a_warning_when_two_factor_is_disabled_in_production()
    {
        $this->app->detectEnvironment(fn() => 'production');

        Config::set('app.debug', false);
        Config::set('artisanpack.security.encrypt', true);
        Config::set('artisanpack.security.enabled', false);

        $this->artisan('security:check-config')
            ->expectsOutputToContain("Checking security configuration for 'production' environment...")
            ->assertSuccessful();
    }

    #[Test]
    public function it_supports_json_output()
    {
        Config::set('app.debug', false);
        Config::set('artisanpack.security.encrypt', true);
        Config::set('artisanpack.security.enabled', true);

        $this->artisan('security:check-config', ['--json' => true])
            ->expectsOutputToContain('"status":')
            ->assertExitCode(0);
    }

    #[Test]
    public function it_supports_category_filtering()
    {
        Config::set('app.debug', false);
        Config::set('artisanpack.security.encrypt', true);

        $this->artisan('security:check-config', ['--category' => 'session'])
            ->expectsOutputToContain("Checking security configuration for 'testing' environment...")
            ->assertExitCode(0);
    }

    #[Test]
    public function it_supports_strict_mode()
    {
        $this->app->detectEnvironment(fn() => 'production');

        Config::set('app.debug', false);
        Config::set('artisanpack.security.encrypt', true);
        Config::set('artisanpack.security.enabled', false);

        // In strict mode, warnings are treated as errors
        $this->artisan('security:check-config', ['--strict' => true])
            ->assertExitCode(1);
    }
}
