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

    #[Test]
    public function it_shows_no_errors_or_warnings_for_a_valid_configuration()
    {
        Config::set('app.debug', false);
        Config::set('artisanpack.security.encrypt', true);
        Config::set('artisanpack.security.enabled', true);
        Config::set('artisanpack.security.security-headers.Content-Security-Policy', "default-src 'self'");

        $this->artisan('security:check-config')
            ->expectsOutput('Checking security configuration for the \'testing\' environment...')
            ->expectsOutput('All security checks passed!')
            ->assertExitCode(0);
    }

    #[Test]
    public function it_shows_an_error_when_debug_is_enabled_in_production()
    {
        $this->app->detectEnvironment(fn() => 'production');

        Config::set('app.debug', true);
        Config::set('artisanpack.security.encrypt', true);
        Config::set('artisanpack.security.enabled', true);
        Config::set('artisanpack.security.security-headers.Content-Security-Policy', "default-src 'self'");

        $this->artisan('security:check-config')
            ->expectsOutput('Checking security configuration for the \'production\' environment...')
            ->expectsOutput('Errors found:')
            ->expectsOutput('- app.debug is enabled in a production environment.')
            ->expectsOutput('Security configuration check failed.')
            ->assertExitCode(1);
    }

    #[Test]
    public function it_shows_a_warning_when_two_factor_is_disabled_in_production()
    {
        $this->app->detectEnvironment(fn() => 'production');

        Config::set('app.debug', false);
        Config::set('artisanpack.security.encrypt', true);
        Config::set('artisanpack.security.enabled', false);
        Config::set('artisanpack.security.security-headers.Content-Security-Policy', "default-src 'self'");

        $this->artisan('security:check-config')
            ->expectsOutput('Checking security configuration for the \'production\' environment...')
            ->expectsOutput('Warnings found:')
            ->expectsOutput('- artisanpack.security.enabled is disabled. It is highly recommended to enable two-factor authentication in production.')
            ->expectsOutput('Security configuration check passed with warnings.')
            ->assertExitCode(0);
    }
}

