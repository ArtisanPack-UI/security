<?php

namespace Tests\Unit;

use ArtisanPackUI\Security\Services\EnvironmentValidationService;
use Illuminate\Support\Facades\Config;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\Test;

class EnvironmentValidationServiceTest extends TestCase
{
    /**
     * @var EnvironmentValidationService
     */
    protected $validator;

    protected function setUp(): void
    {
        parent::setUp();
        $this->validator = new EnvironmentValidationService();
    }

    #[Test]
    public function it_returns_no_errors_or_warnings_for_a_valid_production_configuration()
    {
        Config::set('app.debug', false);
        Config::set('artisanpack.security.encrypt', true);
        Config::set('artisanpack.security.enabled', true);
        Config::set('artisanpack.security.security-headers.Content-Security-Policy', "default-src 'self'");

        $results = $this->validator->validate('production');

        $this->assertEmpty($results['errors']);
        $this->assertEmpty($results['warnings']);
    }

    #[Test]
    public function it_returns_an_error_if_debug_mode_is_enabled_in_production()
    {
        Config::set('app.debug', true);

        $results = $this->validator->validate('production');

        $this->assertContains('app.debug is enabled in a production environment.', $results['errors']);
    }

    #[Test]
    public function it_returns_an_error_if_session_encryption_is_disabled_in_production()
    {
        Config::set('artisanpack.security.encrypt', false);

        $results = $this->validator->validate('production');

        $this->assertContains('artisanpack.security.encrypt is disabled in a production environment.', $results['errors']);
    }

    #[Test]
    public function it_returns_a_warning_if_two_factor_authentication_is_disabled_in_production()
    {
        Config::set('artisanpack.security.enabled', false);

        $results = $this->validator->validate('production');

        $this->assertContains('artisanpack.security.enabled is disabled. It is highly recommended to enable two-factor authentication in production.', $results['warnings']);
    }

    #[Test]
    public function it_returns_a_warning_if_csp_contains_unsafe_inline()
    {
        Config::set('artisanpack.security.security-headers.Content-Security-Policy', "script-src 'unsafe-inline'");

        $results = $this->validator->validate('production');

        $this->assertContains("The Content Security Policy contains 'unsafe-inline'. This is a security risk.", $results['warnings']);
    }

    #[Test]
    public function it_returns_a_warning_if_csp_contains_unsafe_eval()
    {
        Config::set('artisanpack.security.security-headers.Content-Security-Policy', "script-src 'unsafe-eval'");

        $results = $this->validator->validate('production');

        $this->assertContains("The Content Security Policy contains 'unsafe-eval'. This is a security risk.", $results['warnings']);
    }
}
