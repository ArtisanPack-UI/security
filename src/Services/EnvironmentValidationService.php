<?php

namespace ArtisanPackUI\Security\Services;

use Illuminate\Support\Facades\Config;

class EnvironmentValidationService
{
    /**
     * @var array
     */
    protected $errors = [];

    /**
     * @var array
     */
    protected $warnings = [];

    /**
     * Validates the security configuration for the given environment.
     *
     * @param string $environment
     * @return array
     */
    public function validate(string $environment): array
    {
        $this->errors = [];
        $this->warnings = [];

        if ($environment === 'production') {
            $this->validateProductionEnvironment();
        }

        return [
            'errors' => $this->errors,
            'warnings' => $this->warnings,
        ];
    }

    /**
     * Runs all validation checks for a production environment.
     */
    protected function validateProductionEnvironment(): void
    {
        $this->checkDebugMode();
        $this->checkSessionEncryption();
        $this->checkTwoFactorAuthentication();
        $this->checkContentSecurityPolicy();
    }

    /**
     * Checks if debug mode is disabled in production.
     */
    protected function checkDebugMode(): void
    {
        if (Config::get('app.debug')) {
            $this->errors[] = 'app.debug is enabled in a production environment.';
        }
    }

    /**
     * Checks if session encryption is enabled in production.
     */
    protected function checkSessionEncryption(): void
    {
        if (!Config::get('artisanpack.security.encrypt')) {
            $this->errors[] = 'artisanpack.security.encrypt is disabled in a production environment.';
        }
    }

    /**
     * Checks if two-factor authentication is enabled in production.
     */
    protected function checkTwoFactorAuthentication(): void
    {
        if (!Config::get('artisanpack.security.enabled')) {
            $this->warnings[] = 'artisanpack.security.enabled is disabled. It is highly recommended to enable two-factor authentication in production.';
        }
    }

    /**
     * Checks the Content Security Policy for potential vulnerabilities.
     */
    protected function checkContentSecurityPolicy(): void
    {
        $csp = Config::get('artisanpack.security.security-headers.Content-Security-Policy');

        if (str_contains($csp, "'unsafe-inline'")) {
            $this->warnings[] = "The Content Security Policy contains 'unsafe-inline'. This is a security risk.";
        }

        if (str_contains($csp, "'unsafe-eval'")) {
            $this->warnings[] = "The Content Security Policy contains 'unsafe-eval'. This is a security risk.";
        }
    }
}
