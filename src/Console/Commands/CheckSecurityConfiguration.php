<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Console\Commands;

use ArtisanPackUI\Security\Services\EnvironmentValidationService;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\App;

class CheckSecurityConfiguration extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:check-config
                            {--category= : Specific category to check (env, session, database, cache, mail, filesystem, security, api, rbac, csp, password, upload)}
                            {--json : Output results as JSON}
                            {--strict : Treat warnings as errors}
                            {--ignore= : Comma-separated list of check IDs to ignore}
                            {--show-passed : Show passed checks as well}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Check the security configuration of the application';

    /**
     * Environment validation service.
     */
    protected EnvironmentValidationService $validator;

    /**
     * Available check categories.
     *
     * @var array<string, string>
     */
    protected array $categories = [
        'env' => 'Environment Configuration',
        'session' => 'Session Security',
        'database' => 'Database Security',
        'cache' => 'Cache Configuration',
        'mail' => 'Mail Security',
        'filesystem' => 'Filesystem Security',
        'security' => 'General Security',
        'api' => 'API Security',
        'rbac' => 'RBAC Configuration',
        'csp' => 'Content Security Policy',
        'password' => 'Password Policy',
        'upload' => 'File Upload Security',
    ];

    public function __construct(EnvironmentValidationService $validator)
    {
        parent::__construct();
        $this->validator = $validator;
    }

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $environment = App::environment();
        $category = $this->option('category');
        $isJson = $this->option('json');
        $isStrict = $this->option('strict');
        $showPassed = $this->option('show-passed');

        // Get ignored checks
        $ignoredChecks = [];
        if ($ignore = $this->option('ignore')) {
            $ignoredChecks = array_map('trim', explode(',', $ignore));
        }

        if (! $isJson) {
            $this->info("Checking security configuration for '{$environment}' environment...");
            $this->newLine();
        }

        // Run base validation
        $results = $this->validator->validate($environment);

        // Run additional category checks
        $additionalResults = $this->runAdditionalChecks($category);

        // Merge results
        $errors = array_merge($results['errors'] ?? [], $additionalResults['errors'] ?? []);
        $warnings = array_merge($results['warnings'] ?? [], $additionalResults['warnings'] ?? []);
        $passed = $additionalResults['passed'] ?? [];

        // Apply ignored checks
        $errors = $this->filterIgnored($errors, $ignoredChecks);
        $warnings = $this->filterIgnored($warnings, $ignoredChecks);

        // Output results
        if ($isJson) {
            return $this->outputJson($errors, $warnings, $passed, $isStrict);
        }

        return $this->outputTable($errors, $warnings, $passed, $isStrict, $showPassed);
    }

    /**
     * Run additional security checks based on category.
     *
     * @return array<string, array<string>>
     */
    protected function runAdditionalChecks(?string $category): array
    {
        $errors = [];
        $warnings = [];
        $passed = [];

        $categoriesToCheck = $category ? [$category] : array_keys($this->categories);

        foreach ($categoriesToCheck as $cat) {
            $method = 'check'.ucfirst($cat);
            if (method_exists($this, $method)) {
                $result = $this->$method();
                $errors = array_merge($errors, $result['errors'] ?? []);
                $warnings = array_merge($warnings, $result['warnings'] ?? []);
                $passed = array_merge($passed, $result['passed'] ?? []);
            }
        }

        return [
            'errors' => $errors,
            'warnings' => $warnings,
            'passed' => $passed,
        ];
    }

    /**
     * Check API security configuration.
     *
     * @return array<string, array<string>>
     */
    protected function checkApi(): array
    {
        $errors = [];
        $warnings = [];
        $passed = [];

        $apiConfig = config('artisanpack.security.api', []);

        if (! ($apiConfig['enabled'] ?? false)) {
            $warnings[] = '[API-001] API security layer is disabled';
        } else {
            $passed[] = '[API-001] API security layer is enabled';
        }

        // Token expiration
        $expiration = $apiConfig['tokens']['expiration'] ?? null;
        if ($expiration === null) {
            $warnings[] = '[API-002] API tokens do not expire by default';
        } elseif ($expiration > 60 * 24 * 30) { // 30 days
            $warnings[] = '[API-003] API token expiration is very long (> 30 days)';
        } else {
            $passed[] = '[API-002] API token expiration is configured';
        }

        // Rate limiting
        $rateLimiting = config('artisanpack.security.rateLimiting', []);
        if (! ($rateLimiting['enabled'] ?? false)) {
            $warnings[] = '[API-004] Rate limiting is disabled';
        } else {
            $passed[] = '[API-004] Rate limiting is enabled';
        }

        return ['errors' => $errors, 'warnings' => $warnings, 'passed' => $passed];
    }

    /**
     * Check RBAC configuration.
     *
     * @return array<string, array<string>>
     */
    protected function checkRbac(): array
    {
        $errors = [];
        $warnings = [];
        $passed = [];

        $rbacConfig = config('artisanpack.security.rbac', []);

        if (! ($rbacConfig['enabled'] ?? false)) {
            $warnings[] = '[RBAC-001] RBAC is disabled';
        } else {
            $passed[] = '[RBAC-001] RBAC is enabled';
        }

        return ['errors' => $errors, 'warnings' => $warnings, 'passed' => $passed];
    }

    /**
     * Check CSP configuration.
     *
     * @return array<string, array<string>>
     */
    protected function checkCsp(): array
    {
        $errors = [];
        $warnings = [];
        $passed = [];

        $cspConfig = config('artisanpack.security.csp', []);
        $headers = config('artisanpack.security.security-headers', []);

        // Check if CSP is configured
        $cspHeader = $headers['Content-Security-Policy'] ?? '';
        if (empty($cspHeader)) {
            $errors[] = '[CSP-001] Content-Security-Policy header is not configured';
        } else {
            $passed[] = '[CSP-001] Content-Security-Policy header is configured';

            // Check for unsafe values
            if (str_contains($cspHeader, "'unsafe-inline'")) {
                $warnings[] = "[CSP-002] CSP contains 'unsafe-inline'";
            } else {
                $passed[] = "[CSP-002] CSP does not use 'unsafe-inline'";
            }

            if (str_contains($cspHeader, "'unsafe-eval'")) {
                $warnings[] = "[CSP-003] CSP contains 'unsafe-eval'";
            } else {
                $passed[] = "[CSP-003] CSP does not use 'unsafe-eval'";
            }

            if (str_contains($cspHeader, ' * ') || str_ends_with($cspHeader, ' *')) {
                $errors[] = '[CSP-004] CSP contains wildcard (*) source';
            } else {
                $passed[] = '[CSP-004] CSP does not use wildcard sources';
            }
        }

        // Check for violation reporting
        if (! ($cspConfig['reporting']['enabled'] ?? false)) {
            $warnings[] = '[CSP-005] CSP violation reporting is disabled';
        } else {
            $passed[] = '[CSP-005] CSP violation reporting is enabled';
        }

        return ['errors' => $errors, 'warnings' => $warnings, 'passed' => $passed];
    }

    /**
     * Check password security configuration.
     *
     * @return array<string, array<string>>
     */
    protected function checkPassword(): array
    {
        $errors = [];
        $warnings = [];
        $passed = [];

        $passwordConfig = config('artisanpack.security.passwordSecurity', []);

        if (! ($passwordConfig['enabled'] ?? false)) {
            $warnings[] = '[PWD-001] Password security features are disabled';
        } else {
            $passed[] = '[PWD-001] Password security features are enabled';
        }

        // HIBP integration
        if (! ($passwordConfig['hibpCheck']['enabled'] ?? false)) {
            $warnings[] = '[PWD-002] HaveIBeenPwned password check is disabled';
        } else {
            $passed[] = '[PWD-002] HaveIBeenPwned password check is enabled';
        }

        // Password history
        if (! ($passwordConfig['history']['enabled'] ?? false)) {
            $warnings[] = '[PWD-003] Password history (reuse prevention) is disabled';
        } else {
            $passed[] = '[PWD-003] Password history is enabled';
        }

        return ['errors' => $errors, 'warnings' => $warnings, 'passed' => $passed];
    }

    /**
     * Check file upload security configuration.
     *
     * @return array<string, array<string>>
     */
    protected function checkUpload(): array
    {
        $errors = [];
        $warnings = [];
        $passed = [];

        $uploadConfig = config('artisanpack.security.fileUpload', []);

        if (! ($uploadConfig['enabled'] ?? false)) {
            $warnings[] = '[UPLOAD-001] File upload security is disabled';
        } else {
            $passed[] = '[UPLOAD-001] File upload security is enabled';
        }

        // Malware scanning
        $scannerDriver = $uploadConfig['malware']['driver'] ?? 'null';
        if ($scannerDriver === 'null') {
            $warnings[] = '[UPLOAD-002] Malware scanning is disabled (null driver)';
        } else {
            $passed[] = "[UPLOAD-002] Malware scanning is enabled ({$scannerDriver})";
        }

        // Quarantine
        if (! ($uploadConfig['quarantine']['enabled'] ?? false)) {
            $warnings[] = '[UPLOAD-003] File quarantine is disabled';
        } else {
            $passed[] = '[UPLOAD-003] File quarantine is enabled';
        }

        // Dangerous extensions blocked
        $dangerousExts = ['php', 'phtml', 'php3', 'php4', 'php5', 'exe', 'sh', 'bat'];
        $blockedExts = $uploadConfig['validation']['blockedExtensions'] ?? [];
        $missingBlocks = array_diff($dangerousExts, $blockedExts);
        if (! empty($missingBlocks)) {
            $warnings[] = '[UPLOAD-004] Some dangerous extensions not blocked: '.implode(', ', $missingBlocks);
        } else {
            $passed[] = '[UPLOAD-004] Dangerous file extensions are blocked';
        }

        return ['errors' => $errors, 'warnings' => $warnings, 'passed' => $passed];
    }

    /**
     * Check session security configuration.
     *
     * @return array<string, array<string>>
     */
    protected function checkSession(): array
    {
        $errors = [];
        $warnings = [];
        $passed = [];

        $sessionDriver = config('session.driver');
        $sessionSecure = config('session.secure');
        $sessionHttpOnly = config('session.http_only');
        $sessionSameSite = config('session.same_site');

        // Session driver
        if ($sessionDriver === 'file') {
            $warnings[] = '[SESSION-001] Using file session driver (consider database or redis for production)';
        } else {
            $passed[] = "[SESSION-001] Using {$sessionDriver} session driver";
        }

        // Secure cookies
        if (! $sessionSecure && App::environment('production')) {
            $errors[] = '[SESSION-002] Session cookies not marked as secure in production';
        } else {
            $passed[] = '[SESSION-002] Session secure cookie configured correctly';
        }

        // HTTP only
        if (! $sessionHttpOnly) {
            $errors[] = '[SESSION-003] Session cookies not marked as HTTP-only';
        } else {
            $passed[] = '[SESSION-003] Session cookies are HTTP-only';
        }

        // SameSite
        if (empty($sessionSameSite) || $sessionSameSite === 'none') {
            $warnings[] = '[SESSION-004] Session SameSite attribute is not set or is "none"';
        } else {
            $passed[] = "[SESSION-004] Session SameSite is '{$sessionSameSite}'";
        }

        return ['errors' => $errors, 'warnings' => $warnings, 'passed' => $passed];
    }

    /**
     * Check general security configuration.
     *
     * @return array<string, array<string>>
     */
    protected function checkSecurity(): array
    {
        $errors = [];
        $warnings = [];
        $passed = [];

        $headers = config('artisanpack.security.security-headers', []);

        // HSTS
        if (empty($headers['Strict-Transport-Security'])) {
            if (App::environment('production')) {
                $errors[] = '[SEC-001] HSTS header not configured';
            } else {
                $warnings[] = '[SEC-001] HSTS header not configured';
            }
        } else {
            $passed[] = '[SEC-001] HSTS header is configured';
        }

        // X-Frame-Options
        if (empty($headers['X-Frame-Options'])) {
            $errors[] = '[SEC-002] X-Frame-Options header not configured';
        } else {
            $passed[] = '[SEC-002] X-Frame-Options header is configured';
        }

        // X-Content-Type-Options
        if (empty($headers['X-Content-Type-Options'])) {
            $warnings[] = '[SEC-003] X-Content-Type-Options header not configured';
        } else {
            $passed[] = '[SEC-003] X-Content-Type-Options header is configured';
        }

        // XSS Protection
        $xssEnabled = config('artisanpack.security.xss.enabled', false);
        if (! $xssEnabled) {
            $warnings[] = '[SEC-004] XSS protection middleware is disabled';
        } else {
            $passed[] = '[SEC-004] XSS protection middleware is enabled';
        }

        return ['errors' => $errors, 'warnings' => $warnings, 'passed' => $passed];
    }

    /**
     * Filter out ignored checks.
     *
     * @param  array<string>  $items
     * @param  array<string>  $ignored
     * @return array<string>
     */
    protected function filterIgnored(array $items, array $ignored): array
    {
        if (empty($ignored)) {
            return $items;
        }

        return array_filter($items, function ($item) use ($ignored) {
            foreach ($ignored as $ignoreId) {
                if (str_contains($item, "[{$ignoreId}]")) {
                    return false;
                }
            }

            return true;
        });
    }

    /**
     * Output results as JSON.
     *
     * @param  array<string>  $errors
     * @param  array<string>  $warnings
     * @param  array<string>  $passed
     */
    protected function outputJson(array $errors, array $warnings, array $passed, bool $isStrict): int
    {
        $status = 'passed';
        if (! empty($errors) || ($isStrict && ! empty($warnings))) {
            $status = 'failed';
        } elseif (! empty($warnings)) {
            $status = 'passed_with_warnings';
        }

        $output = [
            'status' => $status,
            'environment' => App::environment(),
            'timestamp' => now()->toIso8601String(),
            'summary' => [
                'errors' => count($errors),
                'warnings' => count($warnings),
                'passed' => count($passed),
            ],
            'errors' => $errors,
            'warnings' => $warnings,
            'passed' => $passed,
        ];

        $this->line(json_encode($output, JSON_PRETTY_PRINT));

        return $status === 'failed' ? self::FAILURE : self::SUCCESS;
    }

    /**
     * Output results as table.
     *
     * @param  array<string>  $errors
     * @param  array<string>  $warnings
     * @param  array<string>  $passed
     */
    protected function outputTable(array $errors, array $warnings, array $passed, bool $isStrict, bool $showPassed): int
    {
        $hasIssues = ! empty($errors) || ! empty($warnings);

        if (! empty($errors)) {
            $this->error('Errors ('.count($errors).'):');
            foreach ($errors as $error) {
                $this->line("  <fg=red>x</> {$error}");
            }
            $this->newLine();
        }

        if (! empty($warnings)) {
            $this->warn('Warnings ('.count($warnings).'):');
            foreach ($warnings as $warning) {
                $this->line("  <fg=yellow>!</> {$warning}");
            }
            $this->newLine();
        }

        if ($showPassed && ! empty($passed)) {
            $this->info('Passed ('.count($passed).'):');
            foreach ($passed as $pass) {
                $this->line("  <fg=green>✓</> {$pass}");
            }
            $this->newLine();
        }

        // Summary
        $this->line('<fg=white;options=bold>Summary:</>');
        $this->table(
            ['Status', 'Count'],
            [
                ['<fg=red>Errors</>', count($errors)],
                ['<fg=yellow>Warnings</>', count($warnings)],
                ['<fg=green>Passed</>', count($passed)],
            ]
        );

        // Final status
        $this->newLine();
        if (! empty($errors)) {
            $this->error('Security configuration check FAILED');

            return self::FAILURE;
        }

        if (! empty($warnings)) {
            if ($isStrict) {
                $this->error('Security configuration check FAILED (strict mode)');

                return self::FAILURE;
            }
            $this->warn('Security configuration check PASSED with warnings');

            return self::SUCCESS;
        }

        $this->info('Security configuration check PASSED');

        return self::SUCCESS;
    }
}
