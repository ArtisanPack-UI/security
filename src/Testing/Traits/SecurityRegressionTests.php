<?php

/**
 * SecurityRegressionTests testing trait.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\Traits;

use ArtisanPackUI\Security\Testing\Reporting\SecurityFinding;
use Throwable;

trait SecurityRegressionTests
{
    /**
     * Registry of known fixed vulnerabilities.
     *
     * @var array<string, callable>
     */
    protected array $securityRegressions = [];

    /**
     * Results from regression tests.
     *
     * @var array<string, array<string, mixed>>
     */
    protected array $regressionResults = [];

    /**
     * Record a security finding.
     * This method must be implemented by the class using this trait.
     */
    abstract protected function recordFinding(SecurityFinding $finding): void;

    /**
     * Fail the test with the given message.
     * This method must be implemented by the class using this trait.
     */
    abstract protected function fail(string $message = ''): never;

    /**
     * Register a security regression test.
     *
     * @param  string  $id  Unique identifier (e.g., CVE number, internal ticket)
     * @param  callable  $test  Test function that should pass if vulnerability is fixed
     * @param  string|null  $description  Optional description
     */
    protected function registerSecurityRegression(string $id, callable $test, ?string $description = null): void
    {
        $this->securityRegressions[$id] = [
            'test' => $test,
            'description' => $description,
        ];
    }

    /**
     * Run all registered security regression tests.
     *
     * @return array<string, array<string, mixed>>
     */
    protected function runSecurityRegressionTests(): array
    {
        $this->regressionResults = [];

        foreach ($this->securityRegressions as $id => $config) {
            $test = $config['test'];
            $description = $config['description'] ?? $id;

            try {
                $test();
                $this->regressionResults[$id] = [
                    'status' => 'passed',
                    'description' => $description,
                ];
            } catch (Throwable $e) {
                $this->regressionResults[$id] = [
                    'status' => 'failed',
                    'description' => $description,
                    'error' => $e->getMessage(),
                    'trace' => $e->getTraceAsString(),
                ];

                $this->recordFinding(SecurityFinding::critical(
                    "Security Regression: {$id}",
                    "Previously fixed vulnerability has regressed: {$description}. Error: {$e->getMessage()}",
                    'Security Regression',
                    null,
                    'Review the fix for this vulnerability and ensure it is still in place',
                ));
            }
        }

        return $this->regressionResults;
    }

    /**
     * Assert that a previously fixed vulnerability remains fixed.
     *
     * @param  string  $id  The vulnerability identifier
     * @param  callable  $test  Test that should pass if vulnerability is fixed
     */
    protected function assertVulnerabilityFixed(string $id, callable $test): void
    {
        try {
            $test();
        } catch (Throwable $e) {
            $this->fail("Security regression: {$id} has regressed. {$e->getMessage()}");
        }
    }

    /**
     * Assert that a security fix is still effective.
     *
     * @param  string  $id  Identifier for the fix
     * @param  string  $method  HTTP method
     * @param  string  $uri  Target URI
     * @param  array<string, mixed>  $maliciousPayload  Payload that should be blocked
     * @param  array<int>|int  $expectedStatus  Expected status code(s) indicating blocked attack
     */
    protected function assertSecurityFixEffective(
        string $id,
        string $method,
        string $uri,
        array $maliciousPayload,
        int|array $expectedStatus = [400, 403, 422],
    ): void {
        $expectedStatuses = is_array($expectedStatus) ? $expectedStatus : [$expectedStatus];

        $response = $this->$method($uri, $maliciousPayload);

        if (! in_array($response->status(), $expectedStatuses)) {
            $this->recordFinding(SecurityFinding::critical(
                "Security Fix Regression: {$id}",
                'Security fix no longer effective. Expected status '.implode('/', $expectedStatuses).", got {$response->status()}",
                'Security Regression',
                "{$method} {$uri}",
                'Review and restore the security fix',
            ));

            $this->fail("Security fix {$id} has regressed. Expected status ".implode('/', $expectedStatuses).", got {$response->status()}");
        }
    }

    /**
     * Assert that input sanitization is still working.
     *
     * @param  string  $id  Identifier for the sanitization
     * @param  callable  $sanitizer  Function that sanitizes input
     * @param  string  $maliciousInput  Input that should be sanitized
     * @param  callable  $assertSanitized  Function to verify sanitization
     */
    protected function assertSanitizationEffective(
        string $id,
        callable $sanitizer,
        string $maliciousInput,
        callable $assertSanitized,
    ): void {
        $sanitizedOutput = $sanitizer($maliciousInput);

        try {
            $assertSanitized($sanitizedOutput);
        } catch (Throwable $e) {
            $this->recordFinding(SecurityFinding::high(
                "Sanitization Regression: {$id}",
                "Input sanitization no longer effective: {$e->getMessage()}",
                'Security Regression',
                null,
                'Review and restore the sanitization logic',
            ));

            $this->fail("Sanitization {$id} has regressed: {$e->getMessage()}");
        }
    }

    /**
     * Assert that access control is still enforced.
     *
     * @param  string  $id  Identifier for the access control
     * @param  string  $method  HTTP method
     * @param  string  $uri  Protected URI
     */
    protected function assertAccessControlEnforced(string $id, string $method, string $uri): void
    {
        // Test without authentication
        $response = $this->$method($uri);

        $validStatuses = [401, 403, 302];

        if (! in_array($response->status(), $validStatuses)) {
            $this->recordFinding(SecurityFinding::critical(
                "Access Control Regression: {$id}",
                "Access control no longer enforced on {$method} {$uri}",
                'Security Regression',
                "{$method} {$uri}",
                'Restore authentication/authorization middleware',
            ));

            $this->fail("Access control {$id} has regressed. Endpoint accessible without authentication.");
        }
    }

    /**
     * Load regression tests from a configuration file.
     *
     * @param  string  $path  Path to the configuration file
     */
    protected function loadRegressionTests(string $path): void
    {
        if (! file_exists($path)) {
            return;
        }

        $config = require $path;

        foreach ($config as $id => $testConfig) {
            if (isset($testConfig['test']) && is_callable($testConfig['test'])) {
                $this->registerSecurityRegression(
                    $id,
                    $testConfig['test'],
                    $testConfig['description'] ?? null,
                );
            }
        }
    }

    /**
     * Get a summary of regression test results.
     *
     * @return array<string, int>
     */
    protected function getRegressionSummary(): array
    {
        $passed = 0;
        $failed = 0;

        foreach ($this->regressionResults as $result) {
            if ($result['status'] === 'passed') {
                $passed++;
            } else {
                $failed++;
            }
        }

        return [
            'total' => count($this->regressionResults),
            'passed' => $passed,
            'failed' => $failed,
        ];
    }

    /**
     * Check if all regression tests passed.
     */
    protected function allRegressionsPassing(): bool
    {
        foreach ($this->regressionResults as $result) {
            if ($result['status'] !== 'passed') {
                return false;
            }
        }

        return true;
    }
}
