<?php

/**
 * SecurityTestCase security-testing support.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing;

use ArtisanPackUI\Security\Testing\Reporting\SecurityFinding;
use ArtisanPackUI\Security\Testing\Traits\TestsAuthentication;
use ArtisanPackUI\Security\Testing\Traits\TestsAuthorization;
use ArtisanPackUI\Security\Testing\Traits\TestsCryptography;
use ArtisanPackUI\Security\Testing\Traits\TestsInputValidation;
use ArtisanPackUI\Security\Testing\Traits\TestsSecurityHeaders;
use ArtisanPackUI\Security\Testing\Traits\TestsSessionSecurity;
use Illuminate\Foundation\Testing\TestCase;
use Throwable;

abstract class SecurityTestCase extends TestCase
{
    use TestsAuthentication;
    use TestsAuthorization;
    use TestsCryptography;
    use TestsInputValidation;
    use TestsSecurityHeaders;
    use TestsSessionSecurity;

    /**
     * Security findings collected during tests.
     *
     * @var array<SecurityFinding>
     */
    protected array $securityFindings = [];

    /**
     * Whether to fail on vulnerability detection.
     */
    protected bool $failOnVulnerability = true;

    /**
     * Minimum severity threshold for failure.
     */
    protected string $severityThreshold = 'medium';

    protected function setUp(): void
    {
        parent::setUp();
        $this->securityFindings = [];
    }

    protected function tearDown(): void
    {
        $testFailed = false;

        // Check if the test has already failed (if method exists)
        if (method_exists($this, 'hasFailed')) {
            $testFailed = $this->hasFailed();
        } elseif (method_exists($this, 'status') && method_exists($this->status(), 'isFailure')) {
            $testFailed = $this->status()->isFailure();
        }

        // Only run security assertions if the test hasn't already failed
        // to avoid masking the original failure
        if (! $testFailed) {
            try {
                $this->assertNoSecurityVulnerabilities();
            } catch (Throwable $e) {
                parent::tearDown();
                throw $e;
            }
        }

        parent::tearDown();
    }

    /**
     * Get findings filtered by severity.
     *
     * @return array<SecurityFinding>
     */
    public function getFindings(?string $severity = null): array
    {
        if ($severity === null) {
            return $this->securityFindings;
        }

        return array_filter(
            $this->securityFindings,
            fn (SecurityFinding $f) => $f->severity === $severity,
        );
    }

    /**
     * Record a security finding.
     */
    protected function recordFinding(SecurityFinding $finding): void
    {
        $this->securityFindings[] = $finding;
    }

    /**
     * Assert that no security vulnerabilities were found based on severity threshold.
     *
     * Severity order: critical > high > medium > low > info
     * If threshold is set to 'medium', all findings of critical, high, and medium severity will fail.
     */
    protected function assertNoSecurityVulnerabilities(): void
    {
        if (! $this->failOnVulnerability) {
            return;
        }

        $critical = $this->getFindings(SecurityFinding::SEVERITY_CRITICAL);
        $high = $this->getFindings(SecurityFinding::SEVERITY_HIGH);
        $medium = $this->getFindings(SecurityFinding::SEVERITY_MEDIUM);
        $low = $this->getFindings(SecurityFinding::SEVERITY_LOW);
        $info = $this->getFindings(SecurityFinding::SEVERITY_INFO);

        // Define severity order for comparison
        $severityOrder = [
            SecurityFinding::SEVERITY_CRITICAL => 0,
            SecurityFinding::SEVERITY_HIGH => 1,
            SecurityFinding::SEVERITY_MEDIUM => 2,
            SecurityFinding::SEVERITY_LOW => 3,
            SecurityFinding::SEVERITY_INFO => 4,
        ];

        $thresholdLevel = $severityOrder[$this->severityThreshold] ?? 2; // Default to medium

        // Always check critical
        $this->assertEmpty(
            $critical,
            'Critical security vulnerabilities found: '.$this->formatFindings($critical),
        );

        // Check high if threshold allows (high, medium, low, or info)
        if ($thresholdLevel >= $severityOrder[SecurityFinding::SEVERITY_HIGH]) {
            $this->assertEmpty(
                $high,
                'High severity vulnerabilities found: '.$this->formatFindings($high),
            );
        }

        // Check medium if threshold allows (medium, low, or info)
        if ($thresholdLevel >= $severityOrder[SecurityFinding::SEVERITY_MEDIUM]) {
            $this->assertEmpty(
                $medium,
                'Medium severity vulnerabilities found: '.$this->formatFindings($medium),
            );
        }

        // Check low if threshold allows (low or info)
        if ($thresholdLevel >= $severityOrder[SecurityFinding::SEVERITY_LOW]) {
            $this->assertEmpty(
                $low,
                'Low severity vulnerabilities found: '.$this->formatFindings($low),
            );
        }

        // Check info only if threshold is info
        if ($thresholdLevel >= $severityOrder[SecurityFinding::SEVERITY_INFO]) {
            $this->assertEmpty(
                $info,
                'Info level security findings: '.$this->formatFindings($info),
            );
        }
    }

    /**
     * Format findings for error messages.
     *
     * @param  array<SecurityFinding>  $findings
     */
    protected function formatFindings(array $findings): string
    {
        if (empty($findings)) {
            return 'none';
        }

        return implode('; ', array_map(
            fn (SecurityFinding $f) => "[{$f->id}] {$f->title}",
            $findings,
        ));
    }

    /**
     * Disable vulnerability failure for this test.
     */
    protected function withoutVulnerabilityFailure(): self
    {
        $this->failOnVulnerability = false;

        return $this;
    }

    /**
     * Set the severity threshold for test failure.
     */
    protected function withSeverityThreshold(string $severity): self
    {
        $this->severityThreshold = $severity;

        return $this;
    }

    /**
     * Assert that an endpoint requires authentication.
     */
    protected function assertRequiresAuthentication(string $method, string $uri, array $data = []): void
    {
        $response = $this->$method($uri, $data);

        $this->assertTrue(
            in_array($response->status(), [401, 403, 302]),
            "Endpoint {$method} {$uri} does not require authentication (got status {$response->status()})",
        );
    }

    /**
     * Assert that an endpoint is rate limited.
     */
    protected function assertRateLimited(string $method, string $uri, int $attempts = 100): void
    {
        $rateLimited = false;

        for ($i = 0; $i < $attempts; $i++) {
            $response = $this->$method($uri);
            if ($response->status() === 429) {
                $rateLimited = true;
                break;
            }
        }

        $this->assertTrue(
            $rateLimited,
            "Endpoint {$method} {$uri} is not rate limited after {$attempts} attempts",
        );
    }
}
