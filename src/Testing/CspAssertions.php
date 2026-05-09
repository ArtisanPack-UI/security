<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing;

use ArtisanPackUI\Security\Contracts\CspPolicyInterface;
use Illuminate\Testing\TestResponse;

trait CspAssertions
{
    /**
     * Assert the response has a Content-Security-Policy header.
     */
    protected function assertHasCspHeader(TestResponse $response): void
    {
        $response->assertHeader('Content-Security-Policy');
    }

    /**
     * Assert the response has a Content-Security-Policy-Report-Only header.
     */
    protected function assertHasCspReportOnlyHeader(TestResponse $response): void
    {
        $response->assertHeader('Content-Security-Policy-Report-Only');
    }

    /**
     * Assert the response has no CSP headers.
     */
    protected function assertNoCspHeaders(TestResponse $response): void
    {
        $response->assertHeaderMissing('Content-Security-Policy');
        $response->assertHeaderMissing('Content-Security-Policy-Report-Only');
    }

    /**
     * Assert the CSP header contains a specific directive.
     */
    protected function assertCspContainsDirective(TestResponse $response, string $directive): void
    {
        $csp = $response->headers->get('Content-Security-Policy')
            ?? $response->headers->get('Content-Security-Policy-Report-Only');

        $this->assertNotNull($csp, 'No CSP header found in response');
        $this->assertStringContainsString(
            $directive,
            $csp,
            "CSP header does not contain directive: {$directive}",
        );
    }

    /**
     * Assert the CSP header has a specific directive with a value.
     */
    protected function assertCspDirectiveContains(TestResponse $response, string $directive, string $value): void
    {
        $csp = $response->headers->get('Content-Security-Policy')
            ?? $response->headers->get('Content-Security-Policy-Report-Only');

        $this->assertNotNull($csp, 'No CSP header found in response');

        // Parse the CSP and find the directive
        $directives = $this->parseCspDirectives($csp);

        $this->assertArrayHasKey(
            $directive,
            $directives,
            "CSP header does not contain directive: {$directive}",
        );

        $this->assertStringContainsString(
            $value,
            $directives[$directive],
            "Directive {$directive} does not contain: {$value}",
        );
    }

    /**
     * Assert the CSP header contains a nonce.
     */
    protected function assertCspContainsNonce(TestResponse $response): void
    {
        $csp = $response->headers->get('Content-Security-Policy')
            ?? $response->headers->get('Content-Security-Policy-Report-Only');

        $this->assertNotNull($csp, 'No CSP header found in response');
        $this->assertMatchesRegularExpression(
            "/'nonce-[A-Za-z0-9+\/=]+'/",
            $csp,
            'CSP header does not contain a nonce',
        );
    }

    /**
     * Assert the CSP header uses strict-dynamic.
     */
    protected function assertCspUsesStrictDynamic(TestResponse $response): void
    {
        $csp = $response->headers->get('Content-Security-Policy')
            ?? $response->headers->get('Content-Security-Policy-Report-Only');

        $this->assertNotNull($csp, 'No CSP header found in response');
        $this->assertStringContainsString(
            "'strict-dynamic'",
            $csp,
            'CSP header does not use strict-dynamic',
        );
    }

    /**
     * Assert the CSP header does not contain unsafe-inline for scripts.
     */
    protected function assertCspNoUnsafeInline(TestResponse $response): void
    {
        $csp = $response->headers->get('Content-Security-Policy')
            ?? $response->headers->get('Content-Security-Policy-Report-Only');

        $this->assertNotNull($csp, 'No CSP header found in response');

        $directives = $this->parseCspDirectives($csp);

        if (isset($directives['script-src'])) {
            // Allow unsafe-inline only when combined with nonce or strict-dynamic
            $hasNonce         = preg_match("/'nonce-[A-Za-z0-9+\/=]+'/", $directives['script-src']);
            $hasStrictDynamic = str_contains($directives['script-src'], "'strict-dynamic'");

            if (str_contains($directives['script-src'], "'unsafe-inline'")) {
                $this->assertTrue(
                    $hasNonce || $hasStrictDynamic,
                    'script-src contains unsafe-inline without nonce or strict-dynamic',
                );
            }
        }
    }

    /**
     * Assert the CSP header does not contain unsafe-eval.
     */
    protected function assertCspNoUnsafeEval(TestResponse $response): void
    {
        $csp = $response->headers->get('Content-Security-Policy')
            ?? $response->headers->get('Content-Security-Policy-Report-Only');

        $this->assertNotNull($csp, 'No CSP header found in response');
        $this->assertStringNotContainsString(
            "'unsafe-eval'",
            $csp,
            'CSP header contains unsafe-eval',
        );
    }

    /**
     * Assert the CSP header has a report-uri directive.
     */
    protected function assertCspHasReportUri(TestResponse $response, ?string $uri = null): void
    {
        $csp = $response->headers->get('Content-Security-Policy')
            ?? $response->headers->get('Content-Security-Policy-Report-Only');

        $this->assertNotNull($csp, 'No CSP header found in response');
        $this->assertStringContainsString(
            'report-uri',
            $csp,
            'CSP header does not have report-uri',
        );

        if (null !== $uri) {
            $this->assertStringContainsString(
                $uri,
                $csp,
                "CSP report-uri does not contain: {$uri}",
            );
        }
    }

    /**
     * Get the nonce from the CSP header.
     */
    protected function extractCspNonce(TestResponse $response): ?string
    {
        $csp = $response->headers->get('Content-Security-Policy')
            ?? $response->headers->get('Content-Security-Policy-Report-Only');

        if (null === $csp) {
            return null;
        }

        if (preg_match("/'nonce-([A-Za-z0-9+\/=]+)'/", $csp, $matches)) {
            return $matches[1];
        }

        return null;
    }

    /**
     * Get the CSP service instance.
     */
    protected function getCspService(): CspPolicyInterface
    {
        return app(CspPolicyInterface::class);
    }

    /**
     * Assert a nonce is valid and matches the service.
     */
    protected function assertNonceValid(string $nonce): void
    {
        $this->assertNotEmpty($nonce, 'Nonce is empty');
        $this->assertMatchesRegularExpression(
            '/^[A-Za-z0-9+\/=]+$/',
            $nonce,
            'Nonce is not valid base64',
        );

        // Verify minimum length (16 bytes = ~22 base64 chars)
        $this->assertGreaterThanOrEqual(
            22,
            strlen($nonce),
            'Nonce is too short (should be at least 16 bytes)',
        );
    }

    /**
     * Create a mock CSP violation report for testing.
     *
     * @return array<string, mixed>
     */
    protected function createMockCspViolation(array $overrides = []): array
    {
        return array_merge([
            'csp-report' => [
                'document-uri'        => 'https://example.com/page',
                'blocked-uri'         => 'https://evil.com/script.js',
                'violated-directive'  => 'script-src',
                'effective-directive' => 'script-src',
                'original-policy'     => "default-src 'self'; script-src 'self'",
                'disposition'         => 'enforce',
                'referrer'            => '',
                'status-code'         => 200,
            ],
        ], $overrides);
    }

    /**
     * Submit a mock CSP violation report.
     */
    protected function submitCspViolation(array $report = []): TestResponse
    {
        $violation = $this->createMockCspViolation($report);

        return $this->postJson(
            config('artisanpack.security.csp.reporting.uri', '/csp-violation'),
            $violation,
            ['Content-Type' => 'application/csp-report'],
        );
    }

    /**
     * Parse CSP directives from a policy string.
     *
     * @return array<string, string>
     */
    protected function parseCspDirectives(string $policy): array
    {
        $directives = [];
        $parts      = explode(';', $policy);

        foreach ($parts as $part) {
            $part = trim($part);
            if (empty($part)) {
                continue;
            }

            $spacePos = strpos($part, ' ');
            if (false !== $spacePos) {
                $name  = substr($part, 0, $spacePos);
                $value = substr($part, $spacePos + 1);
            } else {
                $name  = $part;
                $value = '';
            }

            $directives[$name] = $value;
        }

        return $directives;
    }

    /**
     * Disable CSP for a test.
     */
    protected function withoutCsp(): self
    {
        config(['artisanpack.security.csp.enabled' => false]);

        return $this;
    }

    /**
     * Enable CSP report-only mode for a test.
     */
    protected function withCspReportOnly(): self
    {
        config(['artisanpack.security.csp.reportOnly' => true]);

        return $this;
    }

    /**
     * Use a specific CSP preset for a test.
     */
    protected function withCspPreset(string $preset): self
    {
        config(['artisanpack.security.csp.preset' => $preset]);

        return $this;
    }
}
