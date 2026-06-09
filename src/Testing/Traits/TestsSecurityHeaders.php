<?php

/**
 * TestsSecurityHeaders testing trait.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\Traits;

use ArtisanPackUI\Security\Testing\Reporting\SecurityFinding;
use Illuminate\Testing\TestResponse;

trait TestsSecurityHeaders
{
    /**
     * Assert that all recommended security headers are present.
     */
    protected function assertSecurityHeaders(TestResponse $response): void
    {
        $this->assertHasXFrameOptions($response);
        $this->assertHasXContentTypeOptions($response);
        $this->assertHasXXssProtection($response);
        $this->assertHasStrictTransportSecurity($response);
        $this->assertHasContentSecurityPolicy($response);
        $this->assertHasReferrerPolicy($response);
        $this->assertHasPermissionsPolicy($response);
    }

    /**
     * Assert X-Frame-Options header is present.
     */
    protected function assertHasXFrameOptions(TestResponse $response): void
    {
        $header = $response->headers->get('X-Frame-Options');

        if (! $header) {
            $this->recordFinding(SecurityFinding::medium(
                'Missing X-Frame-Options Header',
                'Response does not include X-Frame-Options header',
                'A05:2021-Security Misconfiguration',
                remediation: 'Add X-Frame-Options: DENY or SAMEORIGIN header',
            ));
        } else {
            $validValues = ['DENY', 'SAMEORIGIN'];
            if (! in_array(strtoupper($header), $validValues)) {
                $this->recordFinding(SecurityFinding::low(
                    'Weak X-Frame-Options Value',
                    "X-Frame-Options value '{$header}' may not be secure",
                    'A05:2021-Security Misconfiguration',
                    remediation: 'Use DENY or SAMEORIGIN',
                ));
            }
        }
    }

    /**
     * Assert X-Content-Type-Options header is present.
     */
    protected function assertHasXContentTypeOptions(TestResponse $response): void
    {
        $header = $response->headers->get('X-Content-Type-Options');

        if ($header !== 'nosniff') {
            $this->recordFinding(SecurityFinding::medium(
                'Missing X-Content-Type-Options Header',
                'Response does not include X-Content-Type-Options: nosniff',
                'A05:2021-Security Misconfiguration',
                remediation: 'Add X-Content-Type-Options: nosniff header',
            ));
        }
    }

    /**
     * Assert X-XSS-Protection header is present.
     */
    protected function assertHasXXssProtection(TestResponse $response): void
    {
        $header = $response->headers->get('X-XSS-Protection');

        // Modern recommendation is to disable or omit this header and rely on CSP
        if ($header && ! in_array($header, ['0', '1; mode=block'])) {
            $this->recordFinding(SecurityFinding::low(
                'Suboptimal X-XSS-Protection',
                "X-XSS-Protection value '{$header}' may not be optimal",
                'A05:2021-Security Misconfiguration',
                remediation: 'Use "0" (disabled, rely on CSP) or "1; mode=block"',
            ));
        }
    }

    /**
     * Assert Strict-Transport-Security header is present.
     */
    protected function assertHasStrictTransportSecurity(TestResponse $response): void
    {
        $header = $response->headers->get('Strict-Transport-Security');

        if (! $header) {
            $this->recordFinding(SecurityFinding::high(
                'Missing HSTS Header',
                'Response does not include Strict-Transport-Security header',
                'A05:2021-Security Misconfiguration',
                remediation: 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains',
            ));

            return;
        }

        // Check for minimum max-age
        if (preg_match('/max-age=(\d+)/', $header, $matches)) {
            $maxAge = (int) $matches[1];
            if ($maxAge < 31536000) { // Less than 1 year
                $this->recordFinding(SecurityFinding::low(
                    'Short HSTS Max-Age',
                    "HSTS max-age ({$maxAge}) is less than recommended 1 year",
                    'A05:2021-Security Misconfiguration',
                    remediation: 'Increase max-age to at least 31536000 (1 year)',
                ));
            }
        }
    }

    /**
     * Assert Content-Security-Policy header is present.
     */
    protected function assertHasContentSecurityPolicy(TestResponse $response): void
    {
        $header = $response->headers->get('Content-Security-Policy')
            ?? $response->headers->get('Content-Security-Policy-Report-Only');

        if (! $header) {
            $this->recordFinding(SecurityFinding::high(
                'Missing Content-Security-Policy Header',
                'Response does not include a Content-Security-Policy header',
                'A05:2021-Security Misconfiguration',
                remediation: 'Implement a Content-Security-Policy to prevent XSS attacks',
            ));

            return;
        }

        // Check for unsafe directives
        if (str_contains($header, "'unsafe-inline'") && ! str_contains($header, "'strict-dynamic'") && ! preg_match("/'nonce-/", $header)) {
            $this->recordFinding(SecurityFinding::medium(
                'CSP Uses unsafe-inline',
                'CSP uses unsafe-inline without nonce or strict-dynamic',
                'A05:2021-Security Misconfiguration',
                remediation: 'Use nonces or strict-dynamic instead of unsafe-inline',
            ));
        }

        if (str_contains($header, "'unsafe-eval'")) {
            $this->recordFinding(SecurityFinding::medium(
                'CSP Uses unsafe-eval',
                'CSP uses unsafe-eval which allows dynamic code execution',
                'A05:2021-Security Misconfiguration',
                remediation: 'Remove unsafe-eval and refactor code to avoid eval()',
            ));
        }
    }

    /**
     * Assert Referrer-Policy header is present.
     */
    protected function assertHasReferrerPolicy(TestResponse $response): void
    {
        $header = $response->headers->get('Referrer-Policy');

        if (! $header) {
            $this->recordFinding(SecurityFinding::low(
                'Missing Referrer-Policy Header',
                'Response does not include Referrer-Policy header',
                'A05:2021-Security Misconfiguration',
                remediation: 'Add Referrer-Policy: strict-origin-when-cross-origin',
            ));

            return;
        }

        $insecurePolicies = ['unsafe-url', 'no-referrer-when-downgrade'];
        if (in_array($header, $insecurePolicies)) {
            $this->recordFinding(SecurityFinding::low(
                'Insecure Referrer-Policy',
                "Referrer-Policy '{$header}' may leak sensitive information",
                'A05:2021-Security Misconfiguration',
                remediation: 'Use strict-origin-when-cross-origin or stricter policy',
            ));
        }
    }

    /**
     * Assert Permissions-Policy header is present.
     */
    protected function assertHasPermissionsPolicy(TestResponse $response): void
    {
        $header = $response->headers->get('Permissions-Policy')
            ?? $response->headers->get('Feature-Policy');

        if (! $header) {
            $this->recordFinding(SecurityFinding::low(
                'Missing Permissions-Policy Header',
                'Response does not include Permissions-Policy header',
                'A05:2021-Security Misconfiguration',
                remediation: 'Add Permissions-Policy to restrict browser features',
            ));
        }
    }

    /**
     * Assert that sensitive headers are not exposed.
     */
    protected function assertNoSensitiveHeaders(TestResponse $response): void
    {
        $sensitiveHeaders = [
            'Server',
            'X-Powered-By',
            'X-AspNet-Version',
            'X-AspNetMvc-Version',
        ];

        foreach ($sensitiveHeaders as $header) {
            if ($response->headers->has($header)) {
                $this->recordFinding(SecurityFinding::low(
                    'Information Disclosure via Headers',
                    "Response includes '{$header}' header which reveals server information",
                    'A05:2021-Security Misconfiguration',
                    remediation: "Remove or mask the '{$header}' header",
                ));
            }
        }
    }

    /**
     * Assert Cache-Control headers for sensitive endpoints.
     */
    protected function assertNoCacheForSensitiveEndpoint(TestResponse $response): void
    {
        $cacheControl = $response->headers->get('Cache-Control');

        $requiredDirectives = ['no-store', 'no-cache', 'must-revalidate'];
        $hasRequiredDirectives = true;

        foreach ($requiredDirectives as $directive) {
            if (! str_contains($cacheControl ?? '', $directive)) {
                $hasRequiredDirectives = false;
                break;
            }
        }

        if (! $hasRequiredDirectives) {
            $this->recordFinding(SecurityFinding::medium(
                'Sensitive Data May Be Cached',
                'Response does not have proper Cache-Control headers for sensitive data',
                'A05:2021-Security Misconfiguration',
                remediation: 'Add Cache-Control: no-store, no-cache, must-revalidate',
            ));
        }
    }
}
