<?php

/**
 * HeaderScanner security scanner.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\Scanners;

use ArtisanPackUI\Security\Testing\Reporting\SecurityFinding;
use Illuminate\Http\Request;

class HeaderScanner implements ScannerInterface
{
    /**
     * @var array<SecurityFinding>
     */
    protected array $findings = [];

    /**
     * URL to test for headers.
     */
    protected ?string $testUrl = null;

    /**
     * Headers collected from a response.
     *
     * @var array<string, string>
     */
    protected array $responseHeaders = [];

    public function __construct(?string $testUrl = null)
    {
        $this->testUrl = $testUrl;
    }

    /**
     * Set headers to analyze (for testing without HTTP request).
     *
     * @param  array<string, string>  $headers
     */
    public function setHeaders(array $headers): self
    {
        $this->responseHeaders = $headers;

        return $this;
    }

    public function scan(): array
    {
        $this->findings = [];

        $this->scanSecurityHeaders();
        $this->scanInformationDisclosure();
        $this->scanCookieHeaders();

        return $this->findings;
    }

    public function getName(): string
    {
        return 'Security Header Scanner';
    }

    public function getDescription(): string
    {
        return 'Analyzes HTTP response headers for security issues';
    }

    /**
     * Scan for missing security headers.
     */
    protected function scanSecurityHeaders(): void
    {
        $requiredHeaders = [
            'X-Frame-Options' => [
                'severity'    => 'medium',
                'title'       => 'Missing X-Frame-Options',
                'description' => 'X-Frame-Options header is not set, allowing clickjacking',
                'remediation' => 'Add X-Frame-Options: DENY or SAMEORIGIN',
            ],
            'X-Content-Type-Options' => [
                'severity'    => 'medium',
                'title'       => 'Missing X-Content-Type-Options',
                'description' => 'X-Content-Type-Options header is not set',
                'remediation' => 'Add X-Content-Type-Options: nosniff',
            ],
            'Strict-Transport-Security' => [
                'severity'    => 'high',
                'title'       => 'Missing HSTS Header',
                'description' => 'Strict-Transport-Security header is not set',
                'remediation' => 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains',
            ],
            'Content-Security-Policy' => [
                'severity'    => 'high',
                'title'       => 'Missing Content-Security-Policy',
                'description' => 'No Content-Security-Policy header to prevent XSS',
                'remediation' => 'Implement a Content-Security-Policy',
            ],
            'Referrer-Policy' => [
                'severity'    => 'low',
                'title'       => 'Missing Referrer-Policy',
                'description' => 'Referrer-Policy header is not set',
                'remediation' => 'Add Referrer-Policy: strict-origin-when-cross-origin',
            ],
            'Permissions-Policy' => [
                'severity'    => 'low',
                'title'       => 'Missing Permissions-Policy',
                'description' => 'Permissions-Policy header is not set',
                'remediation' => 'Add Permissions-Policy to restrict browser features',
            ],
        ];

        foreach ($requiredHeaders as $header => $config) {
            if (! $this->hasHeader($header)) {
                $this->findings[] = new SecurityFinding(
                    id: 'HDR-'.strtoupper(substr(md5($header), 0, 8)),
                    title: $config['title'],
                    description: $config['description'],
                    severity: $config['severity'],
                    category: 'A05:2021-Security Misconfiguration',
                    remediation: $config['remediation'],
                );
            }
        }

        // Check CSP for issues if present
        $this->analyzeCsp();

        // Check HSTS settings if present
        $this->analyzeHsts();
    }

    /**
     * Scan for information disclosure headers.
     */
    protected function scanInformationDisclosure(): void
    {
        $disclosureHeaders = [
            'Server'              => 'Server version information exposed',
            'X-Powered-By'        => 'Technology stack information exposed',
            'X-AspNet-Version'    => 'ASP.NET version information exposed',
            'X-AspNetMvc-Version' => 'ASP.NET MVC version exposed',
            'X-Generator'         => 'Generator information exposed',
            'X-Drupal-Cache'      => 'Drupal cache information exposed',
            'X-Varnish'           => 'Varnish cache information exposed',
        ];

        foreach ($disclosureHeaders as $header => $description) {
            if ($this->hasHeader($header)) {
                $this->findings[] = SecurityFinding::low(
                    'Information Disclosure',
                    $description,
                    'A05:2021-Security Misconfiguration',
                    "Header: {$header}",
                    "Remove or mask the {$header} header",
                );
            }
        }
    }

    /**
     * Scan cookie-related headers.
     */
    protected function scanCookieHeaders(): void
    {
        $cookies = $this->getHeaderValues('Set-Cookie');

        if (empty($cookies)) {
            return;
        }

        foreach ($cookies as $cookie) {
            $cookieName = $this->parseCookieName($cookie);

            // Check for Secure flag
            if (! str_contains(strtolower($cookie), 'secure') && app()->environment('production')) {
                $this->findings[] = SecurityFinding::high(
                    'Cookie Missing Secure Flag',
                    "Cookie '{$cookieName}' is not marked as Secure",
                    'A02:2021-Cryptographic Failures',
                    "Set-Cookie: {$cookieName}",
                    'Add Secure flag to cookie',
                );
            }

            // Check for HttpOnly flag on session cookies
            if (! str_contains(strtolower($cookie), 'httponly')) {
                // Session and auth cookies should always be HttpOnly
                $sensitiveNames = ['session', 'sess', 'auth', 'token', 'jwt'];
                foreach ($sensitiveNames as $name) {
                    if (str_contains(strtolower($cookieName), $name)) {
                        $this->findings[] = SecurityFinding::medium(
                            'Sensitive Cookie Missing HttpOnly',
                            "Sensitive cookie '{$cookieName}' is not HttpOnly",
                            'A05:2021-Security Misconfiguration',
                            "Set-Cookie: {$cookieName}",
                            'Add HttpOnly flag to sensitive cookies',
                        );
                        break;
                    }
                }
            }

            // Check SameSite attribute
            if (! preg_match('/samesite\s*=\s*(strict|lax)/i', $cookie)) {
                $this->findings[] = SecurityFinding::low(
                    'Cookie Missing SameSite',
                    "Cookie '{$cookieName}' has no SameSite attribute",
                    'A01:2021-Broken Access Control',
                    "Set-Cookie: {$cookieName}",
                    'Add SameSite=Lax or SameSite=Strict',
                );
            }
        }
    }

    /**
     * Analyze Content-Security-Policy header.
     */
    protected function analyzeCsp(): void
    {
        $csp = $this->getHeader('Content-Security-Policy')
            ?? $this->getHeader('Content-Security-Policy-Report-Only');

        if (! $csp) {
            return;
        }

        // Check for unsafe directives
        if (str_contains($csp, "'unsafe-inline'") &&
            ! str_contains($csp, "'strict-dynamic'") &&
            ! preg_match("/'nonce-/", $csp)) {
            $this->findings[] = SecurityFinding::medium(
                'CSP Uses unsafe-inline',
                'CSP uses unsafe-inline without nonce or strict-dynamic',
                'A05:2021-Security Misconfiguration',
                'Content-Security-Policy header',
                'Use nonces or hashes instead of unsafe-inline',
            );
        }

        if (str_contains($csp, "'unsafe-eval'")) {
            $this->findings[] = SecurityFinding::medium(
                'CSP Uses unsafe-eval',
                'CSP allows unsafe-eval which enables code injection',
                'A05:2021-Security Misconfiguration',
                'Content-Security-Policy header',
                'Remove unsafe-eval and refactor to avoid eval()',
            );
        }

        // Check for wildcard sources
        if (preg_match('/\s\*\s|^\*\s|\s\*$/', $csp)) {
            $this->findings[] = SecurityFinding::medium(
                'CSP Uses Wildcard',
                'CSP contains wildcard (*) source which is too permissive',
                'A05:2021-Security Misconfiguration',
                'Content-Security-Policy header',
                'Replace wildcards with specific trusted domains',
            );
        }
    }

    /**
     * Analyze HSTS header.
     */
    protected function analyzeHsts(): void
    {
        $hsts = $this->getHeader('Strict-Transport-Security');

        if (! $hsts) {
            return;
        }

        // Check max-age
        if (preg_match('/max-age=(\d+)/', $hsts, $matches)) {
            $maxAge = (int) $matches[1];

            if ($maxAge < 31536000) {
                $this->findings[] = SecurityFinding::low(
                    'Short HSTS Max-Age',
                    "HSTS max-age ({$maxAge}s) is less than 1 year",
                    'A05:2021-Security Misconfiguration',
                    'Strict-Transport-Security header',
                    'Increase max-age to at least 31536000 (1 year)',
                );
            }
        }

        // Check for includeSubDomains
        if (! str_contains(strtolower($hsts), 'includesubdomains')) {
            $this->findings[] = SecurityFinding::info(
                'HSTS Missing includeSubDomains',
                'HSTS does not include subdomains',
                'A05:2021-Security Misconfiguration',
                'Strict-Transport-Security header',
                'Consider adding includeSubDomains directive',
            );
        }
    }

    /**
     * Check if a header exists.
     */
    protected function hasHeader(string $name): bool
    {
        return isset($this->responseHeaders[strtolower($name)]) ||
               isset($this->responseHeaders[$name]);
    }

    /**
     * Get a header value (single or first value).
     */
    protected function getHeader(string $name): ?string
    {
        $value = $this->responseHeaders[strtolower($name)]
            ?? $this->responseHeaders[$name]
            ?? null;

        // Handle case where header value might be stored as array
        if (is_array($value)) {
            return $value[0] ?? null;
        }

        return $value;
    }

    /**
     * Get all values for a header (handles multiple Set-Cookie headers).
     *
     * @return array<string>
     */
    protected function getHeaderValues(string $name): array
    {
        $value = $this->responseHeaders[strtolower($name)]
            ?? $this->responseHeaders[$name]
            ?? null;

        if (null === $value) {
            return [];
        }

        if (is_array($value)) {
            return $value;
        }

        return [$value];
    }

    /**
     * Parse cookie name from Set-Cookie header.
     */
    protected function parseCookieName(string $setCookie): string
    {
        $parts = explode('=', $setCookie, 2);

        return trim($parts[0]);
    }
}
