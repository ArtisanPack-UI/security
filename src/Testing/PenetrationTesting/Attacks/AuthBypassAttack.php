<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\PenetrationTesting\Attacks;

use ArtisanPackUI\Security\Testing\PenetrationTesting\AttackInterface;
use ArtisanPackUI\Security\Testing\PenetrationTesting\AttackResult;
use Exception;

class AuthBypassAttack implements AttackInterface
{
    public function execute(object $testCase, string $uri, array $options = []): AttackResult
    {
        $vulnerabilities = [];
        $method          = $options['method'] ?? 'get';
        $requiresAuth    = $options['requires_auth'] ?? true;

        // Test 1: Access without authentication
        try {
            $response = $testCase->$method($uri);

            if ($requiresAuth && in_array($response->status(), [200, 201, 204])) {
                $vulnerabilities[] = [
                    'type'        => 'auth-missing',
                    'description' => 'Endpoint accessible without authentication',
                    'status_code' => $response->status(),
                ];
            }
        } catch (Exception $e) {
            // Access denied as expected
        }

        // Test 2: JWT manipulation (if applicable)
        $this->testJwtManipulation($testCase, $uri, $method, $vulnerabilities);

        // Test 3: Session fixation
        $this->testSessionFixation($testCase, $uri, $vulnerabilities);

        // Test 4: Authorization header manipulation
        $this->testAuthHeaderManipulation($testCase, $uri, $method, $vulnerabilities);

        if (! empty($vulnerabilities)) {
            return AttackResult::vulnerable(
                attack: $this->getName(),
                severity: 'critical',
                findings: $vulnerabilities,
                metadata: ['uri' => $uri, 'method' => $method],
            );
        }

        return AttackResult::notVulnerable(
            attack: $this->getName(),
            metadata: ['uri' => $uri, 'method' => $method],
        );
    }

    public function getName(): string
    {
        return 'Authentication Bypass';
    }

    public function getDescription(): string
    {
        return 'Tests for authentication bypass vulnerabilities';
    }

    public function getOwaspCategory(): string
    {
        return 'A07:2021-Identification and Authentication Failures';
    }

    /**
     * Test JWT manipulation attacks.
     *
     * @param  array<array<string, mixed>>  $vulnerabilities
     */
    protected function testJwtManipulation(object $testCase, string $uri, string $method, array &$vulnerabilities): void
    {
        $jwtPayloads = [
            // Algorithm confusion (none)
            'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJhZG1pbiI6dHJ1ZX0.',
            // Modified signature
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJhZG1pbiI6dHJ1ZX0.invalid',
        ];

        foreach ($jwtPayloads as $jwt) {
            try {
                $response = $testCase
                    ->withHeader('Authorization', 'Bearer '.$jwt)
                    ->$method($uri);

                if (in_array($response->status(), [200, 201, 204])) {
                    $vulnerabilities[] = [
                        'type'        => 'jwt-bypass',
                        'description' => 'Endpoint accepts manipulated JWT',
                        'payload'     => substr($jwt, 0, 50).'...',
                    ];
                    break;
                }
            } catch (Exception $e) {
                // Expected - invalid JWT rejected
            }
        }
    }

    /**
     * Test session fixation vulnerability.
     *
     * Note: Automated verification of session fixation requires application-specific
     * login simulation which cannot be performed generically. This test documents
     * the limitation and recommends manual review.
     *
     * @param  array<array<string, mixed>>  $vulnerabilities
     */
    protected function testSessionFixation(object $testCase, string $uri, array &$vulnerabilities): void
    {
        // Capture current session state for documentation
        $currentSessionId = session()->getId();

        // Automated session fixation testing requires:
        // 1. A valid test user with known credentials
        // 2. Application-specific login endpoint knowledge
        // 3. Cookie preservation across requests
        //
        // Since we cannot simulate login generically, we:
        // 1. Check for secure session configuration
        // 2. Flag for manual review

        // Check session configuration for security best practices
        $sessionConfig = config('session');
        $issues        = [];

        if (($sessionConfig['same_site'] ?? null) === 'none') {
            $issues[] = 'SameSite cookie attribute set to "none"';
        }

        if (! ($sessionConfig['http_only'] ?? true)) {
            $issues[] = 'HttpOnly flag not enabled on session cookies';
        }

        if (app()->environment('production') && ! ($sessionConfig['secure'] ?? false)) {
            $issues[] = 'Secure flag not enabled in production';
        }

        // Always flag for manual verification since automated testing is not possible
        $vulnerabilities[] = [
            'type'               => 'session-fixation-risk',
            'description'        => 'Session fixation cannot be automatically verified. Manual review required to ensure session ID regeneration after authentication.',
            'uri'                => $uri,
            'current_session_id' => substr($currentSessionId, 0, 8).'...',
            'config_issues'      => $issues,
            'recommendation'     => 'Verify that session()->regenerate() is called after successful authentication in your LoginController',
        ];
    }

    /**
     * Test authorization header manipulation.
     *
     * @param  array<array<string, mixed>>  $vulnerabilities
     */
    protected function testAuthHeaderManipulation(object $testCase, string $uri, string $method, array &$vulnerabilities): void
    {
        $manipulationPayloads = [
            ['X-Forwarded-For', '127.0.0.1'],
            ['X-Original-URL', '/admin'],
            ['X-Rewrite-URL', '/admin'],
            ['X-Custom-IP-Authorization', '127.0.0.1'],
            ['X-Forwarded-Host', 'localhost'],
        ];

        // Capture baseline response BEFORE testing with manipulated headers
        $baselineStatus = null;
        try {
            $baseResponse   = $testCase->$method($uri);
            $baselineStatus = $baseResponse->status();
        } catch (Exception $e) {
            // Baseline request failed, assume protected
            $baselineStatus = 401;
        }

        foreach ($manipulationPayloads as [$header, $value]) {
            try {
                $response = $testCase
                    ->withHeader($header, $value)
                    ->$method($uri);

                // If adding these headers changes the response from 401/403 to success
                // it might indicate a bypass
                if (in_array($baselineStatus, [401, 403]) &&
                    in_array($response->status(), [200, 201, 204])) {
                    $vulnerabilities[] = [
                        'type'        => 'header-bypass',
                        'description' => "Authentication bypassed via {$header} header",
                        'header'      => $header,
                        'value'       => $value,
                    ];
                }
            } catch (Exception $e) {
                // Expected behavior
            }
        }
    }
}
