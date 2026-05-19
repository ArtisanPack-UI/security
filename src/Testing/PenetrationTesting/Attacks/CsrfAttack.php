<?php

/**
 * CsrfAttack penetration-test attack.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\PenetrationTesting\Attacks;

use ArtisanPackUI\Security\Testing\PenetrationTesting\AttackInterface;
use ArtisanPackUI\Security\Testing\PenetrationTesting\AttackResult;
use Exception;

class CsrfAttack implements AttackInterface
{
    public function execute(object $testCase, string $uri, array $options = []): AttackResult
    {
        $vulnerabilities = [];
        $method          = strtolower($options['method'] ?? 'post');

        // Only test state-changing methods
        if (! in_array($method, ['post', 'put', 'patch', 'delete'])) {
            return AttackResult::notVulnerable(
                attack: $this->getName(),
                metadata: ['uri' => $uri, 'reason' => 'GET requests do not require CSRF protection'],
            );
        }

        $data = $options['parameters'] ?? [];

        // Test 1: Request with invalid CSRF token to verify protection
        $csrfVulnerable = false;
        try {
            $response = $testCase->withHeader('X-CSRF-TOKEN', 'invalid-token-'.bin2hex(random_bytes(16)))
                ->$method($uri, $data);

            // If request succeeds with an invalid token (not 419 Token Mismatch), it's vulnerable
            if ($response->status() < 400) {
                $csrfVulnerable    = true;
                $vulnerabilities[] = [
                    'type'        => 'csrf-missing',
                    'description' => 'Endpoint accepts requests with invalid CSRF token',
                    'method'      => strtoupper($method),
                    'status_code' => $response->status(),
                ];
            }
        } catch (Exception $e) {
            // CSRF validation likely active - this is expected
        }

        // Test 2: Request without any CSRF token (skip if already found vulnerable)
        if (! $csrfVulnerable) {
            try {
                $response = $testCase->$method($uri, $data);

                if ($response->status() < 400 && 419 !== $response->status()) {
                    $vulnerabilities[] = [
                        'type'        => 'csrf-bypass',
                        'description' => 'Endpoint accepts requests without CSRF token',
                        'method'      => strtoupper($method),
                        'status_code' => $response->status(),
                    ];
                }
            } catch (Exception $e) {
                // Expected behavior - CSRF validation failed
            }
        }

        // Test 3: Check for SameSite cookie protection
        $sameSite = config('session.same_site', 'lax');
        if ('none' === $sameSite || null === $sameSite) {
            $vulnerabilities[] = [
                'type'          => 'weak-samesite',
                'description'   => 'Session cookie SameSite attribute is not protective',
                'current_value' => $sameSite ?? 'not set',
            ];
        }

        if (! empty($vulnerabilities)) {
            return AttackResult::vulnerable(
                attack: $this->getName(),
                severity: 'high',
                findings: $vulnerabilities,
                metadata: ['uri' => $uri, 'method' => strtoupper($method)],
            );
        }

        return AttackResult::notVulnerable(
            attack: $this->getName(),
            metadata: ['uri' => $uri, 'method' => strtoupper($method)],
        );
    }

    public function getName(): string
    {
        return 'Cross-Site Request Forgery (CSRF)';
    }

    public function getDescription(): string
    {
        return 'Tests for CSRF vulnerabilities by attempting requests without valid tokens';
    }

    public function getOwaspCategory(): string
    {
        return 'A01:2021-Broken Access Control';
    }
}
