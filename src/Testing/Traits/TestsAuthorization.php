<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\Traits;

use ArtisanPackUI\Security\Testing\Reporting\SecurityFinding;
use Illuminate\Contracts\Auth\Authenticatable;

trait TestsAuthorization
{
    /**
     * Assert that an endpoint enforces authorization.
     */
    protected function assertEndpointRequiresAuthorization(
        Authenticatable $user,
        string $method,
        string $uri,
        array $data = [],
    ): void {
        $response = $this->actingAs($user)->$method($uri, $data);

        if (403 !== $response->status()) {
            $this->recordFinding(SecurityFinding::high(
                'Missing Authorization Check',
                "User without permission can access {$method} {$uri}",
                'A01:2021-Broken Access Control',
                "{$method} {$uri}",
                'Add proper authorization checks to this endpoint',
            ));
        }

        $this->assertEquals(
            403,
            $response->status(),
            "Expected 403 Forbidden, got {$response->status()}",
        );
    }

    /**
     * Test for Insecure Direct Object Reference (IDOR).
     */
    protected function assertNoIdor(
        Authenticatable $user,
        string $method,
        string $uri,
        string $resourceParam,
        mixed $otherUsersResourceId,
        array $additionalData = [],
    ): void {
        $testUri = str_replace("{{$resourceParam}}", (string) $otherUsersResourceId, $uri);

        $response = $this->actingAs($user)->$method($testUri, $additionalData);

        if (in_array($response->status(), [200, 201, 204])) {
            $this->recordFinding(SecurityFinding::critical(
                'Insecure Direct Object Reference (IDOR)',
                "User can access/modify another user's resource at {$method} {$uri}",
                'A01:2021-Broken Access Control',
                "{$method} {$uri}",
                'Verify that the authenticated user owns or has permission to access the requested resource',
            ));
        }

        $this->assertTrue(
            in_array($response->status(), [403, 404]),
            "Expected 403 or 404, got {$response->status()} for IDOR test",
        );
    }

    /**
     * Assert that privilege escalation is not possible.
     */
    protected function assertNoPrivilegeEscalation(
        Authenticatable $regularUser,
        string $method,
        string $adminUri,
        array $data = [],
    ): void {
        $response = $this->actingAs($regularUser)->$method($adminUri, $data);

        if (in_array($response->status(), [200, 201, 204])) {
            $this->recordFinding(SecurityFinding::critical(
                'Privilege Escalation',
                "Regular user can access admin endpoint {$method} {$adminUri}",
                'A01:2021-Broken Access Control',
                "{$method} {$adminUri}",
                'Implement proper role-based access control',
            ));
        }

        $this->assertTrue(
            in_array($response->status(), [401, 403]),
            "Expected 401 or 403 for privilege escalation test, got {$response->status()}",
        );
    }

    /**
     * Assert that horizontal privilege escalation is not possible.
     */
    protected function assertNoHorizontalPrivilegeEscalation(
        Authenticatable $userA,
        Authenticatable $userB,
        string $method,
        string $uri,
        string $resourceParam,
        mixed $userBResourceId,
    ): void {
        $testUri = str_replace("{{$resourceParam}}", (string) $userBResourceId, $uri);

        $response = $this->actingAs($userA)->$method($testUri);

        if (in_array($response->status(), [200, 201, 204])) {
            $this->recordFinding(SecurityFinding::critical(
                'Horizontal Privilege Escalation',
                "User A can access User B's resource at {$method} {$uri}",
                'A01:2021-Broken Access Control',
                "{$method} {$uri}",
                'Ensure users can only access their own resources',
            ));
        }

        $this->assertTrue(
            in_array($response->status(), [403, 404]),
            'Expected 403 or 404 for horizontal privilege escalation test',
        );
    }

    /**
     * Test that role changes require proper authorization.
     */
    protected function assertRoleChangeProtected(
        Authenticatable $user,
        string $uri,
        string $roleField = 'role',
        string $privilegedRole = 'admin',
    ): void {
        $response = $this->actingAs($user)->put($uri, [
            $roleField => $privilegedRole,
        ]);

        // Check if the role was actually changed
        // Use fresh() for Eloquent models, or re-fetch for non-Eloquent
        if (method_exists($user, 'fresh')) {
            $freshUser = $user->fresh();
        } elseif (method_exists($user, 'refresh')) {
            $user->refresh();
            $freshUser = $user;
        } else {
            // For non-Eloquent implementations, we cannot verify the change
            // but we can check the response status
            if (200 === $response->status() || 204 === $response->status()) {
                $this->recordFinding(SecurityFinding::medium(
                    'Potential Mass Assignment - Role Escalation',
                    "Role change request accepted (status {$response->status()}). Manual verification needed.",
                    'A01:2021-Broken Access Control',
                    $uri,
                    'Protect role field from mass assignment and add authorization checks',
                ));
            }

            return;
        }

        $currentRole = $freshUser->{$roleField} ?? $freshUser->role ?? null;

        if ($currentRole === $privilegedRole) {
            $this->recordFinding(SecurityFinding::critical(
                'Mass Assignment - Role Escalation',
                "User can change their own role to {$privilegedRole}",
                'A01:2021-Broken Access Control',
                $uri,
                'Protect role field from mass assignment and add authorization checks',
            ));
        }
    }

    /**
     * Assert that the endpoint respects CORS settings.
     */
    protected function assertCorsProtected(string $uri, string $maliciousOrigin = 'https://evil.com'): void
    {
        $response = $this->withHeaders([
            'Origin' => $maliciousOrigin,
        ])->options($uri);

        $allowedOrigin = $response->headers->get('Access-Control-Allow-Origin');

        if ('*' === $allowedOrigin || $allowedOrigin === $maliciousOrigin) {
            $this->recordFinding(SecurityFinding::medium(
                'Permissive CORS Configuration',
                "Endpoint allows requests from {$maliciousOrigin}",
                'A01:2021-Broken Access Control',
                $uri,
                'Configure CORS to only allow trusted origins',
            ));
        }
    }

    /**
     * Record a security finding.
     * This method must be implemented by the class using this trait.
     */
    abstract protected function recordFinding(SecurityFinding $finding): void;

    /**
     * Assert that two values are equal.
     * This method must be implemented by the class using this trait.
     */
    abstract protected function assertEquals(mixed $expected, mixed $actual, string $message = ''): void;

    /**
     * Assert that a condition is true.
     * This method must be implemented by the class using this trait.
     */
    abstract protected function assertTrue(mixed $condition, string $message = ''): void;
}
