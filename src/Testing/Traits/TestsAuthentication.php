<?php

/**
 * TestsAuthentication testing trait.
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

trait TestsAuthentication
{
    /**
     * Assert that an endpoint enforces authentication.
     */
    protected function assertEndpointRequiresAuth(string $method, string $uri, array $data = []): void
    {
        $response = $this->$method($uri, $data);

        $validStatuses = [401, 403, 302, 303];

        if (! in_array($response->status(), $validStatuses)) {
            $this->recordFinding(SecurityFinding::high(
                'Missing Authentication',
                "Endpoint {$method} {$uri} does not require authentication",
                'A07:2021-Identification and Authentication Failures',
                "{$method} {$uri}",
                'Add authentication middleware to this route',
            ));
        }

        $this->assertTrue(
            in_array($response->status(), $validStatuses),
            "Expected authentication required, got status {$response->status()}",
        );
    }

    /**
     * Assert that password reset tokens are properly validated.
     */
    protected function assertPasswordResetTokenValidation(string $uri): void
    {
        // Test with invalid token
        $response = $this->post($uri, [
            'token'                 => 'invalid-token',
            'email'                 => 'test@example.com',
            'password'              => 'NewPassword123!',
            'password_confirmation' => 'NewPassword123!',
        ]);

        if (200 === $response->status()) {
            $this->recordFinding(SecurityFinding::critical(
                'Password Reset Token Not Validated',
                'Password reset endpoint accepts invalid tokens',
                'A07:2021-Identification and Authentication Failures',
                $uri,
                'Validate password reset tokens before allowing password changes',
            ));
        }

        $this->assertNotEquals(200, $response->status());
    }

    /**
     * Assert that the session is regenerated after login.
     */
    protected function assertSessionRegeneratedOnLogin(string $loginUri, array $credentials): void
    {
        $sessionIdBefore = session()->getId();

        $this->post($loginUri, $credentials);

        $sessionIdAfter = session()->getId();

        if ($sessionIdBefore === $sessionIdAfter) {
            $this->recordFinding(SecurityFinding::high(
                'Session Fixation Vulnerability',
                'Session ID not regenerated after login',
                'A07:2021-Identification and Authentication Failures',
                $loginUri,
                'Regenerate session ID after successful authentication',
            ));
        }

        $this->assertNotEquals(
            $sessionIdBefore,
            $sessionIdAfter,
            'Session should be regenerated after login',
        );
    }

    /**
     * Test for user enumeration through different error messages.
     */
    protected function assertNoUserEnumeration(string $loginUri, string $emailField = 'email', string $passwordField = 'password'): void
    {
        // Test with invalid user
        $invalidUserResponse = $this->post($loginUri, [
            $emailField    => 'nonexistent@example.com',
            $passwordField => 'SomePassword123!',
        ]);

        // Test with valid user but wrong password (requires a real user in test)
        $invalidPasswordResponse = $this->post($loginUri, [
            $emailField    => 'test@example.com',
            $passwordField => 'WrongPassword123!',
        ]);

        // Both should return the same error structure
        $invalidUserErrors     = $invalidUserResponse->json('errors') ?? $invalidUserResponse->json('message');
        $invalidPasswordErrors = $invalidPasswordResponse->json('errors') ?? $invalidPasswordResponse->json('message');

        // Check if error messages are the same (preventing enumeration)
        if ($invalidUserErrors !== $invalidPasswordErrors) {
            $this->recordFinding(SecurityFinding::medium(
                'User Enumeration Possible',
                'Different error messages for invalid user vs invalid password allow user enumeration',
                'A07:2021-Identification and Authentication Failures',
                $loginUri,
                'Use generic error messages like "Invalid credentials" for all authentication failures',
            ));

            $this->fail(
                "User enumeration vulnerability detected at {$loginUri}: ".
                'Different error responses for invalid user vs invalid password.',
            );
        }
    }

    /**
     * Assert that the logout properly invalidates the session.
     */
    protected function assertLogoutInvalidatesSession(string $logoutUri): void
    {
        $sessionIdBefore = session()->getId();

        $this->post($logoutUri);

        // Get session ID after logout
        $sessionIdAfter = session()->getId();

        // Session should be invalidated - verify both authentication and session state
        $this->assertGuest();

        // Verify session ID was regenerated or invalidated
        $this->assertNotEquals(
            $sessionIdBefore,
            $sessionIdAfter,
            'Session ID should be regenerated or invalidated on logout',
        );
    }

    /**
     * Test for brute force protection.
     */
    protected function assertBruteForceProtection(
        string $loginUri,
        array $credentials,
        int $maxAttempts = 5,
    ): TestResponse {
        $lastResponse = null;

        for ($i = 0; $i < $maxAttempts + 2; $i++) {
            $lastResponse = $this->post($loginUri, $credentials);

            if (429 === $lastResponse->status()) {
                return $lastResponse;
            }
        }

        $this->recordFinding(SecurityFinding::high(
            'Missing Brute Force Protection',
            'Login endpoint allows unlimited attempts without rate limiting',
            'A07:2021-Identification and Authentication Failures',
            $loginUri,
            'Implement rate limiting or account lockout after failed attempts',
        ));

        $this->fail("Expected rate limiting after {$maxAttempts} attempts");
    }

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
     * Assert that the current user is a guest.
     * This method must be implemented by the class using this trait.
     */
    abstract protected function assertGuest(?string $guard = null): static;

    /**
     * Assert that two values are equal.
     * This method must be implemented by the class using this trait.
     */
    abstract protected function assertEquals(mixed $expected, mixed $actual, string $message = ''): void;

    /**
     * Assert that two values are not equal.
     * This method must be implemented by the class using this trait.
     */
    abstract protected function assertNotEquals(mixed $expected, mixed $actual, string $message = ''): void;

    /**
     * Assert that a condition is true.
     * This method must be implemented by the class using this trait.
     */
    abstract protected function assertTrue(mixed $condition, string $message = ''): void;
}
