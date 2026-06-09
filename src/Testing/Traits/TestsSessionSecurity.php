<?php

/**
 * TestsSessionSecurity testing trait.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\Traits;

use ArtisanPackUI\Security\Testing\Reporting\SecurityFinding;
use Countable;

trait TestsSessionSecurity
{
    /**
     * Assert that session cookies have secure flags.
     */
    protected function assertSecureSessionCookies(): void
    {
        $sessionConfig = config('session');

        if (! ($sessionConfig['secure'] ?? false) && app()->environment('production')) {
            $this->recordFinding(SecurityFinding::high(
                'Session Cookie Not Secure',
                'Session cookie does not have the Secure flag enabled in production',
                'A02:2021-Cryptographic Failures',
                'config/session.php',
                'Set SESSION_SECURE_COOKIE=true in production',
            ));
        }

        if (! ($sessionConfig['http_only'] ?? true)) {
            $this->recordFinding(SecurityFinding::medium(
                'Session Cookie Missing HttpOnly',
                'Session cookie does not have the HttpOnly flag',
                'A02:2021-Cryptographic Failures',
                'config/session.php',
                'Ensure session.http_only is set to true',
            ));
        }

        $sameSite = $sessionConfig['same_site'] ?? null;
        if ($sameSite === null || $sameSite === 'none') {
            $this->recordFinding(SecurityFinding::medium(
                'Session Cookie SameSite Not Strict',
                'Session cookie SameSite attribute is not set to Strict or Lax',
                'A01:2021-Broken Access Control',
                'config/session.php',
                'Set SESSION_SAME_SITE=lax or SESSION_SAME_SITE=strict',
            ));
        }
    }

    /**
     * Assert that session timeout is configured.
     */
    protected function assertSessionTimeout(int $maxLifetimeMinutes = 120): void
    {
        $lifetime = config('session.lifetime', 120);

        if ($lifetime > $maxLifetimeMinutes) {
            $this->recordFinding(SecurityFinding::low(
                'Long Session Lifetime',
                "Session lifetime ({$lifetime} minutes) exceeds recommended maximum ({$maxLifetimeMinutes} minutes)",
                'A07:2021-Identification and Authentication Failures',
                'config/session.php',
                "Consider reducing session lifetime to {$maxLifetimeMinutes} minutes or less",
            ));
        }
    }

    /**
     * Assert that session ID is regenerated on privilege change.
     */
    protected function assertSessionRegeneratedOnPrivilegeChange(callable $privilegeChangeAction): void
    {
        $sessionIdBefore = session()->getId();

        $privilegeChangeAction();

        $sessionIdAfter = session()->getId();

        if ($sessionIdBefore === $sessionIdAfter) {
            $this->recordFinding(SecurityFinding::high(
                'Session Fixation Risk',
                'Session ID not regenerated after privilege change',
                'A07:2021-Identification and Authentication Failures',
                remediation: 'Call session()->regenerate() after privilege changes',
            ));
        }

        $this->assertNotEquals(
            $sessionIdBefore,
            $sessionIdAfter,
            'Session ID should be regenerated on privilege change',
        );
    }

    /**
     * Test that session data is properly encrypted.
     */
    protected function assertSessionEncryption(): void
    {
        $driver = config('session.driver');

        // Database and file drivers should use encryption
        if (in_array($driver, ['database', 'file'])) {
            $encrypt = config('session.encrypt', false);

            if (! $encrypt) {
                $this->recordFinding(SecurityFinding::medium(
                    'Session Data Not Encrypted',
                    "Session driver '{$driver}' stores session data without encryption",
                    'A02:2021-Cryptographic Failures',
                    'config/session.php',
                    'Set SESSION_ENCRYPT=true for sensitive applications',
                ));
            }
        }
    }

    /**
     * Assert that concurrent sessions are limited.
     */
    protected function assertConcurrentSessionLimit(): void
    {
        // This is application-specific, provide a hook for custom implementation
        $this->assertTrue(true, 'Override this method to test concurrent session limits');
    }

    /**
     * Test that logout invalidates all session data.
     */
    protected function assertLogoutClearsSession(string $logoutUri): void
    {
        // Store something in session
        session(['test_key' => 'test_value']);

        $this->post($logoutUri);

        $this->assertNull(
            session('test_key'),
            'Session data should be cleared on logout',
        );
    }

    /**
     * Test for session prediction vulnerability.
     */
    protected function assertUnpredictableSessionIds(int $sampleSize = 100): void
    {
        $sessionIds = [];

        for ($i = 0; $i < $sampleSize; $i++) {
            session()->regenerate();
            $sessionIds[] = session()->getId();
        }

        // Check for patterns (very basic check)
        $uniqueIds = array_unique($sessionIds);

        $this->assertCount(
            count($sessionIds),
            $uniqueIds,
            'Session IDs should be unique',
        );

        // Check minimum entropy (session IDs should be at least 128 bits)
        foreach ($sessionIds as $id) {
            $this->assertGreaterThanOrEqual(
                32, // 32 hex chars = 128 bits
                strlen($id),
                'Session ID should have sufficient entropy',
            );
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
    abstract protected function assertNotEquals(mixed $expected, mixed $actual, string $message = ''): void;

    /**
     * Assert that a condition is true.
     * This method must be implemented by the class using this trait.
     */
    abstract protected function assertTrue(mixed $condition, string $message = ''): void;

    /**
     * Assert that a value is null.
     * This method must be implemented by the class using this trait.
     */
    abstract protected function assertNull(mixed $actual, string $message = ''): void;

    /**
     * Assert that an array has a specific count.
     * This method must be implemented by the class using this trait.
     */
    abstract protected function assertCount(int $expectedCount, Countable|iterable $haystack, string $message = ''): void;

    /**
     * Assert that a value is greater than or equal to another.
     * This method must be implemented by the class using this trait.
     */
    abstract protected function assertGreaterThanOrEqual(mixed $expected, mixed $actual, string $message = ''): void;
}
