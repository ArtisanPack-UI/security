<?php

/**
 * TestsCryptography testing trait.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\Traits;

use ArtisanPackUI\Security\Testing\Reporting\SecurityFinding;
use Exception;
use PDO;

trait TestsCryptography
{
    /**
     * Assert that the application key is properly configured.
     */
    protected function assertAppKeyConfigured(): void
    {
        $key = config('app.key');

        if (empty($key)) {
            $this->recordFinding(SecurityFinding::critical(
                'Missing Application Key',
                'APP_KEY is not configured',
                'A02:2021-Cryptographic Failures',
                '.env',
                'Run: php artisan key:generate',
            ));

            $this->fail('APP_KEY is not configured');
        }

        // Check key length (should be 32 bytes for AES-256)
        $keyBytes = base64_decode(str_replace('base64:', '', $key));
        if (strlen($keyBytes) < 32) {
            $this->recordFinding(SecurityFinding::high(
                'Weak Application Key',
                'APP_KEY is shorter than recommended 256 bits',
                'A02:2021-Cryptographic Failures',
                '.env',
                'Regenerate key with: php artisan key:generate',
            ));
        }
    }

    /**
     * Assert that passwords are properly hashed.
     */
    protected function assertPasswordsHashed(): void
    {
        $hashDriver = config('hashing.driver', 'bcrypt');

        $secureDrivers = ['bcrypt', 'argon', 'argon2id'];

        if (! in_array($hashDriver, $secureDrivers)) {
            $this->recordFinding(SecurityFinding::critical(
                'Insecure Password Hashing',
                "Password hashing driver '{$hashDriver}' is not secure",
                'A02:2021-Cryptographic Failures',
                'config/hashing.php',
                'Use bcrypt, argon, or argon2id for password hashing',
            ));
        }

        // Check bcrypt cost factor
        if ($hashDriver === 'bcrypt') {
            $rounds = config('hashing.bcrypt.rounds', 10);
            if ($rounds < 10) {
                $this->recordFinding(SecurityFinding::medium(
                    'Low Bcrypt Cost Factor',
                    "Bcrypt rounds ({$rounds}) is below recommended minimum (10)",
                    'A02:2021-Cryptographic Failures',
                    'config/hashing.php',
                    'Increase bcrypt rounds to at least 10',
                ));
            }
        }
    }

    /**
     * Assert that HTTPS is enforced in production.
     */
    protected function assertHttpsEnforced(): void
    {
        if (app()->environment('production')) {
            $appUrl = config('app.url', '');

            if (! str_starts_with($appUrl, 'https://')) {
                $this->recordFinding(SecurityFinding::high(
                    'HTTPS Not Enforced',
                    'Application URL does not use HTTPS in production',
                    'A02:2021-Cryptographic Failures',
                    '.env',
                    'Set APP_URL to use https:// in production',
                ));
            }
        }
    }

    /**
     * Assert that sensitive data is encrypted at rest.
     */
    protected function assertSensitiveDataEncrypted(string $modelClass, array $sensitiveFields): void
    {
        $model = new $modelClass;
        $casts = $model->getCasts();

        foreach ($sensitiveFields as $field) {
            $cast = $casts[$field] ?? null;

            if ($cast !== 'encrypted' && $cast !== 'encrypted:array' && $cast !== 'encrypted:collection') {
                $this->recordFinding(SecurityFinding::medium(
                    'Sensitive Data Not Encrypted',
                    "Field '{$field}' in {$modelClass} is not encrypted at rest",
                    'A02:2021-Cryptographic Failures',
                    $modelClass,
                    "Add '{$field}' => 'encrypted' to the model's \$casts property",
                ));
            }
        }
    }

    /**
     * Test that random number generation is cryptographically secure.
     */
    protected function assertSecureRandomGeneration(): void
    {
        // Test that random_bytes is available
        try {
            $bytes = random_bytes(32);
            $this->assertEquals(32, strlen($bytes));
        } catch (Exception $e) {
            $this->recordFinding(SecurityFinding::critical(
                'Insecure Random Generation',
                'Cryptographically secure random number generation is not available',
                'A02:2021-Cryptographic Failures',
                null,
                'Ensure the system has a proper entropy source',
            ));

            $this->fail('Secure random generation not available');
        }
    }

    /**
     * Assert that database connections use encryption.
     */
    protected function assertDatabaseConnectionEncrypted(): void
    {
        $connections = config('database.connections', []);
        $defaultConnection = config('database.default');

        $connection = $connections[$defaultConnection] ?? [];

        // Check for SSL configuration
        if (in_array($connection['driver'] ?? '', ['mysql', 'pgsql', 'sqlsrv'])) {
            $sslMode = $connection['sslmode'] ?? $connection['options'][PDO::MYSQL_ATTR_SSL_CA] ?? null;

            if (app()->environment('production') && ! $sslMode) {
                $this->recordFinding(SecurityFinding::medium(
                    'Database Connection Not Encrypted',
                    "Database connection '{$defaultConnection}' may not be using SSL/TLS",
                    'A02:2021-Cryptographic Failures',
                    'config/database.php',
                    'Configure SSL for database connections in production',
                ));
            }
        }
    }

    /**
     * Assert that no weak ciphers are configured.
     */
    protected function assertNoWeakCiphers(): void
    {
        $cipher = config('app.cipher', 'AES-256-CBC');

        $weakCiphers = ['DES', 'RC4', 'MD5', 'SHA1'];

        foreach ($weakCiphers as $weak) {
            if (stripos($cipher, $weak) !== false) {
                $this->recordFinding(SecurityFinding::critical(
                    'Weak Cipher Configured',
                    "Cipher '{$cipher}' contains weak algorithm",
                    'A02:2021-Cryptographic Failures',
                    'config/app.php',
                    'Use AES-256-CBC or AES-256-GCM',
                ));

                $this->fail("Weak cipher configured: {$cipher}");
            }
        }
    }

    /**
     * Test that tokens have sufficient entropy.
     */
    protected function assertTokenEntropy(string $token, int $minBits = 128): void
    {
        $bytes = strlen($token);

        // Assume hex encoding (4 bits per char) or base64 (6 bits per char)
        $estimatedBits = preg_match('/^[a-f0-9]+$/i', $token)
            ? $bytes * 4  // Hex
            : $bytes * 6; // Base64-ish

        if ($estimatedBits < $minBits) {
            $this->recordFinding(SecurityFinding::medium(
                'Insufficient Token Entropy',
                "Token has approximately {$estimatedBits} bits of entropy, minimum {$minBits} recommended",
                'A02:2021-Cryptographic Failures',
                'Token Generation',
                'Use longer tokens with cryptographically secure random generation',
            ));
        }

        $this->assertGreaterThanOrEqual(
            $minBits,
            $estimatedBits,
            "Token should have at least {$minBits} bits of entropy",
        );
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
     * Assert that two values are equal.
     * This method must be implemented by the class using this trait.
     */
    abstract protected function assertEquals(mixed $expected, mixed $actual, string $message = ''): void;

    /**
     * Assert that a value is greater than or equal to another.
     * This method must be implemented by the class using this trait.
     */
    abstract protected function assertGreaterThanOrEqual(mixed $expected, mixed $actual, string $message = ''): void;
}
