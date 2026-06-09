<?php

/**
 * ConfigurationScanner security scanner.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\Scanners;

use ArtisanPackUI\Security\Testing\Reporting\SecurityFinding;
use Illuminate\Support\Facades\File;
use PDO;

class ConfigurationScanner implements ScannerInterface
{
    /**
     * @var array<SecurityFinding>
     */
    protected array $findings = [];

    public function scan(): array
    {
        $this->findings = [];

        $this->scanEnvironmentConfig();
        $this->scanDatabaseConfig();
        $this->scanSessionConfig();
        $this->scanCacheConfig();
        $this->scanMailConfig();
        $this->scanFilesystemConfig();
        $this->scanSecurityConfig();
        $this->scanEnvFile();

        return $this->findings;
    }

    public function getName(): string
    {
        return 'Configuration Scanner';
    }

    public function getDescription(): string
    {
        return 'Scans Laravel configuration for security issues';
    }

    /**
     * Scan environment configuration.
     */
    protected function scanEnvironmentConfig(): void
    {
        // Debug mode in production
        if (app()->environment('production') && config('app.debug', false)) {
            $this->findings[] = SecurityFinding::critical(
                'Debug Mode in Production',
                'APP_DEBUG is enabled in production environment',
                'A05:2021-Security Misconfiguration',
                '.env',
                'Set APP_DEBUG=false in production',
            );
        }

        // App key check
        $appKey = config('app.key');
        if (empty($appKey)) {
            $this->findings[] = SecurityFinding::critical(
                'Missing Application Key',
                'APP_KEY is not set',
                'A02:2021-Cryptographic Failures',
                '.env',
                'Run: php artisan key:generate',
            );
        }

        // Check for non-production environment name in production-like URLs
        $appUrl = config('app.url', '');
        $appEnv = config('app.env', 'production');
        $isProductionUrl = str_contains($appUrl, 'prod') ||
                           str_contains($appUrl, '.com') ||
                           str_contains($appUrl, '.io') ||
                           str_contains($appUrl, '.org');

        if (in_array($appEnv, ['local', 'development', 'dev']) && $isProductionUrl) {
            $this->findings[] = SecurityFinding::medium(
                'Environment Mismatch',
                "APP_ENV is '{$appEnv}' but URL suggests production environment",
                'A05:2021-Security Misconfiguration',
                '.env',
                'Ensure APP_ENV matches the actual environment',
            );
        }
    }

    /**
     * Scan database configuration.
     */
    protected function scanDatabaseConfig(): void
    {
        $connection = config('database.default');
        $dbConfig = config("database.connections.{$connection}", []);

        // Check for default/empty passwords
        $password = $dbConfig['password'] ?? '';
        if (empty($password) && app()->environment('production')) {
            $this->findings[] = SecurityFinding::high(
                'Empty Database Password',
                'Database password is empty in production',
                'A07:2021-Identification and Authentication Failures',
                '.env',
                'Set a strong database password',
            );
        }

        // Check for common weak passwords
        $weakPasswords = ['password', 'secret', '123456', 'admin', 'root', 'mysql'];
        if (in_array($password, $weakPasswords)) {
            $this->findings[] = SecurityFinding::critical(
                'Weak Database Password',
                'Database is using a common/weak password',
                'A07:2021-Identification and Authentication Failures',
                '.env',
                'Use a strong, unique database password',
            );
        }

        // Check for SSL in production
        if (app()->environment('production')) {
            $driver = $dbConfig['driver'] ?? '';
            $sslEnabled = false;

            if ($driver === 'mysql') {
                $sslEnabled = isset($dbConfig['options'][PDO::MYSQL_ATTR_SSL_CA]);
            } elseif ($driver === 'pgsql') {
                $sslEnabled = ($dbConfig['sslmode'] ?? 'prefer') === 'require';
            }

            if (! $sslEnabled) {
                $this->findings[] = SecurityFinding::medium(
                    'Database SSL Not Configured',
                    'Database connection may not be using SSL/TLS',
                    'A02:2021-Cryptographic Failures',
                    'config/database.php',
                    'Configure SSL for database connections in production',
                );
            }
        }
    }

    /**
     * Scan session configuration.
     */
    protected function scanSessionConfig(): void
    {
        // Secure cookie in production
        if (app()->environment('production') && ! config('session.secure', false)) {
            $this->findings[] = SecurityFinding::high(
                'Session Cookie Not Secure',
                'Session cookie Secure flag is not enabled',
                'A02:2021-Cryptographic Failures',
                '.env',
                'Set SESSION_SECURE_COOKIE=true',
            );
        }

        // HTTP only flag
        if (! config('session.http_only', true)) {
            $this->findings[] = SecurityFinding::medium(
                'Session Cookie HttpOnly Disabled',
                'Session cookie HttpOnly flag is disabled',
                'A05:2021-Security Misconfiguration',
                'config/session.php',
                'Set http_only to true',
            );
        }

        // SameSite attribute
        $sameSite = config('session.same_site', 'lax');
        if ($sameSite === 'none' || $sameSite === null) {
            $this->findings[] = SecurityFinding::medium(
                'Weak SameSite Cookie Attribute',
                "Session cookie SameSite is set to '{$sameSite}'",
                'A01:2021-Broken Access Control',
                'config/session.php',
                'Set same_site to "lax" or "strict"',
            );
        }

        // Session lifetime
        $lifetime = config('session.lifetime', 120);
        if ($lifetime > 1440) {
            $this->findings[] = SecurityFinding::low(
                'Long Session Lifetime',
                "Session lifetime ({$lifetime} minutes) exceeds 24 hours",
                'A07:2021-Identification and Authentication Failures',
                'config/session.php',
                'Consider reducing session lifetime',
            );
        }

        // Session driver
        $driver = config('session.driver', 'file');
        if ($driver === 'cookie') {
            $this->findings[] = SecurityFinding::medium(
                'Cookie Session Driver',
                'Using cookie driver exposes session data to clients',
                'A02:2021-Cryptographic Failures',
                'config/session.php',
                'Use file, database, or redis session driver',
            );
        }
    }

    /**
     * Scan cache configuration.
     */
    protected function scanCacheConfig(): void
    {
        $cacheDriver = config('cache.default', 'file');

        // File cache in shared hosting
        if ($cacheDriver === 'file') {
            $cachePath = config('cache.stores.file.path', storage_path('framework/cache'));

            if (! File::exists($cachePath)) {
                return;
            }

            // Check permissions (should not be world-readable)
            $perms = fileperms($cachePath);
            if ($perms !== false && ($perms & 0x0004)) {
                $this->findings[] = SecurityFinding::low(
                    'Cache Directory World-Readable',
                    'Cache directory may be accessible to other users',
                    'A05:2021-Security Misconfiguration',
                    $cachePath,
                    'Set restrictive permissions on cache directory',
                );
            }
        }
    }

    /**
     * Scan mail configuration.
     */
    protected function scanMailConfig(): void
    {
        $mailer = config('mail.default', 'smtp');
        $mailerConfig = config("mail.mailers.{$mailer}", []);

        // Check for unencrypted SMTP
        if ($mailer === 'smtp') {
            $encryption = $mailerConfig['encryption'] ?? null;

            if (app()->environment('production') && ! in_array($encryption, ['tls', 'ssl'])) {
                $this->findings[] = SecurityFinding::medium(
                    'SMTP Without Encryption',
                    'SMTP mail transport is not using TLS/SSL',
                    'A02:2021-Cryptographic Failures',
                    'config/mail.php',
                    'Set MAIL_ENCRYPTION=tls',
                );
            }
        }
    }

    /**
     * Scan filesystem configuration.
     */
    protected function scanFilesystemConfig(): void
    {
        $defaultDisk = config('filesystems.default', 'local');
        $disks = config('filesystems.disks', []);

        foreach ($disks as $name => $disk) {
            // Check for public visibility on sensitive disks
            if (($disk['visibility'] ?? 'private') === 'public' && $name !== 'public') {
                $this->findings[] = SecurityFinding::medium(
                    'Public Disk Visibility',
                    "Disk '{$name}' has public visibility by default",
                    'A01:2021-Broken Access Control',
                    'config/filesystems.php',
                    "Set visibility to 'private' for disk '{$name}'",
                );
            }

            // Check S3 bucket ACL
            if (($disk['driver'] ?? '') === 's3' && ($disk['visibility'] ?? '') === 'public') {
                $this->findings[] = SecurityFinding::medium(
                    'Public S3 Bucket',
                    "S3 disk '{$name}' has public visibility",
                    'A01:2021-Broken Access Control',
                    'config/filesystems.php',
                    'Review S3 bucket permissions',
                );
            }
        }
    }

    /**
     * Scan security-specific configuration.
     */
    protected function scanSecurityConfig(): void
    {
        // Check if our security package config exists
        if (! config('artisanpack.security')) {
            return;
        }

        // Rate limiting
        if (! config('artisanpack.security.rateLimit.enabled', true)) {
            $this->findings[] = SecurityFinding::medium(
                'Rate Limiting Disabled',
                'Rate limiting is disabled in security config',
                'A04:2021-Insecure Design',
                'config/artisanpack/security.php',
                'Enable rate limiting',
            );
        }

        // Security headers
        if (! config('artisanpack.security.headers.enabled', true)) {
            $this->findings[] = SecurityFinding::medium(
                'Security Headers Disabled',
                'Security headers are disabled',
                'A05:2021-Security Misconfiguration',
                'config/artisanpack/security.php',
                'Enable security headers',
            );
        }

        // Password policy
        $passwordConfig = config('artisanpack.security.password', []);
        if (($passwordConfig['minLength'] ?? 8) < 8) {
            $this->findings[] = SecurityFinding::medium(
                'Weak Minimum Password Length',
                'Minimum password length is less than 8 characters',
                'A07:2021-Identification and Authentication Failures',
                'config/artisanpack/security.php',
                'Set minimum password length to at least 8',
            );
        }
    }

    /**
     * Scan .env file for sensitive data exposure.
     */
    protected function scanEnvFile(): void
    {
        $envPath = base_path('.env');

        if (! File::exists($envPath)) {
            return;
        }

        // Check .env file permissions
        $perms = fileperms($envPath);
        if ($perms !== false && ($perms & 0x0004)) {
            $this->findings[] = SecurityFinding::high(
                '.env File World-Readable',
                '.env file may be readable by other system users',
                'A05:2021-Security Misconfiguration',
                $envPath,
                'Set .env file permissions to 600',
            );
        }

        // Check if .env is in public directory (major issue)
        $publicEnv = public_path('.env');
        if (File::exists($publicEnv)) {
            $this->findings[] = SecurityFinding::critical(
                '.env File in Public Directory',
                '.env file exists in public directory and may be web-accessible',
                'A05:2021-Security Misconfiguration',
                $publicEnv,
                'Remove .env from public directory immediately',
            );
        }

        // Check .env.example for sensitive values
        $envExamplePath = base_path('.env.example');
        if (File::exists($envExamplePath)) {
            $content = File::get($envExamplePath);

            // Check for real credentials in example file
            if (preg_match('/password\s*=\s*["\']?(?!your|example|secret|null|empty)[a-zA-Z0-9]+/i', $content)) {
                $this->findings[] = SecurityFinding::medium(
                    'Credentials in .env.example',
                    '.env.example may contain real credentials',
                    'A05:2021-Security Misconfiguration',
                    $envExamplePath,
                    'Remove real credentials from .env.example',
                );
            }
        }
    }
}
