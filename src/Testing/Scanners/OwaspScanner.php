<?php

/**
 * OwaspScanner security scanner.
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
use Illuminate\Support\Facades\Route;

/**
 * OWASP Top 10 2021 Scanner.
 *
 * Scans for common security issues based on OWASP Top 10:
 * A01: Broken Access Control
 * A02: Cryptographic Failures
 * A03: Injection
 * A04: Insecure Design
 * A05: Security Misconfiguration
 * A06: Vulnerable and Outdated Components
 * A07: Identification and Authentication Failures
 * A08: Software and Data Integrity Failures
 * A09: Security Logging and Monitoring Failures
 * A10: Server-Side Request Forgery (SSRF)
 */
class OwaspScanner implements ScannerInterface
{
    /**
     * @var array<SecurityFinding>
     */
    protected array $findings = [];

    /**
     * Categories to scan.
     *
     * @var array<string>
     */
    protected array $categories = ['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10'];

    public function __construct(array $categories = [])
    {
        if (! empty($categories)) {
            $this->categories = $categories;
        }
    }

    public function scan(): array
    {
        $this->findings = [];

        foreach ($this->categories as $category) {
            match ($category) {
                'A01'   => $this->scanBrokenAccessControl(),
                'A02'   => $this->scanCryptographicFailures(),
                'A03'   => $this->scanInjection(),
                'A04'   => $this->scanInsecureDesign(),
                'A05'   => $this->scanSecurityMisconfiguration(),
                'A06'   => $this->scanVulnerableComponents(),
                'A07'   => $this->scanAuthenticationFailures(),
                'A08'   => $this->scanIntegrityFailures(),
                'A09'   => $this->scanLoggingFailures(),
                'A10'   => $this->scanSsrf(),
                default => null,
            };
        }

        return $this->findings;
    }

    public function getName(): string
    {
        return 'OWASP Top 10 Scanner';
    }

    public function getDescription(): string
    {
        return 'Scans for vulnerabilities based on OWASP Top 10 2021';
    }

    /**
     * A01:2021 - Broken Access Control
     */
    protected function scanBrokenAccessControl(): void
    {
        // Check for routes without middleware
        $routes = Route::getRoutes();

        foreach ($routes as $route) {
            $middleware = $route->middleware();
            $uri        = $route->uri();

            // Skip API routes that might use token auth
            if (str_starts_with($uri, 'api/')) {
                continue;
            }

            // Check for sensitive routes without auth middleware
            $sensitivePatterns = ['admin', 'dashboard', 'user', 'profile', 'settings', 'account'];

            foreach ($sensitivePatterns as $pattern) {
                if (str_contains($uri, $pattern) && ! $this->hasAuthMiddleware($middleware)) {
                    $this->findings[] = SecurityFinding::high(
                        'Route Without Authentication',
                        "Route '{$uri}' appears to be sensitive but has no authentication middleware",
                        'A01:2021-Broken Access Control',
                        $uri,
                        'Add auth middleware to protect sensitive routes',
                    );
                }
            }
        }

        // Check for CORS misconfiguration
        $corsConfig = config('cors.allowed_origins', []);
        if (in_array('*', $corsConfig)) {
            $this->findings[] = SecurityFinding::medium(
                'Permissive CORS Configuration',
                'CORS allows all origins (*)',
                'A01:2021-Broken Access Control',
                'config/cors.php',
                'Restrict allowed origins to trusted domains',
            );
        }
    }

    /**
     * A02:2021 - Cryptographic Failures
     */
    protected function scanCryptographicFailures(): void
    {
        // Check APP_KEY
        $appKey = config('app.key');
        if (empty($appKey)) {
            $this->findings[] = SecurityFinding::critical(
                'Missing Application Key',
                'APP_KEY is not configured',
                'A02:2021-Cryptographic Failures',
                '.env',
                'Run: php artisan key:generate',
            );
        }

        // Check session security
        if (! config('session.secure') && app()->environment('production')) {
            $this->findings[] = SecurityFinding::high(
                'Session Cookie Not Secure',
                'Session cookie Secure flag is not enabled in production',
                'A02:2021-Cryptographic Failures',
                'config/session.php',
                'Set SESSION_SECURE_COOKIE=true in production',
            );
        }

        // Check password hashing
        $hashDriver = config('hashing.driver', 'bcrypt');
        if ('md5' === $hashDriver || 'sha1' === $hashDriver) {
            $this->findings[] = SecurityFinding::critical(
                'Weak Password Hashing',
                "Password hashing driver '{$hashDriver}' is cryptographically weak",
                'A02:2021-Cryptographic Failures',
                'config/hashing.php',
                'Use bcrypt or argon2id for password hashing',
            );
        }

        // Check for HTTP in production
        $appUrl = config('app.url', '');
        if (app()->environment('production') && str_starts_with($appUrl, 'http://')) {
            $this->findings[] = SecurityFinding::high(
                'HTTP in Production',
                'Application URL uses HTTP instead of HTTPS in production',
                'A02:2021-Cryptographic Failures',
                '.env',
                'Change APP_URL to use https://',
            );
        }
    }

    /**
     * A03:2021 - Injection
     */
    protected function scanInjection(): void
    {
        // Scan for raw SQL queries in codebase
        $this->scanFilesForPatterns([
            '/DB::raw\s*\(\s*["\'].*\$/'     => 'Potential SQL injection via DB::raw with variable',
            '/->whereRaw\s*\(\s*["\'].*\$/'  => 'Potential SQL injection via whereRaw with variable',
            '/->selectRaw\s*\(\s*["\'].*\$/' => 'Potential SQL injection via selectRaw with variable',
            '/eval\s*\(/'                    => 'Use of eval() function',
            '/exec\s*\(.*\$/'                => 'Command execution with variable input',
            '/shell_exec\s*\(.*\$/'          => 'Shell execution with variable input',
            '/system\s*\(.*\$/'              => 'System command with variable input',
            '/passthru\s*\(.*\$/'            => 'Passthru command with variable input',
            '/`.*\$.*`/'                     => 'Backtick shell execution with variable',
        ], 'A03:2021-Injection');
    }

    /**
     * A04:2021 - Insecure Design
     */
    protected function scanInsecureDesign(): void
    {
        // Check for rate limiting configuration
        if (! config('artisanpack.security.rateLimit.enabled', true)) {
            $this->findings[] = SecurityFinding::medium(
                'Rate Limiting Disabled',
                'Rate limiting is not enabled',
                'A04:2021-Insecure Design',
                'config/artisanpack/security.php',
                'Enable rate limiting to prevent abuse',
            );
        }

        // Check for proper error handling in production
        if (app()->environment('production') && config('app.debug', false)) {
            $this->findings[] = SecurityFinding::high(
                'Debug Mode Enabled in Production',
                'APP_DEBUG is true in production environment',
                'A04:2021-Insecure Design',
                '.env',
                'Set APP_DEBUG=false in production',
            );
        }
    }

    /**
     * A05:2021 - Security Misconfiguration
     */
    protected function scanSecurityMisconfiguration(): void
    {
        // Check security headers configuration
        if (! config('artisanpack.security.headers.enabled', true)) {
            $this->findings[] = SecurityFinding::medium(
                'Security Headers Disabled',
                'Security headers middleware is not enabled',
                'A05:2021-Security Misconfiguration',
                'config/artisanpack/security.php',
                'Enable security headers middleware',
            );
        }

        // Check CSP configuration
        if (! config('artisanpack.security.csp.enabled', true)) {
            $this->findings[] = SecurityFinding::medium(
                'CSP Disabled',
                'Content Security Policy is not enabled',
                'A05:2021-Security Misconfiguration',
                'config/artisanpack/security.php',
                'Enable Content Security Policy',
            );
        }

        // Check for default credentials in config
        $this->checkForDefaultCredentials();
    }

    /**
     * A06:2021 - Vulnerable and Outdated Components
     */
    protected function scanVulnerableComponents(): void
    {
        // Defer to DependencyScanner for detailed analysis
        // Just check if composer.lock exists
        if (! File::exists(base_path('composer.lock'))) {
            $this->findings[] = SecurityFinding::info(
                'Missing composer.lock',
                'composer.lock file not found - dependency versions may not be locked',
                'A06:2021-Vulnerable and Outdated Components',
                base_path(),
                'Run composer install to generate composer.lock',
            );
        }
    }

    /**
     * A07:2021 - Identification and Authentication Failures
     */
    protected function scanAuthenticationFailures(): void
    {
        // Check password validation rules
        $passwordRules = config('artisanpack.security.password.rules', []);

        if (empty($passwordRules)) {
            $this->findings[] = SecurityFinding::medium(
                'No Password Policy Configured',
                'Password validation rules are not configured',
                'A07:2021-Identification and Authentication Failures',
                'config/artisanpack/security.php',
                'Configure password policy with minimum length and complexity requirements',
            );
        }

        // Check session configuration
        $sessionLifetime = config('session.lifetime', 120);
        if ($sessionLifetime > 1440) { // More than 24 hours
            $this->findings[] = SecurityFinding::low(
                'Long Session Lifetime',
                "Session lifetime ({$sessionLifetime} minutes) is very long",
                'A07:2021-Identification and Authentication Failures',
                'config/session.php',
                'Consider reducing session lifetime for sensitive applications',
            );
        }
    }

    /**
     * A08:2021 - Software and Data Integrity Failures
     */
    protected function scanIntegrityFailures(): void
    {
        // Check for unverified redirects
        $this->scanFilesForPatterns([
            '/redirect\s*\(\s*\$_GET/'                           => 'Unvalidated redirect from GET parameter',
            '/redirect\s*\(\s*\$_POST/'                          => 'Unvalidated redirect from POST parameter',
            '/redirect\s*\(\s*request\s*\(\s*[\'"].*[\'"]\s*\)/' => 'Potential unvalidated redirect',
        ], 'A08:2021-Software and Data Integrity Failures');

        // Check for unsigned cookies
        if (! config('session.encrypt', false)) {
            $this->findings[] = SecurityFinding::low(
                'Session Not Encrypted',
                'Session data is not encrypted',
                'A08:2021-Software and Data Integrity Failures',
                'config/session.php',
                'Consider enabling session encryption for sensitive data',
            );
        }
    }

    /**
     * A09:2021 - Security Logging and Monitoring Failures
     */
    protected function scanLoggingFailures(): void
    {
        // Check if security event logging is configured
        if (! config('artisanpack.security.eventLogging.enabled', false)) {
            $this->findings[] = SecurityFinding::medium(
                'Security Event Logging Disabled',
                'Security event logging is not enabled',
                'A09:2021-Security Logging and Monitoring Failures',
                'config/artisanpack/security.php',
                'Enable security event logging to track security-relevant events',
            );
        }

        // Check log channel configuration
        $logChannel = config('logging.default');
        if ('null' === $logChannel && app()->environment('production')) {
            $this->findings[] = SecurityFinding::high(
                'Logging Disabled in Production',
                'Log channel is set to null in production',
                'A09:2021-Security Logging and Monitoring Failures',
                'config/logging.php',
                'Configure a proper logging channel for production',
            );
        }
    }

    /**
     * A10:2021 - Server-Side Request Forgery (SSRF)
     */
    protected function scanSsrf(): void
    {
        $this->scanFilesForPatterns([
            '/file_get_contents\s*\(\s*\$/'       => 'Potential SSRF via file_get_contents with variable URL',
            '/curl_setopt.*CURLOPT_URL.*\$/'      => 'Potential SSRF via cURL with variable URL',
            '/Http::get\s*\(\s*\$/'               => 'Potential SSRF via HTTP client with variable URL',
            '/fopen\s*\(\s*[\'"]https?:\/\/.*\$/' => 'Potential SSRF via fopen with variable URL',
        ], 'A10:2021-Server-Side Request Forgery');
    }

    /**
     * Scan PHP files for dangerous patterns.
     *
     * @param  array<string, string>  $patterns
     */
    protected function scanFilesForPatterns(array $patterns, string $category): void
    {
        $appPath = app_path();

        if (! File::isDirectory($appPath)) {
            return;
        }

        $files = File::allFiles($appPath);

        foreach ($files as $file) {
            if ('php' !== $file->getExtension()) {
                continue;
            }

            $content = File::get($file->getPathname());
            $lines   = explode("\n", $content);

            foreach ($patterns as $pattern => $description) {
                foreach ($lines as $lineNumber => $line) {
                    if (preg_match($pattern, $line)) {
                        $this->findings[] = SecurityFinding::medium(
                            'Potential Security Issue',
                            $description,
                            $category,
                            $file->getPathname().':'.($lineNumber + 1),
                            'Review and sanitize user input before use',
                        );
                    }
                }
            }
        }
    }

    /**
     * Check for default credentials in configuration.
     */
    protected function checkForDefaultCredentials(): void
    {
        $defaultPasswords = ['password', 'secret', 'admin', '123456', 'root'];

        $dbPassword = config('database.connections.mysql.password', '');

        foreach ($defaultPasswords as $default) {
            if ($dbPassword === $default) {
                $this->findings[] = SecurityFinding::critical(
                    'Default Database Password',
                    'Database is using a common/default password',
                    'A05:2021-Security Misconfiguration',
                    '.env',
                    'Change the database password to a strong, unique value',
                );
                break;
            }
        }
    }

    /**
     * Check if middleware list contains authentication middleware.
     */
    protected function hasAuthMiddleware(array $middleware): bool
    {
        $authMiddleware = ['auth', 'auth:sanctum', 'auth:api', 'auth.basic', 'verified'];

        foreach ($middleware as $m) {
            if (in_array($m, $authMiddleware) || str_starts_with($m, 'auth:')) {
                return true;
            }
        }

        return false;
    }
}
