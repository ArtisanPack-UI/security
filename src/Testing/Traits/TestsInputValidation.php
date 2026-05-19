<?php

/**
 * TestsInputValidation testing trait.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\Traits;

use ArtisanPackUI\Security\Testing\PenetrationTesting\Payloads\InjectionPayloads;
use ArtisanPackUI\Security\Testing\PenetrationTesting\Payloads\SqlPayloads;
use ArtisanPackUI\Security\Testing\PenetrationTesting\Payloads\XssPayloads;
use ArtisanPackUI\Security\Testing\Reporting\SecurityFinding;

trait TestsInputValidation
{
    /**
     * Test endpoint for SQL injection vulnerabilities.
     */
    protected function assertNotVulnerableToSqlInjection(
        string $method,
        string $uri,
        array $parameters,
        string $vulnerableParam,
    ): void {
        $payloads = SqlPayloads::getErrorBased();

        foreach ($payloads as $payload) {
            $testParams                   = $parameters;
            $testParams[$vulnerableParam] = $payload;

            $response = $this->$method($uri, $testParams);
            $content  = $response->getContent();

            if ($this->hasSqlError($content)) {
                $this->recordFinding(SecurityFinding::critical(
                    'SQL Injection Vulnerability',
                    "Parameter '{$vulnerableParam}' is vulnerable to SQL injection",
                    'A03:2021-Injection',
                    "{$method} {$uri}",
                    'Use parameterized queries or an ORM to prevent SQL injection',
                ));

                $this->fail("SQL injection detected in parameter: {$vulnerableParam}");
            }
        }
    }

    /**
     * Test endpoint for XSS vulnerabilities.
     */
    protected function assertNotVulnerableToXss(
        string $method,
        string $uri,
        array $parameters,
        string $vulnerableParam,
    ): void {
        $payloads = XssPayloads::getBasic();

        foreach ($payloads as $payload) {
            $testParams                   = $parameters;
            $testParams[$vulnerableParam] = $payload;

            $response = $this->$method($uri, $testParams);
            $content  = $response->getContent();

            // Check if payload is reflected unescaped
            if ($this->isXssPayloadReflected($content, $payload)) {
                $this->recordFinding(SecurityFinding::high(
                    'Cross-Site Scripting (XSS) Vulnerability',
                    "Parameter '{$vulnerableParam}' reflects unescaped user input",
                    'A03:2021-Injection',
                    "{$method} {$uri}",
                    'Escape all user input before rendering in HTML',
                ));

                $this->fail("XSS vulnerability detected in parameter: {$vulnerableParam}");
            }
        }
    }

    /**
     * Test endpoint for command injection.
     */
    protected function assertNotVulnerableToCommandInjection(
        string $method,
        string $uri,
        array $parameters,
        string $vulnerableParam,
    ): void {
        $payloads = InjectionPayloads::getCommandInjection();

        foreach ($payloads as $payload) {
            $testParams                   = $parameters;
            $testParams[$vulnerableParam] = $payload;

            $response = $this->$method($uri, $testParams);
            $content  = $response->getContent();

            if ($this->hasCommandExecutionIndicator($content)) {
                $this->recordFinding(SecurityFinding::critical(
                    'Command Injection Vulnerability',
                    "Parameter '{$vulnerableParam}' is vulnerable to command injection",
                    'A03:2021-Injection',
                    "{$method} {$uri}",
                    'Never pass user input directly to shell commands. Use escapeshellarg() or avoid shell commands entirely.',
                ));

                $this->fail("Command injection detected in parameter: {$vulnerableParam}");
            }
        }
    }

    /**
     * Test for path traversal vulnerabilities.
     */
    protected function assertNotVulnerableToPathTraversal(
        string $method,
        string $uri,
        array $parameters,
        string $vulnerableParam,
    ): void {
        $payloads = [
            '../../../etc/passwd',
            '....//....//....//etc/passwd',
            '..%2f..%2f..%2fetc/passwd',
            '..%252f..%252f..%252fetc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            '....\\\\....\\\\....\\\\windows\\system32\\config\\sam',
        ];

        foreach ($payloads as $payload) {
            $testParams                   = $parameters;
            $testParams[$vulnerableParam] = $payload;

            $response = $this->$method($uri, $testParams);
            $content  = $response->getContent();

            if ($this->hasSensitiveFileContent($content)) {
                $this->recordFinding(SecurityFinding::critical(
                    'Path Traversal Vulnerability',
                    "Parameter '{$vulnerableParam}' allows path traversal",
                    'A01:2021-Broken Access Control',
                    "{$method} {$uri}",
                    'Validate and sanitize file paths. Use a whitelist of allowed files or directories.',
                ));

                $this->fail("Path traversal detected in parameter: {$vulnerableParam}");
            }
        }
    }

    /**
     * Test for LDAP injection.
     */
    protected function assertNotVulnerableToLdapInjection(
        string $method,
        string $uri,
        array $parameters,
        string $vulnerableParam,
    ): void {
        $payloads           = InjectionPayloads::getLdapInjection();
        $vulnerabilityFound = false;

        foreach ($payloads as $payload) {
            $testParams                   = $parameters;
            $testParams[$vulnerableParam] = $payload;

            $response = $this->$method($uri, $testParams);

            // LDAP injection might result in unexpected success or error patterns
            // Check for wildcard injection (returns all results)
            if (200 === $response->status() && str_contains($payload, '*')) {
                $this->recordFinding(SecurityFinding::high(
                    'Potential LDAP Injection',
                    "Parameter '{$vulnerableParam}' may be vulnerable to LDAP injection with wildcard payload",
                    'A03:2021-Injection',
                    "{$method} {$uri}",
                    'Escape special LDAP characters in user input',
                ));
                $vulnerabilityFound = true;
                break;
            }

            // Check for LDAP error disclosure in response
            $content = $response->getContent();
            if ($this->hasLdapError($content)) {
                $this->recordFinding(SecurityFinding::high(
                    'LDAP Injection Vulnerability',
                    "Parameter '{$vulnerableParam}' causes LDAP errors, indicating potential injection",
                    'A03:2021-Injection',
                    "{$method} {$uri}",
                    'Escape special LDAP characters in user input',
                ));
                $vulnerabilityFound = true;
                break;
            }
        }

        if ($vulnerabilityFound) {
            $this->fail("LDAP injection detected in parameter: {$vulnerableParam}");
        }
    }

    /**
     * Check if response contains LDAP error messages.
     */
    protected function hasLdapError(string $content): bool
    {
        $errorPatterns = [
            '/ldap_/i',
            '/invalid dn/i',
            '/bad filter/i',
            '/LDAP error/i',
            '/ldap_search/i',
            '/ldap_bind/i',
        ];

        foreach ($errorPatterns as $pattern) {
            if (preg_match($pattern, $content)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if response contains SQL error messages.
     */
    protected function hasSqlError(string $content): bool
    {
        $errorPatterns = [
            '/sql syntax/i',
            '/mysql_fetch/i',
            '/ORA-\d+/i',
            '/PostgreSQL.*ERROR/i',
            '/SQLite3::query/i',
            '/SQLSTATE\[/i',
            '/Unclosed quotation mark/i',
            '/quoted string not properly terminated/i',
            '/You have an error in your SQL syntax/i',
            '/Warning.*mysql/i',
            '/PDOException/i',
            '/QueryException/i',
        ];

        foreach ($errorPatterns as $pattern) {
            if (preg_match($pattern, $content)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if XSS payload is reflected unescaped.
     */
    protected function isXssPayloadReflected(string $content, string $payload): bool
    {
        // Check for exact payload match (unescaped)
        if (! str_contains($content, $payload)) {
            return false;
        }

        // The payload is present in the response - check if it's properly escaped
        $escapedPayload = htmlspecialchars($payload, ENT_QUOTES, 'UTF-8');

        // If the escaped version is present, we need to check if the unescaped version
        // appears separately (not as part of the escaped version)
        if (str_contains($content, $escapedPayload)) {
            // Remove all escaped occurrences and check if unescaped still exists
            $contentWithoutEscaped = str_replace($escapedPayload, '', $content);

            return str_contains($contentWithoutEscaped, $payload);
        }

        // Payload is present but not escaped - this is a vulnerability
        return true;
    }

    /**
     * Check for command execution indicators.
     */
    protected function hasCommandExecutionIndicator(string $content): bool
    {
        $indicators = [
            'root:x:0:0:',           // /etc/passwd content
            'uid=',                   // id command output
            'gid=',                   // id command output
            'Windows IP Configuration', // ipconfig output
            'COMSPEC',                // Windows environment
            '/bin/bash',              // Shell path
            'Directory of',           // Windows dir command
        ];

        foreach ($indicators as $indicator) {
            if (str_contains($content, $indicator)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check for sensitive file content.
     */
    protected function hasSensitiveFileContent(string $content): bool
    {
        $indicators = [
            'root:x:0:0:',                    // /etc/passwd
            'root:*:',                        // /etc/shadow pattern
            '[boot loader]',                   // Windows boot.ini
            'for 16-bit app support',         // Windows system.ini
            '[extensions]',                    // Windows win.ini
            'SAM',                            // Windows SAM header
        ];

        foreach ($indicators as $indicator) {
            if (str_contains($content, $indicator)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Assert that input validation rejects malformed data.
     */
    protected function assertValidationRejects(
        string $method,
        string $uri,
        array $invalidData,
        string $expectedField,
    ): void {
        $response = $this->$method($uri, $invalidData);

        $this->assertTrue(
            422 === $response->status() || 400 === $response->status(),
            "Expected validation error (422/400) for invalid input, got {$response->status()}",
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
     * Assert that a condition is true.
     * This method must be implemented by the class using this trait.
     */
    abstract protected function assertTrue(mixed $condition, string $message = ''): void;
}
