<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\PenetrationTesting\Attacks;

use ArtisanPackUI\Security\Testing\PenetrationTesting\AttackInterface;
use ArtisanPackUI\Security\Testing\PenetrationTesting\AttackResult;
use ArtisanPackUI\Security\Testing\PenetrationTesting\Payloads\SqlPayloads;
use Exception;
use PDOException;

class SqlInjectionAttack implements AttackInterface
{
    /**
     * SQL payloads to test.
     *
     * @var array<string>
     */
    protected array $payloads;

    /**
     * Time-based SQL payloads.
     *
     * @var array<string>
     */
    protected array $timeBasedPayloads;

    public function __construct()
    {
        $this->payloads          = SqlPayloads::getErrorBased();
        $this->timeBasedPayloads = SqlPayloads::getTimeBased();
    }

    public function execute(object $testCase, string $uri, array $options = []): AttackResult
    {
        $vulnerabilities = [];
        $method          = $options['method'] ?? 'get';
        $params          = $options['parameters'] ?? [];

        // If no parameters provided, try common parameter names
        if (empty($params)) {
            $params = ['id' => '1', 'search' => 'test', 'q' => 'test', 'query' => 'test'];
        }

        foreach ($params as $paramName => $originalValue) {
            foreach ($this->payloads as $payload) {
                $testParams             = $params;
                $testParams[$paramName] = $payload;

                $startTime = microtime(true);

                try {
                    $response = $testCase->$method($uri, $testParams);
                    $duration = microtime(true) - $startTime;
                    $content  = $response->getContent();

                    // Check for error-based SQLi
                    if ($this->hasDbError($content)) {
                        $vulnerabilities[] = [
                            'type'      => 'error-based',
                            'parameter' => $paramName,
                            'payload'   => $payload,
                            'evidence'  => $this->extractError($content),
                        ];
                    }

                    // Check for time-based SQLi (if payload is time-based)
                    if ($this->isTimeBased($payload) && $duration > 4.5) {
                        $vulnerabilities[] = [
                            'type'      => 'time-based',
                            'parameter' => $paramName,
                            'payload'   => $payload,
                            'duration'  => $duration,
                        ];
                    }
                } catch (Exception $e) {
                    // Database errors might throw exceptions
                    if ($this->isDbException($e)) {
                        $vulnerabilities[] = [
                            'type'      => 'error-based',
                            'parameter' => $paramName,
                            'payload'   => $payload,
                            'evidence'  => $e->getMessage(),
                        ];
                    }
                }
            }
        }

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
            metadata: ['uri' => $uri, 'method' => $method, 'tested_params' => array_keys($params)],
        );
    }

    public function getName(): string
    {
        return 'SQL Injection';
    }

    public function getDescription(): string
    {
        return 'Tests for SQL injection vulnerabilities using error-based and time-based techniques';
    }

    public function getOwaspCategory(): string
    {
        return 'A03:2021-Injection';
    }

    /**
     * Check if response contains database error messages.
     */
    protected function hasDbError(string $content): bool
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
            '/Illuminate\\\\Database\\\\QueryException/i',
            '/ODBC.*Driver/i',
            '/Driver.*SQL/i',
            '/Microsoft.*ODBC/i',
            '/JET Database Engine/i',
        ];

        foreach ($errorPatterns as $pattern) {
            if (preg_match($pattern, $content)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Extract error message from content.
     */
    protected function extractError(string $content): string
    {
        $patterns = [
            '/(?:sql|mysql|postgresql|sqlite|oracle|database).*?error[^<]*/i',
            '/SQLSTATE\[[^\]]+\][^<]*/i',
            '/You have an error in your SQL syntax[^<]*/i',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $content, $matches)) {
                return substr($matches[0], 0, 200);
            }
        }

        return 'Database error detected';
    }

    /**
     * Check if payload is time-based.
     */
    protected function isTimeBased(string $payload): bool
    {
        $timeKeywords = ['SLEEP', 'WAITFOR', 'DELAY', 'pg_sleep', 'BENCHMARK'];

        foreach ($timeKeywords as $keyword) {
            if (false !== stripos($payload, $keyword)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if exception is database-related.
     */
    protected function isDbException(Exception $e): bool
    {
        $dbExceptions = [
            PDOException::class,
            'Illuminate\Database\QueryException',
        ];

        foreach ($dbExceptions as $exceptionClass) {
            if (is_a($e, $exceptionClass, true)) {
                return true;
            }
        }

        // Fallback: check if exception class name contains 'Database'
        if (str_contains(get_class($e), 'Database')) {
            return true;
        }

        return false;
    }
}
