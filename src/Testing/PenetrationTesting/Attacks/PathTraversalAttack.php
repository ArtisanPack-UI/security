<?php

/**
 * PathTraversalAttack penetration-test attack.
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
use ArtisanPackUI\Security\Testing\PenetrationTesting\Payloads\InjectionPayloads;
use Exception;

class PathTraversalAttack implements AttackInterface
{
    /**
     * Path traversal payloads.
     *
     * @var array<string>
     */
    protected array $payloads;

    public function __construct()
    {
        $this->payloads = InjectionPayloads::getPathTraversal();
    }

    public function execute(object $testCase, string $uri, array $options = []): AttackResult
    {
        $vulnerabilities = [];
        $method          = $options['method'] ?? 'get';
        $params          = $options['parameters'] ?? [];

        // If no parameters provided, try common file parameter names
        if (empty($params)) {
            $params = ['file' => '', 'path' => '', 'filename' => '', 'doc' => '', 'document' => ''];
        }

        foreach ($params as $paramName => $originalValue) {
            foreach ($this->payloads as $payload) {
                $testParams             = $params;
                $testParams[$paramName] = $payload;

                try {
                    $response = $testCase->$method($uri, $testParams);
                    $content  = $response->getContent();

                    // Check for sensitive file content
                    if ($this->hasSensitiveContent($content)) {
                        $vulnerabilities[] = [
                            'type'      => 'path-traversal',
                            'parameter' => $paramName,
                            'payload'   => $payload,
                            'evidence'  => $this->extractEvidence($content),
                        ];
                    }

                    // Check for error messages indicating path manipulation
                    if ($this->hasPathError($content)) {
                        $vulnerabilities[] = [
                            'type'      => 'path-disclosure',
                            'parameter' => $paramName,
                            'payload'   => $payload,
                            'evidence'  => $this->extractPathError($content),
                        ];
                    }
                } catch (Exception $e) {
                    // Some payloads might cause exceptions
                    if ($this->isPathException($e)) {
                        $vulnerabilities[] = [
                            'type'      => 'path-error',
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
        return 'Path Traversal';
    }

    public function getDescription(): string
    {
        return 'Tests for directory traversal / local file inclusion vulnerabilities';
    }

    public function getOwaspCategory(): string
    {
        return 'A01:2021-Broken Access Control';
    }

    /**
     * Check if content contains sensitive file content.
     */
    protected function hasSensitiveContent(string $content): bool
    {
        $indicators = [
            // Linux /etc/passwd
            'root:x:0:0:',
            'root:*:0:0:',
            'daemon:x:',
            'nobody:x:',

            // Linux /etc/shadow
            'root:$',
            'root:!',

            // Windows files
            '[boot loader]',
            'for 16-bit app support',
            '[extensions]',
            '[mci extensions]',

            // Common config files
            'DB_PASSWORD=',
            'APP_KEY=',
            'AWS_SECRET',
            'MYSQL_PASSWORD',

            // PHP files
            '<?php',

            // SSH keys
            '-----BEGIN RSA PRIVATE KEY-----',
            '-----BEGIN OPENSSH PRIVATE KEY-----',
        ];

        foreach ($indicators as $indicator) {
            if (str_contains($content, $indicator)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check for path-related error messages.
     */
    protected function hasPathError(string $content): bool
    {
        $patterns = [
            '/No such file or directory/i',
            '/failed to open stream/i',
            '/Permission denied/i',
            '/is not within the allowed path/i',
            '/open_basedir restriction/i',
            '/Cannot access file outside of/i',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $content)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Extract evidence of sensitive content.
     */
    protected function extractEvidence(string $content): string
    {
        // Extract a safe snippet showing the vulnerability
        if (preg_match('/root:[x*]:\d+:\d+:[^:]*:[^:]*:[^\n]*/', $content, $matches)) {
            return 'passwd file content: '.$matches[0];
        }

        if (str_contains($content, 'DB_PASSWORD=')) {
            return 'Environment file detected (DB_PASSWORD found)';
        }

        if (str_contains($content, '-----BEGIN')) {
            return 'Private key file detected';
        }

        return 'Sensitive file content detected';
    }

    /**
     * Extract path error message.
     */
    protected function extractPathError(string $content): string
    {
        $patterns = [
            '/(?:No such file or directory|failed to open stream|Permission denied)[^\n]*/i',
            '/open_basedir restriction[^\n]*/i',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $content, $matches)) {
                return substr($matches[0], 0, 200);
            }
        }

        return 'Path error detected';
    }

    /**
     * Check if exception is path-related.
     */
    protected function isPathException(Exception $e): bool
    {
        $message = $e->getMessage();

        $pathKeywords = ['file', 'path', 'directory', 'open_basedir', 'fopen', 'include', 'require'];

        foreach ($pathKeywords as $keyword) {
            if (false !== stripos($message, $keyword)) {
                return true;
            }
        }

        return false;
    }
}
