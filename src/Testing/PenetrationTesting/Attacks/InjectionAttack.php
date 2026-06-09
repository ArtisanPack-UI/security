<?php

/**
 * InjectionAttack penetration-test attack.
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

class InjectionAttack implements AttackInterface
{
    public function execute(object $testCase, string $uri, array $options = []): AttackResult
    {
        $vulnerabilities = [];
        $method = $options['method'] ?? 'get';
        $params = $options['parameters'] ?? [];

        // If no parameters provided, try common parameter names
        if (empty($params)) {
            $params = ['cmd' => '', 'command' => '', 'exec' => '', 'input' => '', 'data' => ''];
        }

        // Test command injection
        $this->testCommandInjection($testCase, $uri, $method, $params, $vulnerabilities);

        // Test template injection
        $this->testTemplateInjection($testCase, $uri, $method, $params, $vulnerabilities);

        // Test header injection
        $this->testHeaderInjection($testCase, $uri, $method, $params, $vulnerabilities);

        if (! empty($vulnerabilities)) {
            $severity = $this->determineSeverity($vulnerabilities);

            return AttackResult::vulnerable(
                attack: $this->getName(),
                severity: $severity,
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
        return 'Generic Injection';
    }

    public function getDescription(): string
    {
        return 'Tests for command injection, template injection, and header injection vulnerabilities';
    }

    public function getOwaspCategory(): string
    {
        return 'A03:2021-Injection';
    }

    /**
     * Test for command injection vulnerabilities.
     *
     * @param  array<string, string>  $params
     * @param  array<array<string, mixed>>  $vulnerabilities
     */
    protected function testCommandInjection(
        object $testCase,
        string $uri,
        string $method,
        array $params,
        array &$vulnerabilities,
    ): void {
        $payloads = InjectionPayloads::getCommandInjection();

        foreach ($params as $paramName => $originalValue) {
            foreach ($payloads as $payload) {
                $testParams = $params;
                $testParams[$paramName] = $payload;

                try {
                    $response = $testCase->$method($uri, $testParams);
                    $content = $response->getContent();

                    if ($this->hasCommandOutput($content)) {
                        $vulnerabilities[] = [
                            'type' => 'command-injection',
                            'parameter' => $paramName,
                            'payload' => $payload,
                            'evidence' => $this->extractCommandEvidence($content),
                        ];
                    }
                } catch (Exception $e) {
                    // Expected behavior for blocked commands
                }
            }
        }
    }

    /**
     * Test for template injection vulnerabilities.
     *
     * @param  array<string, string>  $params
     * @param  array<array<string, mixed>>  $vulnerabilities
     */
    protected function testTemplateInjection(
        object $testCase,
        string $uri,
        string $method,
        array $params,
        array &$vulnerabilities,
    ): void {
        $payloads = InjectionPayloads::getTemplateInjection();

        foreach ($params as $paramName => $originalValue) {
            foreach ($payloads as $payload) {
                $testParams = $params;
                $testParams[$paramName] = $payload;

                try {
                    $response = $testCase->$method($uri, $testParams);
                    $content = $response->getContent();

                    // Check if template expression was evaluated
                    if ($this->templateWasEvaluated($payload, $content)) {
                        $vulnerabilities[] = [
                            'type' => 'template-injection',
                            'parameter' => $paramName,
                            'payload' => $payload,
                            'evidence' => $this->extractTemplateEvidence($content, $payload),
                        ];
                    }
                } catch (Exception $e) {
                    // Template parsing errors might indicate injection possibility
                    if ($this->isTemplateException($e)) {
                        $vulnerabilities[] = [
                            'type' => 'template-error',
                            'parameter' => $paramName,
                            'payload' => $payload,
                            'evidence' => $e->getMessage(),
                        ];
                    }
                }
            }
        }
    }

    /**
     * Test for header injection vulnerabilities.
     *
     * @param  array<string, string>  $params
     * @param  array<array<string, mixed>>  $vulnerabilities
     */
    protected function testHeaderInjection(
        object $testCase,
        string $uri,
        string $method,
        array $params,
        array &$vulnerabilities,
    ): void {
        $payloads = InjectionPayloads::getHeaderInjection();

        foreach ($params as $paramName => $originalValue) {
            foreach ($payloads as $payload) {
                $testParams = $params;
                $testParams[$paramName] = $payload;

                try {
                    $response = $testCase->$method($uri, $testParams);

                    // Check if injected headers appear in response
                    if ($response->headers->has('Header') || $response->headers->has('Injected')) {
                        $vulnerabilities[] = [
                            'type' => 'header-injection',
                            'parameter' => $paramName,
                            'payload' => $payload,
                        ];
                    }
                } catch (Exception $e) {
                    // Expected behavior
                }
            }
        }
    }

    /**
     * Check if response contains command execution output.
     */
    protected function hasCommandOutput(string $content): bool
    {
        $indicators = [
            'uid=',                    // id command
            'gid=',                    // id command
            'root:x:0:0:',            // /etc/passwd
            'Linux',                   // uname output
            'Windows',                 // Windows version info
            'Directory of',           // Windows dir command
            'total ',                  // ls -la output
            'drwx',                    // ls output with permissions
            '-rw-',                    // ls output with permissions
        ];

        foreach ($indicators as $indicator) {
            if (str_contains($content, $indicator)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if template expression was evaluated.
     */
    protected function templateWasEvaluated(string $payload, string $content): bool
    {
        // Check if {{7*7}} resulted in 49
        if (str_contains($payload, '7*7') && str_contains($content, '49')) {
            // Make sure 49 wasn't already in a different context
            return true;
        }

        // Check for config dump
        if (str_contains($payload, 'config') && preg_match('/\[.*=>.*\]/', $content)) {
            return true;
        }

        return false;
    }

    /**
     * Check if exception is template-related.
     */
    protected function isTemplateException(Exception $e): bool
    {
        $keywords = ['blade', 'twig', 'smarty', 'template', 'mustache', 'handlebars'];

        $message = strtolower($e->getMessage());

        foreach ($keywords as $keyword) {
            if (str_contains($message, $keyword)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Extract command execution evidence.
     */
    protected function extractCommandEvidence(string $content): string
    {
        if (preg_match('/uid=\d+\([^)]+\)\s*gid=\d+\([^)]+\)/', $content, $matches)) {
            return 'Command output: '.$matches[0];
        }

        if (preg_match('/root:[x*]:\d+:\d+/', $content, $matches)) {
            return 'passwd content: '.$matches[0];
        }

        return 'Command execution indicators detected';
    }

    /**
     * Extract template evaluation evidence.
     */
    protected function extractTemplateEvidence(string $content, string $payload): string
    {
        if (str_contains($payload, '7*7') && str_contains($content, '49')) {
            return 'Mathematical expression {{7*7}} evaluated to 49';
        }

        return 'Template expression evaluated';
    }

    /**
     * Determine overall severity based on findings.
     */
    protected function determineSeverity(array $vulnerabilities): string
    {
        foreach ($vulnerabilities as $vuln) {
            if ($vuln['type'] === 'command-injection') {
                return 'critical';
            }
        }

        return 'high';
    }
}
