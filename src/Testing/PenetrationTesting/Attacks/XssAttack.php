<?php

/**
 * XssAttack penetration-test attack.
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
use ArtisanPackUI\Security\Testing\PenetrationTesting\Payloads\XssPayloads;
use Exception;

class XssAttack implements AttackInterface
{
    /**
     * XSS payloads to test.
     *
     * @var array<string>
     */
    protected array $payloads;

    public function __construct()
    {
        $this->payloads = array_merge(
            XssPayloads::getBasic(),
            XssPayloads::getEventHandlers(),
        );
    }

    public function execute(object $testCase, string $uri, array $options = []): AttackResult
    {
        $vulnerabilities = [];
        $method          = $options['method'] ?? 'get';
        $params          = $options['parameters'] ?? [];

        // If no parameters provided, try common parameter names
        if (empty($params)) {
            $params = ['search' => 'test', 'q' => 'test', 'name' => 'test', 'message' => 'test'];
        }

        foreach ($params as $paramName => $originalValue) {
            foreach ($this->payloads as $payload) {
                $testParams             = $params;
                $testParams[$paramName] = $payload;

                try {
                    $response = $testCase->$method($uri, $testParams);
                    $content  = $response->getContent();

                    // Check if payload is reflected unescaped
                    if ($this->isPayloadReflected($content, $payload)) {
                        $vulnerabilities[] = [
                            'type'      => $this->determineXssType($payload),
                            'parameter' => $paramName,
                            'payload'   => $payload,
                            'context'   => $this->detectContext($content, $payload),
                        ];
                    }
                } catch (Exception $e) {
                    // Some XSS payloads might cause parsing errors
                    continue;
                }
            }
        }

        if (! empty($vulnerabilities)) {
            return AttackResult::vulnerable(
                attack: $this->getName(),
                severity: 'high',
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
        return 'Cross-Site Scripting (XSS)';
    }

    public function getDescription(): string
    {
        return 'Tests for reflected XSS vulnerabilities by injecting script payloads';
    }

    public function getOwaspCategory(): string
    {
        return 'A03:2021-Injection';
    }

    /**
     * Check if payload is reflected unescaped in response.
     */
    protected function isPayloadReflected(string $content, string $payload): bool
    {
        // Check for exact payload match (unescaped)
        if (str_contains($content, $payload)) {
            // Make sure it's not properly escaped
            $escapedPayload = htmlspecialchars($payload, ENT_QUOTES, 'UTF-8');

            // If the escaped version is present but not the raw version, it's safe
            if (str_contains($content, $escapedPayload) && ! $this->containsUnescaped($content, $payload, $escapedPayload)) {
                return false;
            }

            return true;
        }

        return false;
    }

    /**
     * Check if content contains unescaped payload.
     */
    protected function containsUnescaped(string $content, string $payload, string $escapedPayload): bool
    {
        // Remove escaped versions and check if raw remains
        $withoutEscaped = str_replace($escapedPayload, '', $content);

        return str_contains($withoutEscaped, $payload);
    }

    /**
     * Determine the type of XSS.
     */
    protected function determineXssType(string $payload): string
    {
        if (str_contains($payload, '<script>')) {
            return 'script-tag';
        }

        if (str_contains($payload, 'onerror=') || str_contains($payload, 'onload=')) {
            return 'event-handler';
        }

        if (str_contains($payload, 'javascript:')) {
            return 'javascript-uri';
        }

        if (preg_match('/on\w+\s*=/', $payload)) {
            return 'event-handler';
        }

        return 'reflected';
    }

    /**
     * Detect the HTML context where payload is reflected.
     */
    protected function detectContext(string $content, string $payload): string
    {
        $pos = strpos($content, $payload);

        if (false === $pos) {
            return 'unknown';
        }

        // Get surrounding context
        $before = substr($content, max(0, $pos - 50), 50);
        $after  = substr($content, $pos + strlen($payload), 50);

        // Check if inside script tag
        if (preg_match('/<script[^>]*>$/i', $before)) {
            return 'javascript';
        }

        // Check if inside attribute
        if (preg_match('/\w+\s*=\s*["\']?$/i', $before)) {
            return 'attribute';
        }

        // Check if inside HTML comment
        if (str_contains($before, '<!--') && ! str_contains($before, '-->')) {
            return 'html-comment';
        }

        // Check if inside style
        if (preg_match('/<style[^>]*>$/i', $before)) {
            return 'css';
        }

        return 'html-body';
    }
}
