<?php

/**
 * SarifReportFormat security report formatter.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\Reporting\Formats;

use ArtisanPackUI\Security\Testing\Reporting\SecurityFinding;

class SarifReportFormat implements ReportFormatInterface
{
    public function format(array $findings, array $metadata, array $summary): string
    {
        $rules   = $this->generateRules($findings);
        $results = $this->generateResults($findings);

        $sarif = [
            '$schema' => 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
            'version' => '2.1.0',
            'runs'    => [
                [
                    'tool' => [
                        'driver' => [
                            'name'           => 'ArtisanPack Security Scanner',
                            'informationUri' => 'https://github.com/artisanpack/security',
                            'version'        => $metadata['generatorVersion'] ?? '2.0.0',
                            'rules'          => $rules,
                        ],
                    ],
                    'results'     => $results,
                    'invocations' => [
                        [
                            'executionSuccessful' => true,
                            'endTimeUtc'          => $metadata['generatedAt'] ?? date('c'),
                        ],
                    ],
                ],
            ],
        ];

        return json_encode($sarif, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    public function getName(): string
    {
        return 'SARIF';
    }

    public function getExtension(): string
    {
        return 'sarif';
    }

    public function getMimeType(): string
    {
        return 'application/sarif+json';
    }

    /**
     * Generate SARIF rules from findings.
     *
     * @param  array<SecurityFinding>  $findings
     *
     * @return array<array<string, mixed>>
     */
    protected function generateRules(array $findings): array
    {
        $rules          = [];
        $seenCategories = [];

        foreach ($findings as $finding) {
            $ruleId = $this->generateRuleId($finding->category);

            if (isset($seenCategories[$ruleId])) {
                continue;
            }

            $seenCategories[$ruleId] = true;

            $rules[] = [
                'id'               => $ruleId,
                'name'             => $this->sanitizeRuleName($finding->category),
                'shortDescription' => [
                    'text' => $finding->category,
                ],
                'fullDescription' => [
                    'text' => $this->getCategoryDescription($finding->category),
                ],
                'defaultConfiguration' => [
                    'level' => $this->severityToLevel($finding->severity),
                ],
                'properties' => [
                    'security-severity' => $this->severityToScore($finding->severity),
                    'tags'              => ['security', $this->getOwaspTag($finding->category)],
                ],
            ];
        }

        return $rules;
    }

    /**
     * Generate SARIF results from findings.
     *
     * @param  array<SecurityFinding>  $findings
     *
     * @return array<array<string, mixed>>
     */
    protected function generateResults(array $findings): array
    {
        $results = [];

        foreach ($findings as $finding) {
            $result = [
                'ruleId'  => $this->generateRuleId($finding->category),
                'level'   => $this->severityToLevel($finding->severity),
                'message' => [
                    'text' => $finding->description,
                ],
                'properties' => [
                    'id'       => $finding->id,
                    'severity' => $finding->severity,
                ],
            ];

            // Add location if available
            if ($finding->location) {
                $location            = $this->parseLocation($finding->location);
                $result['locations'] = [
                    [
                        'physicalLocation' => $location,
                    ],
                ];
            }

            // Add fix suggestion if remediation is available
            if ($finding->remediation) {
                $result['fixes'] = [
                    [
                        'description' => [
                            'text' => $finding->remediation,
                        ],
                    ],
                ];
            }

            $results[] = $result;
        }

        return $results;
    }

    /**
     * Generate a rule ID from a category.
     */
    protected function generateRuleId(string $category): string
    {
        // Extract OWASP ID if present (e.g., A01:2021-Broken Access Control -> A01)
        if (preg_match('/^(A\d{2})/', $category, $matches)) {
            return 'OWASP-'.$matches[1];
        }

        // Generate a generic ID
        return 'SEC-'.strtoupper(substr(md5($category), 0, 6));
    }

    /**
     * Sanitize a category name for use as a rule name.
     */
    protected function sanitizeRuleName(string $category): string
    {
        // Remove OWASP prefix if present
        $name = preg_replace('/^A\d{2}:\d{4}-/', '', $category);

        return $name ?: $category;
    }

    /**
     * Get a description for an OWASP category.
     */
    protected function getCategoryDescription(string $category): string
    {
        $descriptions = [
            'A01' => 'Broken Access Control: Failures in enforcing proper access restrictions',
            'A02' => 'Cryptographic Failures: Failures related to cryptography which leads to exposure of sensitive data',
            'A03' => 'Injection: User-supplied data is not validated and processed by an interpreter',
            'A04' => 'Insecure Design: Missing or ineffective control design',
            'A05' => 'Security Misconfiguration: Missing appropriate security hardening or incorrect configuration',
            'A06' => 'Vulnerable and Outdated Components: Using components with known vulnerabilities',
            'A07' => 'Identification and Authentication Failures: Failures in user identification or authentication',
            'A08' => 'Software and Data Integrity Failures: Failures related to code and infrastructure integrity',
            'A09' => 'Security Logging and Monitoring Failures: Insufficient logging, detection, or response',
            'A10' => 'Server-Side Request Forgery: Fetching remote resources without validating user-supplied URL',
        ];

        foreach ($descriptions as $id => $description) {
            if (str_contains($category, $id)) {
                return $description;
            }
        }

        return $category;
    }

    /**
     * Convert severity to SARIF level.
     */
    protected function severityToLevel(string $severity): string
    {
        return match ($severity) {
            'critical', 'high' => 'error',
            'medium'           => 'warning',
            default            => 'note',
        };
    }

    /**
     * Convert severity to security-severity score (0-10).
     */
    protected function severityToScore(string $severity): string
    {
        return match ($severity) {
            'critical' => '9.0',
            'high'     => '7.0',
            'medium'   => '5.0',
            'low'      => '3.0',
            default    => '1.0',
        };
    }

    /**
     * Get OWASP tag from category.
     */
    protected function getOwaspTag(string $category): string
    {
        if (preg_match('/^(A\d{2})/', $category, $matches)) {
            return 'owasp-'.strtolower($matches[1]);
        }

        return 'security';
    }

    /**
     * Parse a location string into SARIF format.
     *
     * @return array<string, mixed>
     */
    protected function parseLocation(string $location): array
    {
        $result = [
            'artifactLocation' => [
                'uri' => $location,
            ],
        ];

        // Check if location includes line number (e.g., "file.php:123")
        if (preg_match('/^(.+):(\d+)(?::(\d+))?$/', $location, $matches)) {
            $result['artifactLocation']['uri'] = $matches[1];
            $result['region']                  = [
                'startLine' => (int) $matches[2],
            ];

            if (isset($matches[3])) {
                $result['region']['startColumn'] = (int) $matches[3];
            }
        }

        return $result;
    }
}
