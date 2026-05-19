<?php

/**
 * JunitReportFormat security report formatter.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\Reporting\Formats;

use ArtisanPackUI\Security\Testing\Reporting\SecurityFinding;
use DOMDocument;

class JunitReportFormat implements ReportFormatInterface
{
    public function format(array $findings, array $metadata, array $summary): string
    {
        $dom               = new DOMDocument('1.0', 'UTF-8');
        $dom->formatOutput = true;

        // Create root testsuites element
        $testsuites = $dom->createElement('testsuites');
        $dom->appendChild($testsuites);

        // Create testsuite element
        $testsuite = $dom->createElement('testsuite');
        $testsuite->setAttribute('name', 'Security Tests');
        $testsuite->setAttribute('tests', (string) count($findings));
        $testsuite->setAttribute('failures', (string) $this->countFailures($findings));
        $testsuite->setAttribute('errors', '0');
        $testsuite->setAttribute('time', '0');
        $testsuite->setAttribute('timestamp', $metadata['generatedAt'] ?? date('c'));
        $testsuites->appendChild($testsuite);

        // Add properties
        $properties = $dom->createElement('properties');
        $testsuite->appendChild($properties);

        foreach ($metadata as $name => $value) {
            if (is_scalar($value)) {
                $property = $dom->createElement('property');
                $property->setAttribute('name', $name);
                $property->setAttribute('value', (string) $value);
                $properties->appendChild($property);
            }
        }

        // Group findings by category for test cases
        $groupedFindings = $this->groupByCategory($findings);

        foreach ($groupedFindings as $category => $categoryFindings) {
            foreach ($categoryFindings as $finding) {
                $testcase = $dom->createElement('testcase');
                $testcase->setAttribute('name', $finding->title);
                $testcase->setAttribute('classname', $this->sanitizeClassName($category));
                $testcase->setAttribute('time', '0');
                $testsuite->appendChild($testcase);

                // Critical and high are failures
                if (in_array($finding->severity, ['critical', 'high'])) {
                    $failure = $dom->createElement('failure');
                    $failure->setAttribute('type', $finding->severity);
                    $failure->setAttribute('message', $finding->description);

                    $failureText = $this->buildFailureText($finding);
                    $failure->appendChild($dom->createCDATASection($failureText));

                    $testcase->appendChild($failure);
                }
                // Medium are warnings (system-out)
                elseif ('medium' === $finding->severity) {
                    $systemOut = $dom->createElement('system-out');
                    $systemOut->appendChild($dom->createCDATASection(
                        "Warning: {$finding->description}\nLocation: {$finding->location}",
                    ));
                    $testcase->appendChild($systemOut);
                }
            }
        }

        // If no findings, add a passing test
        if (empty($findings)) {
            $testcase = $dom->createElement('testcase');
            $testcase->setAttribute('name', 'No security vulnerabilities detected');
            $testcase->setAttribute('classname', 'SecurityScan');
            $testcase->setAttribute('time', '0');
            $testsuite->appendChild($testcase);
        }

        return $dom->saveXML();
    }

    public function getName(): string
    {
        return 'JUnit XML';
    }

    public function getExtension(): string
    {
        return 'xml';
    }

    public function getMimeType(): string
    {
        return 'application/xml';
    }

    /**
     * Count failures (critical and high severity findings).
     *
     * @param  array<SecurityFinding>  $findings
     */
    protected function countFailures(array $findings): int
    {
        return count(array_filter(
            $findings,
            fn (SecurityFinding $f) => in_array($f->severity, ['critical', 'high']),
        ));
    }

    /**
     * Group findings by category.
     *
     * @param  array<SecurityFinding>  $findings
     *
     * @return array<string, array<SecurityFinding>>
     */
    protected function groupByCategory(array $findings): array
    {
        $groups = [];

        foreach ($findings as $finding) {
            $groups[$finding->category][] = $finding;
        }

        return $groups;
    }

    /**
     * Sanitize a category name for use as a class name.
     */
    protected function sanitizeClassName(string $category): string
    {
        // Remove special characters and convert to PascalCase
        $cleaned = preg_replace('/[^a-zA-Z0-9\s]/', '', $category);
        $words   = explode(' ', $cleaned);

        return implode('', array_map('ucfirst', array_map('strtolower', $words)));
    }

    /**
     * Build the failure text content.
     */
    protected function buildFailureText(SecurityFinding $finding): string
    {
        $text = "ID: {$finding->id}\n";
        $text .= "Severity: {$finding->severity}\n";
        $text .= "Category: {$finding->category}\n";

        if ($finding->location) {
            $text .= "Location: {$finding->location}\n";
        }

        if ($finding->evidence) {
            $text .= "Evidence: {$finding->evidence}\n";
        }

        if ($finding->remediation) {
            $text .= "\nRemediation: {$finding->remediation}\n";
        }

        return $text;
    }
}
