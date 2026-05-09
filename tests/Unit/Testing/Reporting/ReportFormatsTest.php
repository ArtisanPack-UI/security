<?php

declare(strict_types=1);

namespace Tests\Unit\Testing\Reporting;

use ArtisanPackUI\Security\Testing\Reporting\Formats\HtmlReportFormat;
use ArtisanPackUI\Security\Testing\Reporting\Formats\JsonReportFormat;
use ArtisanPackUI\Security\Testing\Reporting\Formats\JunitReportFormat;
use ArtisanPackUI\Security\Testing\Reporting\Formats\MarkdownReportFormat;
use ArtisanPackUI\Security\Testing\Reporting\Formats\SarifReportFormat;
use ArtisanPackUI\Security\Testing\Reporting\SecurityFinding;
use Tests\TestCase;

class ReportFormatsTest extends TestCase
{
    protected array $sampleFindings;

    protected array $sampleSummary;

    protected array $sampleMetadata;

    protected function setUp(): void
    {
        parent::setUp();

        $this->sampleFindings = [
            SecurityFinding::critical('SQL Injection', 'Possible SQL injection in login form', 'A03:2021-Injection'),
            SecurityFinding::high('XSS Vulnerability', 'Reflected XSS in search', 'A03:2021-Injection'),
            SecurityFinding::medium('Missing Headers', 'Security headers not set', 'A05:2021-Security Misconfiguration'),
        ];

        $this->sampleSummary = [
            'total'      => 3,
            'bySeverity' => [
                'critical' => 1,
                'high'     => 1,
                'medium'   => 1,
                'low'      => 0,
                'info'     => 0,
            ],
            'byCategory' => [
                'A03:2021-Injection'                 => 2,
                'A05:2021-Security Misconfiguration' => 1,
            ],
        ];

        $this->sampleMetadata = [
            'generatedAt' => now()->toIso8601String(),
            'projectName' => 'Test Project',
            'version'     => '1.0.0',
        ];
    }

    // JSON Format Tests

    public function test_json_format_returns_valid_json(): void
    {
        $format = new JsonReportFormat;
        $output = $format->format($this->sampleFindings, $this->sampleMetadata, $this->sampleSummary);

        $this->assertJson($output);
    }

    public function test_json_format_contains_findings(): void
    {
        $format  = new JsonReportFormat;
        $output  = $format->format($this->sampleFindings, $this->sampleMetadata, $this->sampleSummary);
        $decoded = json_decode($output, true);

        $this->assertArrayHasKey('findings', $decoded);
        $this->assertCount(3, $decoded['findings']);
    }

    public function test_json_format_contains_summary(): void
    {
        $format  = new JsonReportFormat;
        $output  = $format->format($this->sampleFindings, $this->sampleMetadata, $this->sampleSummary);
        $decoded = json_decode($output, true);

        $this->assertArrayHasKey('summary', $decoded);
        $this->assertEquals(3, $decoded['summary']['total']);
    }

    public function test_json_format_contains_metadata(): void
    {
        $format  = new JsonReportFormat;
        $output  = $format->format($this->sampleFindings, $this->sampleMetadata, $this->sampleSummary);
        $decoded = json_decode($output, true);

        $this->assertArrayHasKey('metadata', $decoded);
    }

    public function test_json_format_extension(): void
    {
        $format = new JsonReportFormat;

        $this->assertEquals('json', $format->getExtension());
    }

    public function test_json_format_name(): void
    {
        $format = new JsonReportFormat;

        $this->assertEquals('JSON', $format->getName());
    }

    public function test_json_format_mime_type(): void
    {
        $format = new JsonReportFormat;

        $this->assertEquals('application/json', $format->getMimeType());
    }

    // HTML Format Tests

    public function test_html_format_returns_valid_html(): void
    {
        $format = new HtmlReportFormat;
        $output = $format->format($this->sampleFindings, $this->sampleMetadata, $this->sampleSummary);

        $this->assertStringContainsString('<!DOCTYPE html>', $output);
        $this->assertStringContainsString('</html>', $output);
    }

    public function test_html_format_contains_title(): void
    {
        $format = new HtmlReportFormat;
        $output = $format->format($this->sampleFindings, $this->sampleMetadata, $this->sampleSummary);

        $this->assertStringContainsString('<title>', $output);
    }

    public function test_html_format_contains_findings(): void
    {
        $format = new HtmlReportFormat;
        $output = $format->format($this->sampleFindings, $this->sampleMetadata, $this->sampleSummary);

        $this->assertStringContainsString('SQL Injection', $output);
        $this->assertStringContainsString('XSS Vulnerability', $output);
    }

    public function test_html_format_extension(): void
    {
        $format = new HtmlReportFormat;

        $this->assertEquals('html', $format->getExtension());
    }

    // JUnit Format Tests

    public function test_junit_format_returns_valid_xml(): void
    {
        $format = new JunitReportFormat;
        $output = $format->format($this->sampleFindings, $this->sampleMetadata, $this->sampleSummary);

        $this->assertStringContainsString('<?xml version="1.0"', $output);
        $this->assertStringContainsString('<testsuites>', $output);
    }

    public function test_junit_format_contains_test_cases(): void
    {
        $format = new JunitReportFormat;
        $output = $format->format($this->sampleFindings, $this->sampleMetadata, $this->sampleSummary);

        $this->assertStringContainsString('<testcase', $output);
    }

    public function test_junit_format_extension(): void
    {
        $format = new JunitReportFormat;

        $this->assertEquals('xml', $format->getExtension());
    }

    // SARIF Format Tests

    public function test_sarif_format_returns_valid_json(): void
    {
        $format = new SarifReportFormat;
        $output = $format->format($this->sampleFindings, $this->sampleMetadata, $this->sampleSummary);

        $this->assertJson($output);
    }

    public function test_sarif_format_has_correct_version(): void
    {
        $format  = new SarifReportFormat;
        $output  = $format->format($this->sampleFindings, $this->sampleMetadata, $this->sampleSummary);
        $decoded = json_decode($output, true);

        $this->assertEquals('2.1.0', $decoded['version']);
        $this->assertStringContainsString('sarif', strtolower($decoded['$schema']));
    }

    public function test_sarif_format_contains_runs(): void
    {
        $format  = new SarifReportFormat;
        $output  = $format->format($this->sampleFindings, $this->sampleMetadata, $this->sampleSummary);
        $decoded = json_decode($output, true);

        $this->assertArrayHasKey('runs', $decoded);
        $this->assertNotEmpty($decoded['runs']);
    }

    public function test_sarif_format_contains_results(): void
    {
        $format  = new SarifReportFormat;
        $output  = $format->format($this->sampleFindings, $this->sampleMetadata, $this->sampleSummary);
        $decoded = json_decode($output, true);

        $results = $decoded['runs'][0]['results'] ?? [];
        $this->assertCount(3, $results);
    }

    public function test_sarif_format_extension(): void
    {
        $format = new SarifReportFormat;

        $this->assertEquals('sarif', $format->getExtension());
    }

    // Markdown Format Tests

    public function test_markdown_format_contains_header(): void
    {
        $format = new MarkdownReportFormat;
        $output = $format->format($this->sampleFindings, $this->sampleMetadata, $this->sampleSummary);

        $this->assertStringContainsString('# Security Report', $output);
    }

    public function test_markdown_format_contains_findings(): void
    {
        $format = new MarkdownReportFormat;
        $output = $format->format($this->sampleFindings, $this->sampleMetadata, $this->sampleSummary);

        $this->assertStringContainsString('SQL Injection', $output);
        $this->assertStringContainsString('XSS Vulnerability', $output);
    }

    public function test_markdown_format_extension(): void
    {
        $format = new MarkdownReportFormat;

        $this->assertEquals('md', $format->getExtension());
    }

    // Empty findings tests

    public function test_json_format_handles_empty_findings(): void
    {
        $format = new JsonReportFormat;
        $output = $format->format([], $this->sampleMetadata, ['total' => 0, 'bySeverity' => []]);

        $decoded = json_decode($output, true);
        $this->assertEmpty($decoded['findings']);
    }

    public function test_html_format_handles_empty_findings(): void
    {
        $format = new HtmlReportFormat;
        $output = $format->format([], $this->sampleMetadata, ['total' => 0, 'bySeverity' => []]);

        $this->assertStringContainsString('<!DOCTYPE html>', $output);
    }

    public function test_junit_format_handles_empty_findings(): void
    {
        $format = new JunitReportFormat;
        $output = $format->format([], $this->sampleMetadata, ['total' => 0, 'bySeverity' => []]);

        $this->assertStringContainsString('tests="0"', $output);
    }

    public function test_sarif_format_handles_empty_findings(): void
    {
        $format = new SarifReportFormat;
        $output = $format->format([], $this->sampleMetadata, ['total' => 0, 'bySeverity' => []]);

        $decoded = json_decode($output, true);
        $this->assertEmpty($decoded['runs'][0]['results']);
    }

    public function test_markdown_format_handles_empty_findings(): void
    {
        $format = new MarkdownReportFormat;
        $output = $format->format([], $this->sampleMetadata, ['total' => 0, 'bySeverity' => []]);

        $this->assertStringContainsString('# Security Report', $output);
    }
}
