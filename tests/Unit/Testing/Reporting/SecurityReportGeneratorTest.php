<?php

declare(strict_types=1);

namespace Tests\Unit\Testing\Reporting;

use ArtisanPackUI\Security\Testing\Reporting\SecurityFinding;
use ArtisanPackUI\Security\Testing\Reporting\SecurityReportGenerator;
use InvalidArgumentException;
use Tests\TestCase;

class SecurityReportGeneratorTest extends TestCase
{
    public function test_can_add_finding(): void
    {
        $generator = new SecurityReportGenerator;
        $finding = SecurityFinding::high('Test Finding', 'Description', 'test');

        $generator->addFinding($finding);
        $findings = $generator->getFindings();

        $this->assertCount(1, $findings);
        $this->assertEquals('Test Finding', $findings[0]->title);
    }

    public function test_can_add_multiple_findings(): void
    {
        $generator = new SecurityReportGenerator;

        $generator->addFinding(SecurityFinding::high('Finding 1', 'Desc', 'cat'));
        $generator->addFinding(SecurityFinding::medium('Finding 2', 'Desc', 'cat'));
        $generator->addFinding(SecurityFinding::low('Finding 3', 'Desc', 'cat'));

        $this->assertCount(3, $generator->getFindings());
    }

    public function test_can_add_findings_array(): void
    {
        $generator = new SecurityReportGenerator;
        $findings = [
            SecurityFinding::high('Finding 1', 'Desc', 'cat'),
            SecurityFinding::medium('Finding 2', 'Desc', 'cat'),
        ];

        $generator->addFindings($findings);

        $this->assertCount(2, $generator->getFindings());
    }

    public function test_generates_summary(): void
    {
        $generator = new SecurityReportGenerator;
        $generator->addFinding(SecurityFinding::critical('Critical', 'Desc', 'A01'));
        $generator->addFinding(SecurityFinding::high('High', 'Desc', 'A02'));
        $generator->addFinding(SecurityFinding::high('High 2', 'Desc', 'A02'));

        $summary = $generator->getSummary();

        $this->assertEquals(3, $summary['total']);
        $this->assertEquals(1, $summary['bySeverity']['critical']);
        $this->assertEquals(2, $summary['bySeverity']['high']);
    }

    public function test_summary_counts_by_category(): void
    {
        $generator = new SecurityReportGenerator;
        $generator->addFinding(SecurityFinding::high('F1', 'Desc', 'Injection'));
        $generator->addFinding(SecurityFinding::high('F2', 'Desc', 'Injection'));
        $generator->addFinding(SecurityFinding::medium('F3', 'Desc', 'XSS'));

        $summary = $generator->getSummary();

        $this->assertEquals(2, $summary['byCategory']['Injection']);
        $this->assertEquals(1, $summary['byCategory']['XSS']);
    }

    public function test_generates_json_report(): void
    {
        $generator = new SecurityReportGenerator;
        $generator->addFinding(SecurityFinding::high('Test', 'Desc', 'cat'));

        $report = $generator->generate('json');

        $this->assertJson($report);
        $decoded = json_decode($report, true);
        $this->assertArrayHasKey('findings', $decoded);
    }

    public function test_generates_html_report(): void
    {
        $generator = new SecurityReportGenerator;
        $generator->addFinding(SecurityFinding::high('Test', 'Desc', 'cat'));

        $report = $generator->generate('html');

        $this->assertStringContainsString('<!DOCTYPE html>', $report);
    }

    public function test_generates_sarif_report(): void
    {
        $generator = new SecurityReportGenerator;
        $generator->addFinding(SecurityFinding::high('Test', 'Desc', 'cat'));

        $report = $generator->generate('sarif');

        $decoded = json_decode($report, true);
        $this->assertEquals('2.1.0', $decoded['version']);
    }

    public function test_generates_junit_report(): void
    {
        $generator = new SecurityReportGenerator;
        $generator->addFinding(SecurityFinding::high('Test', 'Desc', 'cat'));

        $report = $generator->generate('junit');

        $this->assertStringContainsString('<testsuites>', $report);
    }

    public function test_generates_markdown_report(): void
    {
        $generator = new SecurityReportGenerator;
        $generator->addFinding(SecurityFinding::high('Test', 'Desc', 'cat'));

        $report = $generator->generate('markdown');

        $this->assertStringContainsString('# Security Report', $report);
    }

    public function test_throws_exception_for_unknown_format(): void
    {
        $generator = new SecurityReportGenerator;

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unknown format');

        $generator->generate('unknown-format');
    }

    public function test_saves_report_to_file(): void
    {
        $generator = new SecurityReportGenerator;
        $generator->addFinding(SecurityFinding::high('Test', 'Desc', 'cat'));

        $path = sys_get_temp_dir().'/security-report-test.json';
        $result = $generator->saveToFile($path, 'json');

        $this->assertTrue($result);
        $this->assertFileExists($path);
        $content = file_get_contents($path);
        $this->assertJson($content);

        unlink($path);
    }

    public function test_clears_findings(): void
    {
        $generator = new SecurityReportGenerator;
        $generator->addFinding(SecurityFinding::high('Test', 'Desc', 'cat'));

        $this->assertCount(1, $generator->getFindings());

        $generator->clear();

        $this->assertEmpty($generator->getFindings());
    }

    public function test_gets_findings_by_severity(): void
    {
        $generator = new SecurityReportGenerator;
        $generator->addFinding(SecurityFinding::critical('Critical', 'Desc', 'cat'));
        $generator->addFinding(SecurityFinding::high('High', 'Desc', 'cat'));
        $generator->addFinding(SecurityFinding::medium('Medium', 'Desc', 'cat'));

        $highFindings = $generator->getFindingsBySeverity('high');

        $this->assertCount(1, $highFindings);
    }

    public function test_has_blocking_findings(): void
    {
        $generator = new SecurityReportGenerator;
        $generator->addFinding(SecurityFinding::medium('Medium', 'Desc', 'cat'));

        $summary = $generator->getSummary();
        $this->assertFalse($summary['hasBlocking']);

        $generator->addFinding(SecurityFinding::critical('Critical', 'Desc', 'cat'));

        $summary = $generator->getSummary();
        $this->assertTrue($summary['hasBlocking']);
    }

    public function test_sorts_by_severity(): void
    {
        $generator = new SecurityReportGenerator;
        $generator->addFinding(SecurityFinding::low('Low', 'Desc', 'cat'));
        $generator->addFinding(SecurityFinding::critical('Critical', 'Desc', 'cat'));
        $generator->addFinding(SecurityFinding::medium('Medium', 'Desc', 'cat'));

        $generator->sortBySeverity();
        $findings = $generator->getFindings();

        $this->assertEquals('critical', $findings[0]->severity);
        $this->assertEquals('medium', $findings[1]->severity);
        $this->assertEquals('low', $findings[2]->severity);
    }

    public function test_empty_report_generates_successfully(): void
    {
        $generator = new SecurityReportGenerator;

        $report = $generator->generate('json');
        $decoded = json_decode($report, true);

        $this->assertEmpty($decoded['findings']);
        $this->assertEquals(0, $decoded['summary']['total']);
    }

    public function test_can_add_metadata(): void
    {
        $generator = new SecurityReportGenerator('TestProject', '1.0.0');
        $generator->withMetadata(['customField' => 'customValue']);
        $generator->addFinding(SecurityFinding::high('Test', 'Desc', 'cat'));

        $report = $generator->generate('json');
        $decoded = json_decode($report, true);

        $this->assertArrayHasKey('metadata', $decoded);
        $this->assertEquals('TestProject', $decoded['metadata']['projectName']);
        $this->assertEquals('customValue', $decoded['metadata']['customField']);
    }

    public function test_fluent_interface(): void
    {
        $generator = (new SecurityReportGenerator)
            ->addFinding(SecurityFinding::high('Test 1', 'Desc', 'cat'))
            ->addFinding(SecurityFinding::medium('Test 2', 'Desc', 'cat'))
            ->withMetadata(['scanType' => 'full'])
            ->sortBySeverity();

        $findings = $generator->getFindings();

        $this->assertCount(2, $findings);
        $this->assertEquals('high', $findings[0]->severity);
    }
}
