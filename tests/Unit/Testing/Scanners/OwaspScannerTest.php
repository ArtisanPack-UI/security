<?php

declare(strict_types=1);

namespace Tests\Unit\Testing\Scanners;

use ArtisanPackUI\Security\Testing\Reporting\SecurityFinding;
use ArtisanPackUI\Security\Testing\Scanners\OwaspScanner;
use Tests\TestCase;

class OwaspScannerTest extends TestCase
{
    protected OwaspScanner $scanner;

    protected function setUp(): void
    {
        parent::setUp();
        $this->scanner = new OwaspScanner;
    }

    public function test_can_instantiate_scanner(): void
    {
        $this->assertInstanceOf(OwaspScanner::class, $this->scanner);
    }

    public function test_scan_returns_array(): void
    {
        $findings = $this->scanner->scan();

        $this->assertIsArray($findings);
    }

    public function test_findings_are_security_finding_instances(): void
    {
        $findings = $this->scanner->scan();

        foreach ($findings as $finding) {
            $this->assertInstanceOf(SecurityFinding::class, $finding);
        }
    }

    public function test_findings_have_valid_severity(): void
    {
        $findings = $this->scanner->scan();

        $validSeverities = [
            SecurityFinding::SEVERITY_CRITICAL,
            SecurityFinding::SEVERITY_HIGH,
            SecurityFinding::SEVERITY_MEDIUM,
            SecurityFinding::SEVERITY_LOW,
            SecurityFinding::SEVERITY_INFO,
        ];

        foreach ($findings as $finding) {
            $this->assertContains(
                $finding->severity,
                $validSeverities,
                "Invalid severity: {$finding->severity}",
            );
        }
    }

    public function test_scanner_name(): void
    {
        $this->assertEquals('OWASP Top 10 Scanner', $this->scanner->getName());
    }

    public function test_scanner_description(): void
    {
        $description = $this->scanner->getDescription();

        $this->assertStringContainsString('OWASP', $description);
    }

    public function test_findings_have_category(): void
    {
        $findings = $this->scanner->scan();

        foreach ($findings as $finding) {
            $this->assertNotEmpty($finding->category);
        }
    }

    public function test_findings_have_title_and_description(): void
    {
        $findings = $this->scanner->scan();

        foreach ($findings as $finding) {
            $this->assertNotEmpty($finding->title);
            $this->assertNotEmpty($finding->description);
        }
    }

    public function test_findings_have_valid_id(): void
    {
        $findings = $this->scanner->scan();

        foreach ($findings as $finding) {
            $this->assertNotEmpty($finding->id);
            $this->assertStringStartsWith('SEC-', $finding->id);
        }
    }
}
