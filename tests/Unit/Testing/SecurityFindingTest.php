<?php

declare(strict_types=1);

namespace Tests\Unit\Testing;

use ArtisanPackUI\Security\Testing\Reporting\SecurityFinding;
use Tests\TestCase;

class SecurityFindingTest extends TestCase
{
    public function test_can_create_finding_with_constructor(): void
    {
        $finding = new SecurityFinding(
            id: 'test-001',
            title: 'Test Finding',
            description: 'Test description',
            severity: SecurityFinding::SEVERITY_HIGH,
            category: 'test-category',
            location: 'app/Test.php:10',
            evidence: 'Found vulnerable code',
            remediation: 'Fix the issue',
            metadata: ['key' => 'value'],
        );

        $this->assertEquals('test-001', $finding->id);
        $this->assertEquals('Test Finding', $finding->title);
        $this->assertEquals('Test description', $finding->description);
        $this->assertEquals(SecurityFinding::SEVERITY_HIGH, $finding->severity);
        $this->assertEquals('test-category', $finding->category);
        $this->assertEquals('app/Test.php:10', $finding->location);
        $this->assertEquals('Found vulnerable code', $finding->evidence);
        $this->assertEquals('Fix the issue', $finding->remediation);
        $this->assertEquals(['key' => 'value'], $finding->metadata);
    }

    public function test_can_create_critical_finding(): void
    {
        $finding = SecurityFinding::critical(
            'Critical Issue',
            'Critical description',
            'critical-category',
        );

        $this->assertEquals(SecurityFinding::SEVERITY_CRITICAL, $finding->severity);
        $this->assertEquals('Critical Issue', $finding->title);
        $this->assertEquals('Critical description', $finding->description);
        $this->assertEquals('critical-category', $finding->category);
    }

    public function test_can_create_high_finding(): void
    {
        $finding = SecurityFinding::high(
            'High Issue',
            'High description',
            'high-category',
        );

        $this->assertEquals(SecurityFinding::SEVERITY_HIGH, $finding->severity);
        $this->assertEquals('High Issue', $finding->title);
    }

    public function test_can_create_medium_finding(): void
    {
        $finding = SecurityFinding::medium(
            'Medium Issue',
            'Medium description',
            'medium-category',
        );

        $this->assertEquals(SecurityFinding::SEVERITY_MEDIUM, $finding->severity);
        $this->assertEquals('Medium Issue', $finding->title);
    }

    public function test_can_create_low_finding(): void
    {
        $finding = SecurityFinding::low(
            'Low Issue',
            'Low description',
            'low-category',
        );

        $this->assertEquals(SecurityFinding::SEVERITY_LOW, $finding->severity);
        $this->assertEquals('Low Issue', $finding->title);
    }

    public function test_can_create_info_finding(): void
    {
        $finding = SecurityFinding::info(
            'Info Issue',
            'Info description',
            'info-category',
        );

        $this->assertEquals(SecurityFinding::SEVERITY_INFO, $finding->severity);
        $this->assertEquals('Info Issue', $finding->title);
    }

    public function test_converts_to_array(): void
    {
        $finding = SecurityFinding::high(
            'Test Finding',
            'Test description',
            'test-category',
            'app/Test.php:10',
            'Fix it',
        );

        $array = $finding->toArray();

        $this->assertArrayHasKey('id', $array);
        $this->assertArrayHasKey('title', $array);
        $this->assertArrayHasKey('description', $array);
        $this->assertArrayHasKey('severity', $array);
        $this->assertArrayHasKey('category', $array);
        $this->assertArrayHasKey('location', $array);
        $this->assertArrayHasKey('remediation', $array);
        $this->assertArrayHasKey('metadata', $array);

        $this->assertEquals('Test Finding', $array['title']);
        $this->assertEquals(SecurityFinding::SEVERITY_HIGH, $array['severity']);
    }

    public function test_creates_from_vulnerability_array(): void
    {
        $data = [
            'id' => 'from-array-001',
            'title' => 'From Array',
            'description' => 'Created from array',
            'severity' => SecurityFinding::SEVERITY_LOW,
            'category' => 'array-category',
            'location' => 'test/location.php',
            'remediation' => 'Array recommendation',
            'evidence' => 'Some evidence',
            'metadata' => ['source' => 'array'],
        ];

        $finding = SecurityFinding::fromVulnerability($data);

        $this->assertEquals('from-array-001', $finding->id);
        $this->assertEquals('From Array', $finding->title);
        $this->assertEquals(SecurityFinding::SEVERITY_LOW, $finding->severity);
        $this->assertEquals(['source' => 'array'], $finding->metadata);
    }

    public function test_generates_unique_id(): void
    {
        $finding1 = SecurityFinding::high('Test 1', 'Desc 1', 'cat1');
        $finding2 = SecurityFinding::high('Test 2', 'Desc 2', 'cat2');

        $this->assertNotEquals($finding1->id, $finding2->id);
        $this->assertStringStartsWith('SEC-', $finding1->id);
        $this->assertStringStartsWith('SEC-', $finding2->id);
    }

    public function test_is_critical(): void
    {
        $critical = SecurityFinding::critical('Test', 'Desc', 'cat');
        $high = SecurityFinding::high('Test', 'Desc', 'cat');

        $this->assertTrue($critical->isCritical());
        $this->assertFalse($high->isCritical());
    }

    public function test_is_high(): void
    {
        $high = SecurityFinding::high('Test', 'Desc', 'cat');
        $medium = SecurityFinding::medium('Test', 'Desc', 'cat');

        $this->assertTrue($high->isHigh());
        $this->assertFalse($medium->isHigh());
    }

    public function test_is_blocking(): void
    {
        $critical = SecurityFinding::critical('Test', 'Desc', 'cat');
        $high = SecurityFinding::high('Test', 'Desc', 'cat');
        $medium = SecurityFinding::medium('Test', 'Desc', 'cat');

        $this->assertTrue($critical->isBlocking());
        $this->assertTrue($high->isBlocking());
        $this->assertFalse($medium->isBlocking());
    }

    public function test_severity_order(): void
    {
        $critical = SecurityFinding::critical('Test', 'Desc', 'cat');
        $high = SecurityFinding::high('Test', 'Desc', 'cat');
        $medium = SecurityFinding::medium('Test', 'Desc', 'cat');
        $low = SecurityFinding::low('Test', 'Desc', 'cat');
        $info = SecurityFinding::info('Test', 'Desc', 'cat');

        $this->assertEquals(0, $critical->getSeverityOrder());
        $this->assertEquals(1, $high->getSeverityOrder());
        $this->assertEquals(2, $medium->getSeverityOrder());
        $this->assertEquals(3, $low->getSeverityOrder());
        $this->assertEquals(4, $info->getSeverityOrder());
    }

    public function test_can_create_with_location_and_remediation(): void
    {
        $finding = SecurityFinding::high(
            'Test',
            'Description',
            'Category',
            'src/File.php:42',
            'Fix the vulnerability',
        );

        $this->assertEquals('src/File.php:42', $finding->location);
        $this->assertEquals('Fix the vulnerability', $finding->remediation);
    }
}
