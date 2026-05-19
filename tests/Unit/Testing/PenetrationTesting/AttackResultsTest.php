<?php

declare(strict_types=1);

namespace Tests\Unit\Testing\PenetrationTesting;

use ArtisanPackUI\Security\Testing\PenetrationTesting\AttackResult;
use ArtisanPackUI\Security\Testing\PenetrationTesting\AttackResults;
use Tests\TestCase;

class AttackResultsTest extends TestCase
{
    // AttackResult Tests

    public function test_can_create_attack_result(): void
    {
        $result = new AttackResult(
            attack: 'SQL Injection',
            vulnerable: true,
            findings: [['payload' => "' OR '1'='1", 'response' => 'Error']],
            severity: 'high',
            metadata: ['target' => '/api/users'],
        );

        $this->assertEquals('SQL Injection', $result->attack);
        $this->assertTrue($result->vulnerable);
        $this->assertCount(1, $result->findings);
        $this->assertEquals('high', $result->severity);
        $this->assertEquals('/api/users', $result->metadata['target']);
    }

    public function test_attack_result_to_array(): void
    {
        $result = new AttackResult(
            attack: 'XSS',
            vulnerable: false,
            findings: [],
            severity: 'none',
            metadata: [],
        );

        $array = $result->toArray();

        $this->assertArrayHasKey('attack', $array);
        $this->assertArrayHasKey('vulnerable', $array);
        $this->assertArrayHasKey('severity', $array);
        $this->assertArrayHasKey('findings', $array);
        $this->assertArrayHasKey('findingCount', $array);
        $this->assertArrayHasKey('metadata', $array);
    }

    public function test_create_vulnerable_result(): void
    {
        $result = AttackResult::vulnerable(
            'SQL Injection',
            'critical',
            [['payload' => 'test', 'response' => 'vulnerable']],
            ['endpoint' => '/api'],
        );

        $this->assertTrue($result->vulnerable);
        $this->assertEquals('critical', $result->severity);
        $this->assertCount(1, $result->findings);
    }

    public function test_create_not_vulnerable_result(): void
    {
        $result = AttackResult::notVulnerable('XSS', ['tested' => true]);

        $this->assertFalse($result->vulnerable);
        $this->assertEquals('none', $result->severity);
        $this->assertEmpty($result->findings);
    }

    public function test_is_critical(): void
    {
        $critical = AttackResult::vulnerable('Test', 'critical');
        $high     = AttackResult::vulnerable('Test', 'high');

        $this->assertTrue($critical->isCritical());
        $this->assertFalse($high->isCritical());
    }

    public function test_is_high(): void
    {
        $high   = AttackResult::vulnerable('Test', 'high');
        $medium = AttackResult::vulnerable('Test', 'medium');

        $this->assertTrue($high->isHigh());
        $this->assertFalse($medium->isHigh());
    }

    public function test_is_blocking(): void
    {
        $critical = AttackResult::vulnerable('Test', 'critical');
        $high     = AttackResult::vulnerable('Test', 'high');
        $medium   = AttackResult::vulnerable('Test', 'medium');
        $notVuln  = AttackResult::notVulnerable('Test');

        $this->assertTrue($critical->isBlocking());
        $this->assertTrue($high->isBlocking());
        $this->assertFalse($medium->isBlocking());
        $this->assertFalse($notVuln->isBlocking());
    }

    public function test_get_finding_count(): void
    {
        $result = new AttackResult(
            attack: 'Test',
            vulnerable: true,
            findings: [
                ['payload' => '1'],
                ['payload' => '2'],
                ['payload' => '3'],
            ],
            severity: 'high',
        );

        $this->assertEquals(3, $result->getFindingCount());
    }

    // AttackResults Tests

    public function test_can_create_attack_results_collection(): void
    {
        $results = new AttackResults;

        $this->assertInstanceOf(AttackResults::class, $results);
    }

    public function test_can_add_result(): void
    {
        $results = new AttackResults;
        $result  = AttackResult::notVulnerable('XSS');

        $results->add($result);

        $this->assertCount(1, $results->all());
    }

    public function test_can_add_multiple_results(): void
    {
        $results = new AttackResults;

        $results->add(AttackResult::notVulnerable('Type1'));
        $results->add(AttackResult::vulnerable('Type2', 'high'));
        $results->add(AttackResult::notVulnerable('Type3'));

        $this->assertCount(3, $results->all());
    }

    public function test_has_vulnerabilities(): void
    {
        $resultsWithVulns = new AttackResults;
        $resultsWithVulns->add(AttackResult::vulnerable('Test', 'high'));

        $resultsWithoutVulns = new AttackResults;
        $resultsWithoutVulns->add(AttackResult::notVulnerable('Test'));

        $this->assertTrue($resultsWithVulns->hasVulnerabilities());
        $this->assertFalse($resultsWithoutVulns->hasVulnerabilities());
    }

    public function test_get_vulnerable(): void
    {
        $results = new AttackResults;
        $results->add(AttackResult::vulnerable('SQLi', 'high'));
        $results->add(AttackResult::notVulnerable('XSS'));
        $results->add(AttackResult::vulnerable('CSRF', 'medium'));

        $vulnerable = $results->getVulnerable();

        $this->assertCount(2, $vulnerable);
    }

    public function test_get_by_severity(): void
    {
        $results = new AttackResults;
        $results->add(AttackResult::vulnerable('T1', 'critical'));
        $results->add(AttackResult::vulnerable('T2', 'high'));
        $results->add(AttackResult::vulnerable('T3', 'high'));
        $results->add(AttackResult::notVulnerable('T4'));

        $highSeverity = $results->getBySeverity('high');

        $this->assertCount(2, $highSeverity);
    }

    public function test_to_array(): void
    {
        $results = new AttackResults;
        $results->add(AttackResult::vulnerable('Test', 'high'));

        $array = $results->toArray();

        $this->assertIsArray($array);
        $this->assertCount(1, $array);
        $this->assertArrayHasKey('attack', $array[0]);
    }

    public function test_get_summary(): void
    {
        $results = new AttackResults;
        $results->add(AttackResult::vulnerable('SQLi', 'critical'));
        $results->add(AttackResult::vulnerable('XSS', 'high'));
        $results->add(AttackResult::notVulnerable('CSRF'));

        $summary = $results->getSummary();

        $this->assertEquals(3, $summary['total_attacks']);
        $this->assertEquals(2, $summary['vulnerable']);
        $this->assertEquals(1, $summary['not_vulnerable']);
        $this->assertArrayHasKey('by_severity', $summary);
        $this->assertEquals(1, $summary['by_severity']['critical']);
        $this->assertEquals(1, $summary['by_severity']['high']);
    }

    public function test_has_critical(): void
    {
        $resultsWithCritical = new AttackResults;
        $resultsWithCritical->add(AttackResult::vulnerable('Test', 'critical'));

        $resultsWithoutCritical = new AttackResults;
        $resultsWithoutCritical->add(AttackResult::vulnerable('Test', 'high'));

        $this->assertTrue($resultsWithCritical->hasCritical());
        $this->assertFalse($resultsWithoutCritical->hasCritical());
    }

    public function test_has_blocking(): void
    {
        $resultsWithBlocking = new AttackResults;
        $resultsWithBlocking->add(AttackResult::vulnerable('Test', 'high'));

        $resultsWithoutBlocking = new AttackResults;
        $resultsWithoutBlocking->add(AttackResult::vulnerable('Test', 'medium'));

        $this->assertTrue($resultsWithBlocking->hasBlocking());
        $this->assertFalse($resultsWithoutBlocking->hasBlocking());
    }

    public function test_get_total_vulnerabilities(): void
    {
        $results = new AttackResults;

        // Result with 2 findings
        $results->add(new AttackResult(
            attack: 'SQLi',
            vulnerable: true,
            findings: [['p' => '1'], ['p' => '2']],
            severity: 'high',
        ));

        // Result with 1 finding (implicit)
        $results->add(AttackResult::vulnerable('XSS', 'medium'));

        // Not vulnerable
        $results->add(AttackResult::notVulnerable('CSRF'));

        $this->assertEquals(3, $results->getTotalVulnerabilities());
    }

    public function test_fluent_add(): void
    {
        $results = (new AttackResults)
            ->add(AttackResult::notVulnerable('T1'))
            ->add(AttackResult::notVulnerable('T2'));

        $this->assertCount(2, $results->all());
    }

    public function test_all_method(): void
    {
        $results = new AttackResults;
        $results->add(AttackResult::notVulnerable('Test1'));
        $results->add(AttackResult::notVulnerable('Test2'));

        $all = $results->all();

        $this->assertCount(2, $all);
        foreach ($all as $result) {
            $this->assertInstanceOf(AttackResult::class, $result);
        }
    }
}
