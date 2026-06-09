<?php

declare(strict_types=1);

namespace Tests\Unit\Testing\CiCd;

use ArtisanPackUI\Security\Testing\CiCd\GateResult;
use ArtisanPackUI\Security\Testing\CiCd\SecurityGate;
use ArtisanPackUI\Security\Testing\Performance\BenchmarkResult;
use ArtisanPackUI\Security\Testing\Reporting\SecurityFinding;
use Tests\TestCase;

class SecurityGateTest extends TestCase
{
    public function test_creates_gate_with_default_thresholds(): void
    {
        $gate = new SecurityGate;

        $this->assertInstanceOf(SecurityGate::class, $gate);
    }

    public function test_passes_with_no_findings(): void
    {
        $gate = new SecurityGate;
        $result = $gate->evaluate([]);

        $this->assertTrue($result->passed);
        $this->assertEmpty($result->failures);
    }

    public function test_fails_with_critical_finding(): void
    {
        $gate = new SecurityGate(maxCritical: 0);
        $findings = [
            SecurityFinding::critical('Critical Issue', 'Description', 'test'),
        ];

        $result = $gate->evaluate($findings);

        $this->assertFalse($result->passed);
        $this->assertNotEmpty($result->failures);
        $this->assertStringContainsString('Critical', $result->failures[0]);
    }

    public function test_passes_with_critical_finding_when_threshold_allows(): void
    {
        $gate = new SecurityGate(maxCritical: 1);
        $findings = [
            SecurityFinding::critical('Critical Issue', 'Description', 'test'),
        ];

        $result = $gate->evaluate($findings);

        $this->assertTrue($result->passed);
    }

    public function test_fails_with_high_finding_exceeding_threshold(): void
    {
        $gate = new SecurityGate(maxHigh: 0);
        $findings = [
            SecurityFinding::high('High Issue', 'Description', 'test'),
        ];

        $result = $gate->evaluate($findings);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('High', $result->failures[0]);
    }

    public function test_fails_with_medium_findings_exceeding_threshold(): void
    {
        $gate = new SecurityGate(maxMedium: 2);
        $findings = [
            SecurityFinding::medium('Medium 1', 'Description', 'test'),
            SecurityFinding::medium('Medium 2', 'Description', 'test'),
            SecurityFinding::medium('Medium 3', 'Description', 'test'),
        ];

        $result = $gate->evaluate($findings);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('Medium', $result->failures[0]);
    }

    public function test_ignores_low_findings(): void
    {
        $gate = new SecurityGate;
        $findings = [
            SecurityFinding::low('Low Issue 1', 'Description', 'test'),
            SecurityFinding::low('Low Issue 2', 'Description', 'test'),
            SecurityFinding::low('Low Issue 3', 'Description', 'test'),
        ];

        $result = $gate->evaluate($findings);

        $this->assertTrue($result->passed);
    }

    public function test_ignores_info_findings(): void
    {
        $gate = new SecurityGate;
        $findings = [
            SecurityFinding::info('Info 1', 'Description', 'test'),
            SecurityFinding::info('Info 2', 'Description', 'test'),
        ];

        $result = $gate->evaluate($findings);

        $this->assertTrue($result->passed);
    }

    public function test_checks_performance_overhead(): void
    {
        $gate = new SecurityGate(maxOverheadPercent: 10.0);

        $benchmarks = [
            new BenchmarkResult(
                name: 'High Overhead Test',
                withSecurity: ['mean' => 15.0, 'min' => 12.0, 'max' => 18.0, 'stddev' => 1.5],
                withoutSecurity: ['mean' => 10.0, 'min' => 9.0, 'max' => 11.0, 'stddev' => 0.5],
                iterations: 100,
            ),
        ];

        $result = $gate->evaluate([], $benchmarks);

        // 50% overhead exceeds 10% threshold
        $this->assertFalse($result->passed);
        $this->assertStringContainsString('overhead', $result->failures[0]);
    }

    public function test_passes_performance_check_when_under_threshold(): void
    {
        $gate = new SecurityGate(maxOverheadPercent: 15.0);

        $benchmarks = [
            new BenchmarkResult(
                name: 'Acceptable Overhead',
                withSecurity: ['mean' => 11.0, 'min' => 10.0, 'max' => 12.0, 'stddev' => 0.5],
                withoutSecurity: ['mean' => 10.0, 'min' => 9.0, 'max' => 11.0, 'stddev' => 0.5],
                iterations: 100,
            ),
        ];

        $result = $gate->evaluate([], $benchmarks);

        // 10% overhead is under 15% threshold
        $this->assertTrue($result->passed);
    }

    public function test_adds_custom_rule(): void
    {
        $gate = new SecurityGate;
        $gate->addRule('custom', function ($findings, $benchmarks) {
            return count($findings) < 5 ? true : 'Too many findings';
        });

        $findings = [
            SecurityFinding::low('Issue 1', 'Desc', 'test'),
            SecurityFinding::low('Issue 2', 'Desc', 'test'),
            SecurityFinding::low('Issue 3', 'Desc', 'test'),
            SecurityFinding::low('Issue 4', 'Desc', 'test'),
            SecurityFinding::low('Issue 5', 'Desc', 'test'),
        ];

        $result = $gate->evaluate($findings);

        $this->assertFalse($result->passed);
        $this->assertStringContainsString("Rule 'custom' failed", $result->failures[0]);
    }

    public function test_custom_rule_passes_when_returning_true(): void
    {
        $gate = new SecurityGate;
        $gate->addRule('always-pass', function () {
            return true;
        });

        $result = $gate->evaluate([]);

        $this->assertTrue($result->passed);
    }

    public function test_creates_strict_gate(): void
    {
        $gate = SecurityGate::strict();

        // Strict gate should fail on any high findings
        $findings = [
            SecurityFinding::high('High Issue', 'Description', 'test'),
        ];

        $result = $gate->evaluate($findings);

        $this->assertFalse($result->passed);
    }

    public function test_creates_permissive_gate(): void
    {
        $gate = SecurityGate::permissive();

        // Permissive gate should allow some high findings
        $findings = [
            SecurityFinding::high('High Issue 1', 'Description', 'test'),
            SecurityFinding::high('High Issue 2', 'Description', 'test'),
        ];

        $result = $gate->evaluate($findings);

        $this->assertTrue($result->passed);
    }

    public function test_gate_result_exit_code_success(): void
    {
        $result = new GateResult(
            passed: true,
            failures: [],
            summary: ['critical' => 0, 'high' => 0, 'medium' => 0],
        );

        $this->assertEquals(0, $result->getExitCode());
    }

    public function test_gate_result_exit_code_failure(): void
    {
        $result = new GateResult(
            passed: false,
            failures: ['Some failure'],
            summary: ['critical' => 1, 'high' => 0, 'medium' => 0],
        );

        $this->assertEquals(1, $result->getExitCode());
    }

    public function test_gate_result_failure_message(): void
    {
        $result = new GateResult(
            passed: false,
            failures: ['Failure 1', 'Failure 2'],
            summary: ['critical' => 0, 'high' => 0, 'medium' => 0],
        );

        $message = $result->getFailureMessage();

        $this->assertStringContainsString('Failure 1', $message);
        $this->assertStringContainsString('Failure 2', $message);
    }

    public function test_gate_result_empty_failure_message_when_passed(): void
    {
        $result = new GateResult(
            passed: true,
            failures: [],
            summary: ['critical' => 0, 'high' => 0, 'medium' => 0],
        );

        $this->assertEquals('', $result->getFailureMessage());
    }

    public function test_gate_result_to_array(): void
    {
        $result = new GateResult(
            passed: true,
            failures: [],
            summary: ['critical' => 0, 'high' => 1, 'medium' => 2],
        );

        $array = $result->toArray();

        $this->assertArrayHasKey('passed', $array);
        $this->assertArrayHasKey('failures', $array);
        $this->assertArrayHasKey('summary', $array);
        $this->assertTrue($array['passed']);
        $this->assertEquals(1, $array['summary']['high']);
    }

    public function test_summary_contains_correct_counts(): void
    {
        $gate = new SecurityGate(maxCritical: 5, maxHigh: 5, maxMedium: 20);
        $findings = [
            SecurityFinding::critical('Critical 1', 'Desc', 'test'),
            SecurityFinding::high('High 1', 'Desc', 'test'),
            SecurityFinding::high('High 2', 'Desc', 'test'),
            SecurityFinding::medium('Medium 1', 'Desc', 'test'),
        ];

        $result = $gate->evaluate($findings);

        $this->assertEquals(1, $result->summary['critical']);
        $this->assertEquals(2, $result->summary['high']);
        $this->assertEquals(1, $result->summary['medium']);
    }

    public function test_multiple_failures_accumulated(): void
    {
        $gate = new SecurityGate(
            maxCritical: 0,
            maxHigh: 0,
            maxMedium: 0,
            maxOverheadPercent: 5.0,
        );

        $findings = [
            SecurityFinding::critical('Critical', 'Desc', 'test'),
            SecurityFinding::high('High', 'Desc', 'test'),
            SecurityFinding::medium('Medium', 'Desc', 'test'),
        ];

        $benchmarks = [
            new BenchmarkResult(
                name: 'Slow Test',
                withSecurity: ['mean' => 12.0, 'min' => 10.0, 'max' => 14.0, 'stddev' => 1.0],
                withoutSecurity: ['mean' => 10.0, 'min' => 9.0, 'max' => 11.0, 'stddev' => 0.5],
                iterations: 100,
            ),
        ];

        $result = $gate->evaluate($findings, $benchmarks);

        $this->assertFalse($result->passed);
        $this->assertCount(4, $result->failures);
    }

    public function test_fluent_rule_addition(): void
    {
        $gate = (new SecurityGate)
            ->addRule('rule1', fn () => true)
            ->addRule('rule2', fn () => true);

        $result = $gate->evaluate([]);

        $this->assertTrue($result->passed);
    }
}
