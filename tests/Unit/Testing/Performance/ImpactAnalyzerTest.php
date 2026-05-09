<?php

declare(strict_types=1);

namespace Tests\Unit\Testing\Performance;

use ArtisanPackUI\Security\Testing\Performance\BenchmarkResult;
use ArtisanPackUI\Security\Testing\Performance\ImpactAnalyzer;
use Tests\TestCase;

class ImpactAnalyzerTest extends TestCase
{
    public function test_can_create_analyzer_with_results(): void
    {
        $results = [
            $this->createAcceptableResult('Test 1'),
            $this->createAcceptableResult('Test 2'),
        ];

        $analyzer = new ImpactAnalyzer($results);

        $this->assertInstanceOf(ImpactAnalyzer::class, $analyzer);
    }

    public function test_is_acceptable_when_all_results_pass(): void
    {
        $results = [
            $this->createAcceptableResult('Test 1'),
            $this->createAcceptableResult('Test 2'),
            $this->createAcceptableResult('Test 3'),
        ];

        $analyzer = new ImpactAnalyzer($results);

        $this->assertTrue($analyzer->isAcceptable());
    }

    public function test_is_not_acceptable_when_any_result_fails(): void
    {
        $results = [
            $this->createAcceptableResult('Test 1'),
            $this->createUnacceptableResult('Test 2'),
            $this->createAcceptableResult('Test 3'),
        ];

        $analyzer = new ImpactAnalyzer($results);

        $this->assertFalse($analyzer->isAcceptable());
    }

    public function test_gets_summary_with_counts(): void
    {
        $results = [
            $this->createAcceptableResult('Test 1'),
            $this->createUnacceptableResult('Test 2'),
            $this->createAcceptableResult('Test 3'),
        ];

        $analyzer = new ImpactAnalyzer($results);
        $summary  = $analyzer->getSummary();

        $this->assertEquals(3, $summary['total_benchmarks']);
        $this->assertEquals(2, $summary['acceptable']);
        $this->assertEquals(1, $summary['unacceptable']);
    }

    public function test_gets_summary_with_pass_rate(): void
    {
        $results = [
            $this->createAcceptableResult('Test 1'),
            $this->createAcceptableResult('Test 2'),
            $this->createUnacceptableResult('Test 3'),
        ];

        $analyzer = new ImpactAnalyzer($results);
        $summary  = $analyzer->getSummary();

        // 2 out of 3 pass = 66.67%
        $this->assertEqualsWithDelta(66.67, $summary['pass_rate'], 0.01);
    }

    public function test_calculates_average_overhead(): void
    {
        // 5% overhead
        $acceptable = new BenchmarkResult(
            name: 'Acceptable',
            withSecurity: ['mean' => 10.5],
            withoutSecurity: ['mean' => 10.0],
            iterations: 100,
        );

        // 150% overhead
        $unacceptable = new BenchmarkResult(
            name: 'Unacceptable',
            withSecurity: ['mean' => 25.0],
            withoutSecurity: ['mean' => 10.0],
            iterations: 100,
        );

        $analyzer = new ImpactAnalyzer([$acceptable, $unacceptable]);
        $summary  = $analyzer->getSummary();

        // Average of 5% and 150% = 77.5%
        $this->assertEqualsWithDelta(77.5, $summary['average_overhead'], 0.1);
    }

    public function test_gets_recommendations_for_failed_results(): void
    {
        $results = [
            $this->createAcceptableResult('Encryption'),
            $this->createUnacceptableResult('Hashing'),
        ];

        $analyzer        = new ImpactAnalyzer($results);
        $recommendations = $analyzer->getRecommendations();

        $this->assertArrayHasKey('Hashing', $recommendations);
        $this->assertArrayNotHasKey('Encryption', $recommendations);
    }

    public function test_no_recommendations_when_all_pass(): void
    {
        $results = [
            $this->createAcceptableResult('Test 1'),
            $this->createAcceptableResult('Test 2'),
        ];

        $analyzer        = new ImpactAnalyzer($results);
        $recommendations = $analyzer->getRecommendations();

        $this->assertEmpty($recommendations);
    }

    public function test_handles_empty_results(): void
    {
        $analyzer = new ImpactAnalyzer([]);
        $summary  = $analyzer->getSummary();

        $this->assertEquals(0, $summary['total_benchmarks']);
        $this->assertEquals(0, $summary['acceptable']);
        $this->assertEquals(0, $summary['unacceptable']);
        $this->assertEquals(0.0, $summary['average_overhead']);
        $this->assertTrue($analyzer->isAcceptable());
    }

    public function test_applies_custom_thresholds(): void
    {
        $results = [
            new BenchmarkResult(
                name: 'Encryption Test',
                withSecurity: ['mean' => 20.0],
                withoutSecurity: ['mean' => 10.0],
                iterations: 100,
            ),
        ];

        // 100% overhead, custom threshold of 150% for encryption
        $analyzer = new ImpactAnalyzer($results, ['encryption' => 150.0]);

        $this->assertTrue($analyzer->isAcceptable());
    }

    public function test_set_threshold_method(): void
    {
        $results = [
            $this->createUnacceptableResult('Test'),
        ];

        $analyzer = new ImpactAnalyzer($results);
        $analyzer->setThreshold('default', 200.0);

        $this->assertTrue($analyzer->isAcceptable());
    }

    public function test_add_results_method(): void
    {
        $analyzer = new ImpactAnalyzer;
        $analyzer->addResults([
            $this->createAcceptableResult('Test 1'),
            $this->createAcceptableResult('Test 2'),
        ]);

        $summary = $analyzer->getSummary();
        $this->assertEquals(2, $summary['total_benchmarks']);
    }

    public function test_passes_with_100_percent_rate(): void
    {
        $results = [
            $this->createAcceptableResult('Test 1'),
            $this->createAcceptableResult('Test 2'),
            $this->createAcceptableResult('Test 3'),
        ];

        $analyzer = new ImpactAnalyzer($results);
        $summary  = $analyzer->getSummary();

        $this->assertEquals(100.0, $summary['pass_rate']);
    }

    public function test_analyze_returns_security_findings(): void
    {
        $results = [
            $this->createUnacceptableResult('Slow Test'),
        ];

        $analyzer = new ImpactAnalyzer($results);
        $findings = $analyzer->analyze();

        $this->assertNotEmpty($findings);
        $this->assertEquals('Performance Impact', $findings[0]->category);
    }

    public function test_to_array_export(): void
    {
        $results = [
            $this->createAcceptableResult('Test'),
        ];

        $analyzer = new ImpactAnalyzer($results);
        $export   = $analyzer->toArray();

        $this->assertArrayHasKey('summary', $export);
        $this->assertArrayHasKey('recommendations', $export);
        $this->assertArrayHasKey('findings', $export);
    }

    public function test_middleware_threshold_applied(): void
    {
        $middlewareResult = new BenchmarkResult(
            name: 'Middleware Test',
            withSecurity: ['mean' => 10.6], // 6% overhead
            withoutSecurity: ['mean' => 10.0],
            iterations: 100,
        );

        // Default middleware threshold is 5%, so 6% should fail
        $analyzer = new ImpactAnalyzer([$middlewareResult]);

        $this->assertFalse($analyzer->isAcceptable());
    }

    protected function createAcceptableResult(string $name): BenchmarkResult
    {
        return new BenchmarkResult(
            name: $name,
            withSecurity: ['mean' => 10.5, 'min' => 10.0, 'max' => 11.0, 'stddev' => 0.25],
            withoutSecurity: ['mean' => 10.0, 'min' => 9.0, 'max' => 11.0, 'stddev' => 0.5],
            iterations: 100,
        );
    }

    protected function createUnacceptableResult(string $name): BenchmarkResult
    {
        return new BenchmarkResult(
            name: $name,
            withSecurity: ['mean' => 25.0, 'min' => 20.0, 'max' => 30.0, 'stddev' => 2.5],
            withoutSecurity: ['mean' => 10.0, 'min' => 9.0, 'max' => 11.0, 'stddev' => 0.5],
            iterations: 100,
        );
    }
}
