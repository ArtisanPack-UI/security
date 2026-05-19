<?php

declare(strict_types=1);

namespace Tests\Unit\Testing\Performance;

use ArtisanPackUI\Security\Testing\Performance\BenchmarkResult;
use Tests\TestCase;

class BenchmarkResultTest extends TestCase
{
    public function test_can_create_benchmark_result(): void
    {
        $withSecurity = [
            'mean'   => 10.5,
            'min'    => 8.0,
            'max'    => 15.0,
            'stddev' => 2.5,
        ];

        $withoutSecurity = [
            'mean'   => 5.0,
            'min'    => 4.0,
            'max'    => 7.0,
            'stddev' => 1.0,
        ];

        $result = new BenchmarkResult(
            name: 'Test Benchmark',
            withSecurity: $withSecurity,
            withoutSecurity: $withoutSecurity,
            iterations: 1000,
        );

        $this->assertEquals('Test Benchmark', $result->name);
        $this->assertEquals(1000, $result->iterations);
        $this->assertEquals($withSecurity, $result->withSecurity);
        $this->assertEquals($withoutSecurity, $result->withoutSecurity);
    }

    public function test_calculates_overhead_percentage(): void
    {
        $result = new BenchmarkResult(
            name: 'Overhead Test',
            withSecurity: ['mean' => 12.0, 'min' => 10.0, 'max' => 14.0, 'stddev' => 1.0],
            withoutSecurity: ['mean' => 10.0, 'min' => 9.0, 'max' => 11.0, 'stddev' => 0.5],
            iterations: 100,
        );

        // Overhead = ((12.0 - 10.0) / 10.0) * 100 = 20%
        $this->assertEquals(20.0, $result->getOverhead());
    }

    public function test_overhead_is_zero_when_baseline_is_zero(): void
    {
        $result = new BenchmarkResult(
            name: 'Zero Baseline',
            withSecurity: ['mean' => 5.0, 'min' => 4.0, 'max' => 6.0, 'stddev' => 0.5],
            withoutSecurity: ['mean' => 0.0, 'min' => 0.0, 'max' => 0.0, 'stddev' => 0.0],
            iterations: 100,
        );

        $this->assertEquals(0.0, $result->getOverhead());
    }

    public function test_is_acceptable_when_under_threshold(): void
    {
        $result = new BenchmarkResult(
            name: 'Acceptable Test',
            withSecurity: ['mean' => 11.0, 'min' => 10.0, 'max' => 12.0, 'stddev' => 0.5],
            withoutSecurity: ['mean' => 10.0, 'min' => 9.0, 'max' => 11.0, 'stddev' => 0.5],
            iterations: 100,
        );

        // Overhead = 10%, threshold = 15%
        $this->assertTrue($result->isAcceptable(15.0));
    }

    public function test_is_not_acceptable_when_over_threshold(): void
    {
        $result = new BenchmarkResult(
            name: 'Not Acceptable Test',
            withSecurity: ['mean' => 12.0, 'min' => 10.0, 'max' => 14.0, 'stddev' => 1.0],
            withoutSecurity: ['mean' => 10.0, 'min' => 9.0, 'max' => 11.0, 'stddev' => 0.5],
            iterations: 100,
        );

        // Overhead = 20%, threshold = 15%
        $this->assertFalse($result->isAcceptable(15.0));
    }

    public function test_is_acceptable_when_equal_to_threshold(): void
    {
        $result = new BenchmarkResult(
            name: 'Equal Threshold Test',
            withSecurity: ['mean' => 11.5, 'min' => 10.0, 'max' => 13.0, 'stddev' => 0.75],
            withoutSecurity: ['mean' => 10.0, 'min' => 9.0, 'max' => 11.0, 'stddev' => 0.5],
            iterations: 100,
        );

        // Overhead = 15%, threshold = 15%
        $this->assertTrue($result->isAcceptable(15.0));
    }

    public function test_converts_to_array(): void
    {
        $result = new BenchmarkResult(
            name: 'Array Test',
            withSecurity: ['mean' => 12.0, 'min' => 10.0, 'max' => 14.0, 'stddev' => 1.0],
            withoutSecurity: ['mean' => 10.0, 'min' => 9.0, 'max' => 11.0, 'stddev' => 0.5],
            iterations: 500,
        );

        $array = $result->toArray();

        $this->assertArrayHasKey('name', $array);
        $this->assertArrayHasKey('iterations', $array);
        $this->assertArrayHasKey('withSecurity', $array);
        $this->assertArrayHasKey('withoutSecurity', $array);
        $this->assertArrayHasKey('overhead', $array);
        $this->assertArrayHasKey('acceptable', $array);

        $this->assertEquals('Array Test', $array['name']);
        $this->assertEquals(500, $array['iterations']);
        $this->assertEquals(20.0, $array['overhead']['percent']);
    }

    public function test_overhead_array_includes_absolute_value(): void
    {
        $result = new BenchmarkResult(
            name: 'Absolute Test',
            withSecurity: ['mean' => 15.0, 'min' => 12.0, 'max' => 18.0, 'stddev' => 1.5],
            withoutSecurity: ['mean' => 10.0, 'min' => 8.0, 'max' => 12.0, 'stddev' => 1.0],
            iterations: 100,
        );

        $array = $result->toArray();

        // Absolute overhead = 15.0 - 10.0 = 5.0
        $this->assertEquals(5.0, $array['overhead']['absolute_ms']);
        // Percent overhead = 50%
        $this->assertEquals(50.0, $array['overhead']['percent']);
    }

    public function test_handles_negative_overhead(): void
    {
        // Security actually improves performance (unlikely but possible)
        $result = new BenchmarkResult(
            name: 'Negative Overhead',
            withSecurity: ['mean' => 8.0, 'min' => 7.0, 'max' => 9.0, 'stddev' => 0.5],
            withoutSecurity: ['mean' => 10.0, 'min' => 9.0, 'max' => 11.0, 'stddev' => 0.5],
            iterations: 100,
        );

        // Overhead = ((8.0 - 10.0) / 10.0) * 100 = -20%
        $this->assertEquals(-20.0, $result->getOverhead());
        $this->assertTrue($result->isAcceptable(15.0));
    }

    public function test_get_absolute_overhead(): void
    {
        $result = new BenchmarkResult(
            name: 'Absolute Test',
            withSecurity: ['mean' => 15.0],
            withoutSecurity: ['mean' => 10.0],
            iterations: 100,
        );

        $this->assertEquals(5.0, $result->getAbsoluteOverhead());
    }

    public function test_get_summary(): void
    {
        $result = new BenchmarkResult(
            name: 'Summary Test',
            withSecurity: ['mean' => 12.0],
            withoutSecurity: ['mean' => 10.0],
            iterations: 100,
        );

        $summary = $result->getSummary();

        $this->assertStringContainsString('Summary Test', $summary);
        $this->assertStringContainsString('20.00%', $summary);
        $this->assertStringContainsString('overhead', $summary);
    }

    public function test_get_comparison(): void
    {
        $result = new BenchmarkResult(
            name: 'Comparison Test',
            withSecurity: ['mean' => 15.0, 'p95' => 20.0, 'p99' => 25.0],
            withoutSecurity: ['mean' => 10.0, 'p95' => 15.0, 'p99' => 18.0],
            iterations: 100,
        );

        $comparison = $result->getComparison();

        $this->assertEquals(5.0, $comparison['difference']['mean']);
        $this->assertEquals(5.0, $comparison['difference']['p95']);
        $this->assertEquals(7.0, $comparison['difference']['p99']);
    }

    public function test_to_table_row(): void
    {
        $result = new BenchmarkResult(
            name: 'Table Test',
            withSecurity: ['mean' => 12.0],
            withoutSecurity: ['mean' => 10.0],
            iterations: 100,
        );

        $row = $result->toTableRow();

        $this->assertCount(5, $row);
        $this->assertEquals('Table Test', $row[0]);
        $this->assertStringContainsString('12.000ms', $row[1]);
        $this->assertStringContainsString('10.000ms', $row[2]);
        $this->assertStringContainsString('20.00%', $row[3]);
    }

    public function test_default_acceptable_threshold(): void
    {
        $result = new BenchmarkResult(
            name: 'Default Threshold Test',
            withSecurity: ['mean' => 11.0],
            withoutSecurity: ['mean' => 10.0],
            iterations: 100,
        );

        // Default threshold is 10%
        $this->assertTrue($result->isAcceptable());
    }
}
