<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\Performance;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class SecurityBenchmark
{
    /**
     * Benchmark results.
     *
     * @var array<BenchmarkResult>
     */
    protected array $results = [];

    /**
     * Benchmark a security feature's performance impact.
     */
    public function benchmark(
        string $name,
        callable $withSecurity,
        callable $withoutSecurity,
        int $iterations = 1000,
    ): BenchmarkResult {
        // Warmup
        for ($i = 0; $i < 10; $i++) {
            $withSecurity();
            $withoutSecurity();
        }

        // Force garbage collection
        gc_collect_cycles();

        // Benchmark with security
        $withSecurityTimes = [];
        for ($i = 0; $i < $iterations; $i++) {
            $start = hrtime(true);
            $withSecurity();
            $withSecurityTimes[] = hrtime(true) - $start;
        }

        gc_collect_cycles();

        // Benchmark without security
        $withoutSecurityTimes = [];
        for ($i = 0; $i < $iterations; $i++) {
            $start = hrtime(true);
            $withoutSecurity();
            $withoutSecurityTimes[] = hrtime(true) - $start;
        }

        $result = new BenchmarkResult(
            name: $name,
            withSecurity: $this->calculateStats($withSecurityTimes),
            withoutSecurity: $this->calculateStats($withoutSecurityTimes),
            iterations: $iterations,
        );

        $this->results[] = $result;

        return $result;
    }

    /**
     * Benchmark middleware performance.
     */
    public function benchmarkMiddleware(
        string $middlewareClass,
        ?Request $request = null,
        int $iterations = 1000,
    ): BenchmarkResult {
        $request ??= Request::create('/test', 'GET');
        $middleware  = app($middlewareClass);
        $passthrough = fn ($r) => response('OK');

        return $this->benchmark(
            name: "Middleware: {$middlewareClass}",
            withSecurity: fn () => $middleware->handle(clone $request, $passthrough),
            withoutSecurity: fn () => $passthrough(clone $request),
            iterations: $iterations,
        );
    }

    /**
     * Benchmark validation rule performance.
     */
    public function benchmarkValidation(
        string $rule,
        mixed $value,
        int $iterations = 1000,
    ): BenchmarkResult {
        return $this->benchmark(
            name: "Validation: {$rule}",
            withSecurity: fn () => Validator::make(['field' => $value], ['field' => $rule])->passes(),
            withoutSecurity: fn () => true,
            iterations: $iterations,
        );
    }

    /**
     * Benchmark encryption/decryption performance.
     */
    public function benchmarkEncryption(
        string $data,
        int $iterations = 1000,
    ): BenchmarkResult {
        return $this->benchmark(
            name: 'Encryption/Decryption',
            withSecurity: function () use ($data): void {
                $encrypted = encrypt($data);
                decrypt($encrypted);
            },
            withoutSecurity: fn () => $data,
            iterations: $iterations,
        );
    }

    /**
     * Benchmark hashing performance.
     */
    public function benchmarkHashing(
        string $password,
        int $iterations = 100, // Fewer iterations for hashing as it's intentionally slow
    ): BenchmarkResult {
        return $this->benchmark(
            name: 'Password Hashing',
            withSecurity: fn () => bcrypt($password),
            withoutSecurity: fn () => md5($password), // Insecure comparison
            iterations: $iterations,
        );
    }

    /**
     * Benchmark nonce generation.
     */
    public function benchmarkNonceGeneration(int $iterations = 1000): BenchmarkResult
    {
        return $this->benchmark(
            name: 'Nonce Generation',
            withSecurity: fn () => bin2hex(random_bytes(16)),
            withoutSecurity: fn () => uniqid(), // Insecure comparison
            iterations: $iterations,
        );
    }

    /**
     * Run a full benchmark suite.
     *
     * @return array<BenchmarkResult>
     */
    public function runFullSuite(): array
    {
        $this->results = [];

        // Benchmark common security operations
        $this->benchmarkEncryption('Test data for encryption benchmarking');
        $this->benchmarkHashing('SecurePassword123!');
        $this->benchmarkNonceGeneration();
        $this->benchmarkValidation('required|string|min:8', 'testvalue');

        return $this->results;
    }

    /**
     * Get all benchmark results.
     *
     * @return array<BenchmarkResult>
     */
    public function getResults(): array
    {
        return $this->results;
    }

    /**
     * Generate a report from all results.
     *
     * @return array<array<string, mixed>>
     */
    public function generateReport(): array
    {
        return array_map(fn (BenchmarkResult $r) => $r->toArray(), $this->results);
    }

    /**
     * Clear all results.
     */
    public function clearResults(): self
    {
        $this->results = [];

        return $this;
    }

    /**
     * Check if all benchmarks are within acceptable overhead.
     */
    public function allWithinThreshold(float $maxOverheadPercent = 10.0): bool
    {
        foreach ($this->results as $result) {
            if (! $result->isAcceptable($maxOverheadPercent)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Calculate statistics from timing data.
     *
     * @param  array<int>  $times  Times in nanoseconds
     *
     * @return array<string, float>
     */
    protected function calculateStats(array $times): array
    {
        sort($times);
        $count = count($times);

        if (0 === $count) {
            return [
                'min'    => 0,
                'max'    => 0,
                'mean'   => 0,
                'median' => 0,
                'p95'    => 0,
                'p99'    => 0,
                'stddev' => 0,
            ];
        }

        $sum  = array_sum($times);
        $mean = $sum / $count;

        // Calculate standard deviation
        $squaredDiffs = array_map(fn ($t) => pow($t - $mean, 2), $times);
        $stddev       = sqrt(array_sum($squaredDiffs) / $count);

        return [
            'min'    => min($times) / 1e6,         // Convert to ms
            'max'    => max($times) / 1e6,
            'mean'   => $mean / 1e6,
            'median' => $times[(int) ($count / 2)] / 1e6,
            'p95'    => $times[(int) ($count * 0.95)] / 1e6,
            'p99'    => $times[(int) ($count * 0.99)] / 1e6,
            'stddev' => $stddev / 1e6,
        ];
    }
}
