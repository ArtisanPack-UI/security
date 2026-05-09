<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\Performance;

class BenchmarkResult
{
    /**
     * Create a new benchmark result.
     *
     * @param  string  $name  Name of the benchmark
     * @param  array<string, float>  $withSecurity  Stats with security enabled
     * @param  array<string, float>  $withoutSecurity  Stats without security
     * @param  int  $iterations  Number of iterations run
     */
    public function __construct(
        public readonly string $name,
        public readonly array $withSecurity,
        public readonly array $withoutSecurity,
        public readonly int $iterations,
    ) {}

    /**
     * Get the overhead percentage.
     */
    public function getOverhead(): float
    {
        $withoutMean = $this->withoutSecurity['mean'] ?? 0;

        if (0 == $withoutMean) {
            return 0;
        }

        $withMean = $this->withSecurity['mean'] ?? 0;

        return (($withMean - $withoutMean) / $withoutMean) * 100;
    }

    /**
     * Get the absolute overhead in milliseconds.
     */
    public function getAbsoluteOverhead(): float
    {
        return ($this->withSecurity['mean'] ?? 0) - ($this->withoutSecurity['mean'] ?? 0);
    }

    /**
     * Check if the overhead is acceptable.
     */
    public function isAcceptable(float $maxOverheadPercent = 10.0): bool
    {
        return $this->getOverhead() <= $maxOverheadPercent;
    }

    /**
     * Get a human-readable summary.
     */
    public function getSummary(): string
    {
        $overhead   = $this->getOverhead();
        $absoluteMs = $this->getAbsoluteOverhead();

        return sprintf(
            '%s: %.2f%% overhead (%.3fms per operation)',
            $this->name,
            $overhead,
            $absoluteMs,
        );
    }

    /**
     * Get detailed statistics comparison.
     *
     * @return array<string, array<string, float>>
     */
    public function getComparison(): array
    {
        return [
            'with_security'    => $this->withSecurity,
            'without_security' => $this->withoutSecurity,
            'difference'       => [
                'mean' => ($this->withSecurity['mean'] ?? 0) - ($this->withoutSecurity['mean'] ?? 0),
                'p95'  => ($this->withSecurity['p95'] ?? 0) - ($this->withoutSecurity['p95'] ?? 0),
                'p99'  => ($this->withSecurity['p99'] ?? 0) - ($this->withoutSecurity['p99'] ?? 0),
            ],
        ];
    }

    /**
     * Convert to array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'name'            => $this->name,
            'iterations'      => $this->iterations,
            'withSecurity'    => $this->withSecurity,
            'withoutSecurity' => $this->withoutSecurity,
            'overhead'        => [
                'percent'     => $this->getOverhead(),
                'absolute_ms' => $this->getAbsoluteOverhead(),
            ],
            'acceptable' => $this->isAcceptable(),
        ];
    }

    /**
     * Format result as a table row.
     *
     * @return array<string>
     */
    public function toTableRow(): array
    {
        return [
            $this->name,
            sprintf('%.3fms', $this->withSecurity['mean'] ?? 0),
            sprintf('%.3fms', $this->withoutSecurity['mean'] ?? 0),
            sprintf('%.2f%%', $this->getOverhead()),
            $this->isAcceptable() ? 'PASS' : 'FAIL',
        ];
    }
}
