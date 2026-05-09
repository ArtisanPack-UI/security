<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\Performance;

use ArtisanPackUI\Security\Testing\Reporting\SecurityFinding;

class ImpactAnalyzer
{
    /**
     * Acceptable overhead thresholds by component type.
     *
     * @var array<string, float>
     */
    protected array $thresholds = [
        'middleware' => 5.0,      // Max 5% for middleware
        'validation' => 10.0,     // Max 10% for validation
        'encryption' => 50.0,     // Higher tolerance for crypto
        'hashing'    => 100.0,       // Hashing is intentionally slow
        'default'    => 15.0,        // Default threshold
    ];

    /**
     * Benchmark results to analyze.
     *
     * @var array<BenchmarkResult>
     */
    protected array $results = [];

    /**
     * Create a new impact analyzer.
     *
     * @param  array<BenchmarkResult>  $results
     * @param  array<string, float>  $customThresholds
     */
    public function __construct(array $results = [], array $customThresholds = [])
    {
        $this->results    = $results;
        $this->thresholds = array_merge($this->thresholds, $customThresholds);
    }

    /**
     * Add benchmark results.
     *
     * @param  array<BenchmarkResult>  $results
     */
    public function addResults(array $results): self
    {
        $this->results = array_merge($this->results, $results);

        return $this;
    }

    /**
     * Set a custom threshold.
     */
    public function setThreshold(string $type, float $maxOverhead): self
    {
        $this->thresholds[$type] = $maxOverhead;

        return $this;
    }

    /**
     * Analyze all results and return findings.
     *
     * @return array<SecurityFinding>
     */
    public function analyze(): array
    {
        $findings = [];

        foreach ($this->results as $result) {
            $threshold = $this->getThresholdFor($result->name);
            $overhead  = $result->getOverhead();

            if ($overhead > $threshold) {
                $findings[] = SecurityFinding::medium(
                    'Performance Impact Exceeded',
                    sprintf(
                        '%s has %.2f%% overhead (threshold: %.2f%%)',
                        $result->name,
                        $overhead,
                        $threshold,
                    ),
                    'Performance Impact',
                    $result->name,
                    'Consider optimizing or reviewing if this security feature is necessary',
                );
            }
        }

        return $findings;
    }

    /**
     * Get the overall impact summary.
     *
     * @return array<string, mixed>
     */
    public function getSummary(): array
    {
        $totalOverhead     = 0;
        $acceptableCount   = 0;
        $unacceptableCount = 0;
        $details           = [];

        foreach ($this->results as $result) {
            $threshold  = $this->getThresholdFor($result->name);
            $overhead   = $result->getOverhead();
            $acceptable = $overhead <= $threshold;

            $totalOverhead += $overhead;

            if ($acceptable) {
                $acceptableCount++;
            } else {
                $unacceptableCount++;
            }

            $details[] = [
                'name'       => $result->name,
                'overhead'   => $overhead,
                'threshold'  => $threshold,
                'acceptable' => $acceptable,
            ];
        }

        $count = count($this->results);

        return [
            'total_benchmarks' => $count,
            'average_overhead' => $count > 0 ? $totalOverhead / $count : 0,
            'acceptable'       => $acceptableCount,
            'unacceptable'     => $unacceptableCount,
            'pass_rate'        => $count > 0 ? ($acceptableCount / $count) * 100 : 100,
            'details'          => $details,
        ];
    }

    /**
     * Check if all results are within acceptable thresholds.
     */
    public function isAcceptable(): bool
    {
        foreach ($this->results as $result) {
            $threshold = $this->getThresholdFor($result->name);

            if ($result->getOverhead() > $threshold) {
                return false;
            }
        }

        return true;
    }

    /**
     * Get recommendations for high-overhead components.
     *
     * @return array<string, string>
     */
    public function getRecommendations(): array
    {
        $recommendations = [];

        foreach ($this->results as $result) {
            $threshold = $this->getThresholdFor($result->name);
            $overhead  = $result->getOverhead();

            if ($overhead > $threshold) {
                $recommendations[$result->name] = $this->generateRecommendation($result, $overhead, $threshold);
            }
        }

        return $recommendations;
    }

    /**
     * Export analysis to array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'summary'         => $this->getSummary(),
            'recommendations' => $this->getRecommendations(),
            'findings'        => array_map(fn ($f) => $f->toArray(), $this->analyze()),
        ];
    }

    /**
     * Get the threshold for a benchmark based on its name.
     */
    protected function getThresholdFor(string $name): float
    {
        $nameLower = strtolower($name);

        if (str_contains($nameLower, 'middleware')) {
            return $this->thresholds['middleware'];
        }

        if (str_contains($nameLower, 'validation')) {
            return $this->thresholds['validation'];
        }

        if (str_contains($nameLower, 'encrypt')) {
            return $this->thresholds['encryption'];
        }

        if (str_contains($nameLower, 'hash')) {
            return $this->thresholds['hashing'];
        }

        return $this->thresholds['default'];
    }

    /**
     * Generate a recommendation for a high-overhead component.
     */
    protected function generateRecommendation(BenchmarkResult $result, float $overhead, float $threshold): string
    {
        $absoluteMs = $result->getAbsoluteOverhead();
        $name       = strtolower($result->name);

        if (str_contains($name, 'middleware')) {
            return sprintf(
                'Middleware adds %.3fms per request (%.1f%% overhead). Consider: '.
                '1) Caching expensive computations, '.
                '2) Moving checks to route-specific middleware, '.
                '3) Using lazy evaluation where possible.',
                $absoluteMs,
                $overhead,
            );
        }

        if (str_contains($name, 'validation')) {
            return sprintf(
                'Validation adds %.3fms (%.1f%% overhead). Consider: '.
                '1) Simplifying complex rules, '.
                '2) Caching compiled rules, '.
                '3) Using early-exit validation.',
                $absoluteMs,
                $overhead,
            );
        }

        if (str_contains($name, 'encrypt')) {
            return sprintf(
                'Encryption adds %.3fms (%.1f%% overhead). This is expected for cryptographic operations. '.
                'Ensure encryption is only used where necessary.',
                $absoluteMs,
                $overhead,
            );
        }

        return sprintf(
            '%s adds %.3fms (%.1f%% overhead, threshold: %.1f%%). Review for optimization opportunities.',
            $result->name,
            $absoluteMs,
            $overhead,
            $threshold,
        );
    }
}
