<?php

/**
 * SecurityGate CI/CD integration.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\CiCd;

use ArtisanPackUI\Security\Testing\Performance\BenchmarkResult;
use ArtisanPackUI\Security\Testing\Reporting\SecurityFinding;

class SecurityGate
{
    /**
     * Custom rules.
     *
     * @var array<string, callable>
     */
    protected array $rules = [];

    public function __construct(
        protected int $maxCritical = 0,
        protected int $maxHigh = 0,
        protected int $maxMedium = 10,
        protected float $maxOverheadPercent = 15.0,
    ) {}

    /**
     * Add a custom rule.
     *
     * @param  callable  $check  Function that returns true if passed, or error message if failed
     */
    public function addRule(string $name, callable $check): self
    {
        $this->rules[$name] = $check;

        return $this;
    }

    /**
     * Evaluate findings and benchmarks against the gate.
     *
     * @param  array<SecurityFinding>  $findings
     * @param  array<BenchmarkResult>  $benchmarks
     */
    public function evaluate(array $findings, ?array $benchmarks = null): GateResult
    {
        $failures = [];

        // Check severity thresholds
        $critical = $this->countBySeverity($findings, SecurityFinding::SEVERITY_CRITICAL);
        $high     = $this->countBySeverity($findings, SecurityFinding::SEVERITY_HIGH);
        $medium   = $this->countBySeverity($findings, SecurityFinding::SEVERITY_MEDIUM);

        if ($critical > $this->maxCritical) {
            $failures[] = "Critical findings ({$critical}) exceed threshold ({$this->maxCritical})";
        }

        if ($high > $this->maxHigh) {
            $failures[] = "High findings ({$high}) exceed threshold ({$this->maxHigh})";
        }

        if ($medium > $this->maxMedium) {
            $failures[] = "Medium findings ({$medium}) exceed threshold ({$this->maxMedium})";
        }

        // Check performance overhead
        if ($benchmarks) {
            foreach ($benchmarks as $benchmark) {
                $overhead = $benchmark instanceof BenchmarkResult
                    ? $benchmark->getOverhead()
                    : ($benchmark['overhead']['percent'] ?? 0);

                $name = $benchmark instanceof BenchmarkResult
                    ? $benchmark->name
                    : ($benchmark['name'] ?? 'Unknown');

                if ($overhead > $this->maxOverheadPercent) {
                    $failures[] = sprintf(
                        'Performance overhead for %s (%.1f%%) exceeds threshold (%.1f%%)',
                        $name,
                        $overhead,
                        $this->maxOverheadPercent,
                    );
                }
            }
        }

        // Run custom rules
        foreach ($this->rules as $name => $check) {
            $result = $check($findings, $benchmarks);

            if (true !== $result) {
                $failures[] = "Rule '{$name}' failed: {$result}";
            }
        }

        return new GateResult(
            passed: empty($failures),
            failures: $failures,
            summary: [
                'critical' => $critical,
                'high'     => $high,
                'medium'   => $medium,
            ],
        );
    }

    /**
     * Create a strict gate (no critical or high findings allowed).
     */
    public static function strict(): self
    {
        return new self(
            maxCritical: 0,
            maxHigh: 0,
            maxMedium: 5,
            maxOverheadPercent: 10.0,
        );
    }

    /**
     * Create a permissive gate (only blocks on critical).
     */
    public static function permissive(): self
    {
        return new self(
            maxCritical: 0,
            maxHigh: 10,
            maxMedium: 50,
            maxOverheadPercent: 25.0,
        );
    }

    /**
     * Count findings by severity.
     *
     * @param  array<SecurityFinding>  $findings
     */
    protected function countBySeverity(array $findings, string $severity): int
    {
        return count(array_filter($findings, fn ($f) => $f->severity === $severity));
    }
}

class GateResult
{
    public function __construct(
        public readonly bool $passed,
        public readonly array $failures,
        public readonly array $summary,
    ) {}

    /**
     * Get the exit code for CLI.
     */
    public function getExitCode(): int
    {
        return $this->passed ? 0 : 1;
    }

    /**
     * Get failure messages as a string.
     */
    public function getFailureMessage(): string
    {
        if (empty($this->failures)) {
            return '';
        }

        return implode("\n", $this->failures);
    }

    /**
     * Convert to array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'passed'   => $this->passed,
            'failures' => $this->failures,
            'summary'  => $this->summary,
        ];
    }
}
