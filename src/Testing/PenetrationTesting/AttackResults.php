<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\PenetrationTesting;

class AttackResults
{
    /**
     * Create a new attack results collection.
     *
     * @param  array<AttackResult>  $results
     */
    public function __construct(
        protected array $results = [],
    ) {}

    /**
     * Add a result.
     */
    public function add(AttackResult $result): self
    {
        $this->results[] = $result;

        return $this;
    }

    /**
     * Check if any attacks found vulnerabilities.
     */
    public function hasVulnerabilities(): bool
    {
        foreach ($this->results as $result) {
            if ($result->vulnerable) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if any critical vulnerabilities were found.
     */
    public function hasCritical(): bool
    {
        foreach ($this->results as $result) {
            if ($result->isCritical()) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if any blocking vulnerabilities were found (critical or high).
     */
    public function hasBlocking(): bool
    {
        foreach ($this->results as $result) {
            if ($result->isBlocking()) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get all vulnerable results.
     *
     * @return array<AttackResult>
     */
    public function getVulnerable(): array
    {
        return array_filter($this->results, fn (AttackResult $r) => $r->vulnerable);
    }

    /**
     * Get results by severity.
     *
     * @return array<AttackResult>
     */
    public function getBySeverity(string $severity): array
    {
        return array_filter($this->results, fn (AttackResult $r) => $r->severity === $severity);
    }

    /**
     * Get all results.
     *
     * @return array<AttackResult>
     */
    public function all(): array
    {
        return $this->results;
    }

    /**
     * Get total vulnerability count.
     */
    public function getTotalVulnerabilities(): int
    {
        $count = 0;
        foreach ($this->results as $result) {
            if ($result->vulnerable) {
                $count += max(1, $result->getFindingCount());
            }
        }

        return $count;
    }

    /**
     * Get summary statistics.
     *
     * @return array<string, mixed>
     */
    public function getSummary(): array
    {
        $summary = [
            'total_attacks'  => count($this->results),
            'vulnerable'     => 0,
            'not_vulnerable' => 0,
            'by_severity'    => [
                'critical' => 0,
                'high'     => 0,
                'medium'   => 0,
                'low'      => 0,
            ],
        ];

        foreach ($this->results as $result) {
            if ($result->vulnerable) {
                $summary['vulnerable']++;
                $summary['by_severity'][$result->severity] =
                    ($summary['by_severity'][$result->severity] ?? 0) + 1;
            } else {
                $summary['not_vulnerable']++;
            }
        }

        return $summary;
    }

    /**
     * Convert to array.
     *
     * @return array<array<string, mixed>>
     */
    public function toArray(): array
    {
        return array_map(fn (AttackResult $r) => $r->toArray(), $this->results);
    }
}
