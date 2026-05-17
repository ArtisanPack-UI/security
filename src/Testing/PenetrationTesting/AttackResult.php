<?php

/**
 * AttackResult penetration-testing support class.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\PenetrationTesting;

class AttackResult
{
    /**
     * Create a new attack result.
     *
     * @param  string  $attack  The attack type name
     * @param  bool  $vulnerable  Whether the target is vulnerable
     * @param  array<array<string, mixed>>  $findings  Detailed findings
     * @param  string  $severity  Severity level (critical, high, medium, low, none)
     * @param  array<string, mixed>  $metadata  Additional metadata
     */
    public function __construct(
        public readonly string $attack,
        public readonly bool $vulnerable,
        public readonly array $findings = [],
        public readonly string $severity = 'none',
        public readonly array $metadata = [],
    ) {}

    /**
     * Create a vulnerable result.
     *
     * @param  array<array<string, mixed>>  $findings
     * @param  array<string, mixed>  $metadata
     */
    public static function vulnerable(
        string $attack,
        string $severity,
        array $findings = [],
        array $metadata = [],
    ): self {
        return new self(
            attack: $attack,
            vulnerable: true,
            findings: $findings,
            severity: $severity,
            metadata: $metadata,
        );
    }

    /**
     * Create a not vulnerable result.
     *
     * @param  array<string, mixed>  $metadata
     */
    public static function notVulnerable(string $attack, array $metadata = []): self
    {
        return new self(
            attack: $attack,
            vulnerable: false,
            findings: [],
            severity: 'none',
            metadata: $metadata,
        );
    }

    /**
     * Check if the attack found a critical vulnerability.
     */
    public function isCritical(): bool
    {
        return $this->vulnerable && 'critical' === $this->severity;
    }

    /**
     * Check if the attack found a high severity vulnerability.
     */
    public function isHigh(): bool
    {
        return $this->vulnerable && 'high' === $this->severity;
    }

    /**
     * Check if the attack found a blocking vulnerability (critical or high).
     */
    public function isBlocking(): bool
    {
        return $this->vulnerable && in_array($this->severity, ['critical', 'high']);
    }

    /**
     * Get the number of findings.
     */
    public function getFindingCount(): int
    {
        return count($this->findings);
    }

    /**
     * Convert to array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'attack'       => $this->attack,
            'vulnerable'   => $this->vulnerable,
            'severity'     => $this->severity,
            'findings'     => $this->findings,
            'findingCount' => $this->getFindingCount(),
            'metadata'     => $this->metadata,
        ];
    }
}
