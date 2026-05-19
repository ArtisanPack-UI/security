<?php

/**
 * SecurityFinding testing-report support class.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\Reporting;

class SecurityFinding
{
    public const SEVERITY_CRITICAL = 'critical';

    public const SEVERITY_HIGH = 'high';

    public const SEVERITY_MEDIUM = 'medium';

    public const SEVERITY_LOW = 'low';

    public const SEVERITY_INFO = 'info';

    public function __construct(
        public readonly string $id,
        public readonly string $title,
        public readonly string $description,
        public readonly string $severity,
        public readonly string $category,
        public readonly ?string $location = null,
        public readonly ?string $evidence = null,
        public readonly ?string $remediation = null,
        public readonly array $metadata = [],
    ) {}

    /**
     * Create a critical severity finding.
     */
    public static function critical(
        string $title,
        string $description,
        string $category,
        ?string $location = null,
        ?string $remediation = null,
    ): self {
        return new self(
            id: self::generateId(),
            title: $title,
            description: $description,
            severity: self::SEVERITY_CRITICAL,
            category: $category,
            location: $location,
            remediation: $remediation,
        );
    }

    /**
     * Create a high severity finding.
     */
    public static function high(
        string $title,
        string $description,
        string $category,
        ?string $location = null,
        ?string $remediation = null,
    ): self {
        return new self(
            id: self::generateId(),
            title: $title,
            description: $description,
            severity: self::SEVERITY_HIGH,
            category: $category,
            location: $location,
            remediation: $remediation,
        );
    }

    /**
     * Create a medium severity finding.
     */
    public static function medium(
        string $title,
        string $description,
        string $category,
        ?string $location = null,
        ?string $remediation = null,
    ): self {
        return new self(
            id: self::generateId(),
            title: $title,
            description: $description,
            severity: self::SEVERITY_MEDIUM,
            category: $category,
            location: $location,
            remediation: $remediation,
        );
    }

    /**
     * Create a low severity finding.
     */
    public static function low(
        string $title,
        string $description,
        string $category,
        ?string $location = null,
        ?string $remediation = null,
    ): self {
        return new self(
            id: self::generateId(),
            title: $title,
            description: $description,
            severity: self::SEVERITY_LOW,
            category: $category,
            location: $location,
            remediation: $remediation,
        );
    }

    /**
     * Create an info severity finding.
     */
    public static function info(
        string $title,
        string $description,
        string $category,
        ?string $location = null,
        ?string $remediation = null,
    ): self {
        return new self(
            id: self::generateId(),
            title: $title,
            description: $description,
            severity: self::SEVERITY_INFO,
            category: $category,
            location: $location,
            remediation: $remediation,
        );
    }

    /**
     * Create a finding from a vulnerability array.
     *
     * @param  array<string, mixed>  $vulnerability
     */
    public static function fromVulnerability(array $vulnerability): self
    {
        return new self(
            id: $vulnerability['id'] ?? self::generateId(),
            title: $vulnerability['title'] ?? 'Unknown Vulnerability',
            description: $vulnerability['description'] ?? '',
            severity: $vulnerability['severity'] ?? self::SEVERITY_MEDIUM,
            category: $vulnerability['category'] ?? 'unknown',
            location: $vulnerability['location'] ?? null,
            evidence: $vulnerability['evidence'] ?? null,
            remediation: $vulnerability['remediation'] ?? null,
            metadata: $vulnerability['metadata'] ?? [],
        );
    }

    /**
     * Check if this is a critical finding.
     */
    public function isCritical(): bool
    {
        return self::SEVERITY_CRITICAL === $this->severity;
    }

    /**
     * Check if this is a high severity finding.
     */
    public function isHigh(): bool
    {
        return self::SEVERITY_HIGH === $this->severity;
    }

    /**
     * Check if this is a blocking finding (critical or high).
     */
    public function isBlocking(): bool
    {
        return $this->isCritical() || $this->isHigh();
    }

    /**
     * Get the severity order for sorting.
     */
    public function getSeverityOrder(): int
    {
        return match ($this->severity) {
            self::SEVERITY_CRITICAL => 0,
            self::SEVERITY_HIGH     => 1,
            self::SEVERITY_MEDIUM   => 2,
            self::SEVERITY_LOW      => 3,
            self::SEVERITY_INFO     => 4,
            default                 => 5,
        };
    }

    /**
     * Convert the finding to an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id'          => $this->id,
            'title'       => $this->title,
            'description' => $this->description,
            'severity'    => $this->severity,
            'category'    => $this->category,
            'location'    => $this->location,
            'evidence'    => $this->evidence,
            'remediation' => $this->remediation,
            'metadata'    => $this->metadata,
        ];
    }

    /**
     * Generate a unique finding ID.
     */
    protected static function generateId(): string
    {
        return 'SEC-'.strtoupper(bin2hex(random_bytes(4)));
    }
}
