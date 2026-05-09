<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\Reporting;

use ArtisanPackUI\Security\Contracts\SecurityReportInterface;
use ArtisanPackUI\Security\Testing\Reporting\Formats\HtmlReportFormat;
use ArtisanPackUI\Security\Testing\Reporting\Formats\JsonReportFormat;
use ArtisanPackUI\Security\Testing\Reporting\Formats\JunitReportFormat;
use ArtisanPackUI\Security\Testing\Reporting\Formats\MarkdownReportFormat;
use ArtisanPackUI\Security\Testing\Reporting\Formats\SarifReportFormat;
use InvalidArgumentException;

class SecurityReportGenerator implements SecurityReportInterface
{
    /**
     * @var array<SecurityFinding>
     */
    protected array $findings = [];

    /**
     * @var array<string, mixed>
     */
    protected array $metadata = [];

    /**
     * Create a new report generator.
     */
    public function __construct(
        protected string $projectName = '',
        protected ?string $version = null,
    ) {
        $this->metadata = [
            'generatedAt'      => now()->toIso8601String(),
            'projectName'      => $projectName,
            'version'          => $version,
            'generator'        => 'ArtisanPack Security Testing Framework',
            'generatorVersion' => '2.0.0',
        ];
    }

    /**
     * Add findings to the report.
     *
     * @param  array<SecurityFinding>  $findings
     */
    public function addFindings(array $findings): self
    {
        $this->findings = array_merge($this->findings, $findings);

        return $this;
    }

    /**
     * Add a single finding to the report.
     */
    public function addFinding(SecurityFinding $finding): self
    {
        $this->findings[] = $finding;

        return $this;
    }

    /**
     * Get all findings.
     *
     * @return array<SecurityFinding>
     */
    public function getFindings(): array
    {
        return $this->findings;
    }

    /**
     * Generate the report in the specified format.
     */
    public function generate(string $format = 'json'): string
    {
        return match ($format) {
            'json'           => $this->generateJson(),
            'html'           => $this->generateHtml(),
            'junit'          => $this->generateJunit(),
            'sarif'          => $this->generateSarif(),
            'markdown', 'md' => $this->generateMarkdown(),
            default          => throw new InvalidArgumentException("Unknown format: {$format}"),
        };
    }

    /**
     * Get a summary of the findings.
     *
     * @return array<string, mixed>
     */
    public function getSummary(): array
    {
        return [
            'total'      => count($this->findings),
            'bySeverity' => [
                'critical' => $this->countBySeverity([SecurityFinding::SEVERITY_CRITICAL]),
                'high'     => $this->countBySeverity([SecurityFinding::SEVERITY_HIGH]),
                'medium'   => $this->countBySeverity([SecurityFinding::SEVERITY_MEDIUM]),
                'low'      => $this->countBySeverity([SecurityFinding::SEVERITY_LOW]),
                'info'     => $this->countBySeverity([SecurityFinding::SEVERITY_INFO]),
            ],
            'byCategory'  => $this->groupByCategory(),
            'hasBlocking' => $this->hasBlockingFindings(),
        ];
    }

    /**
     * Get findings filtered by severity.
     *
     * @return array<SecurityFinding>
     */
    public function getFindingsBySeverity(string $severity): array
    {
        return array_filter(
            $this->findings,
            fn (SecurityFinding $f) => $f->severity === $severity,
        );
    }

    /**
     * Sort findings by severity (most critical first).
     */
    public function sortBySeverity(): self
    {
        usort($this->findings, fn (SecurityFinding $a, SecurityFinding $b) => $a->getSeverityOrder() <=> $b->getSeverityOrder());

        return $this;
    }

    /**
     * Save report to a file.
     */
    public function saveToFile(string $path, string $format = 'json'): bool
    {
        $content = $this->generate($format);

        return false !== file_put_contents($path, $content);
    }

    /**
     * Add custom metadata.
     *
     * @param  array<string, mixed>  $metadata
     */
    public function withMetadata(array $metadata): self
    {
        $this->metadata = array_merge($this->metadata, $metadata);

        return $this;
    }

    /**
     * Clear all findings.
     */
    public function clear(): self
    {
        $this->findings = [];

        return $this;
    }

    /**
     * Generate JSON report.
     */
    protected function generateJson(): string
    {
        $formatter = new JsonReportFormat;

        return $formatter->format($this->findings, $this->metadata, $this->getSummary());
    }

    /**
     * Generate HTML report.
     */
    protected function generateHtml(): string
    {
        $formatter = new HtmlReportFormat;

        return $formatter->format($this->findings, $this->metadata, $this->getSummary());
    }

    /**
     * Generate JUnit XML report.
     */
    protected function generateJunit(): string
    {
        $formatter = new JunitReportFormat;

        return $formatter->format($this->findings, $this->metadata, $this->getSummary());
    }

    /**
     * Generate SARIF report for GitHub Security tab.
     */
    protected function generateSarif(): string
    {
        $formatter = new SarifReportFormat;

        return $formatter->format($this->findings, $this->metadata, $this->getSummary());
    }

    /**
     * Generate Markdown report.
     */
    protected function generateMarkdown(): string
    {
        $formatter = new MarkdownReportFormat;

        return $formatter->format($this->findings, $this->metadata, $this->getSummary());
    }

    /**
     * Count findings by severity.
     *
     * @param  array<string>  $severities
     */
    protected function countBySeverity(array $severities): int
    {
        return count(array_filter(
            $this->findings,
            fn (SecurityFinding $f) => in_array($f->severity, $severities),
        ));
    }

    /**
     * Group findings by category.
     *
     * @return array<string, int>
     */
    protected function groupByCategory(): array
    {
        $groups = [];

        foreach ($this->findings as $finding) {
            $groups[$finding->category] = ($groups[$finding->category] ?? 0) + 1;
        }

        arsort($groups);

        return $groups;
    }

    /**
     * Check if there are blocking findings (critical or high).
     */
    protected function hasBlockingFindings(): bool
    {
        foreach ($this->findings as $finding) {
            if ($finding->isBlocking()) {
                return true;
            }
        }

        return false;
    }
}
