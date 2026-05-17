<?php

/**
 * `SecurityScan` Artisan command.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Console\Commands;

use ArtisanPackUI\Security\Testing\Reporting\SecurityReportGenerator;
use ArtisanPackUI\Security\Testing\Scanners\ConfigurationScanner;
use ArtisanPackUI\Security\Testing\Scanners\DependencyScanner;
use ArtisanPackUI\Security\Testing\Scanners\HeaderScanner;
use ArtisanPackUI\Security\Testing\Scanners\OwaspScanner;
use Illuminate\Console\Command;

class SecurityScan extends Command
{
    protected $signature = 'security:scan
                            {--type=all : Type of scan (all, owasp, dependencies, config, headers)}
                            {--format=json : Output format (json, html, sarif, junit, markdown)}
                            {--output= : Output file path}
                            {--fail-on=high : Fail on severity (critical, high, medium, low)}
                            {--baseline= : Path to baseline file for differential scanning}
                            {--categories= : Comma-separated list of OWASP categories to scan (e.g., A01,A03)}';

    protected $description = 'Run security scans and generate reports';

    public function handle(): int
    {
        $this->info('Starting security scan...');
        $this->newLine();

        $findings = [];
        $type     = $this->option('type');

        // Run scanners based on type
        if ('all' === $type || 'owasp' === $type) {
            $this->info('Running OWASP Top 10 scan...');
            $categories = $this->option('categories')
                ? explode(',', $this->option('categories'))
                : [];
            $scanner       = new OwaspScanner($categories);
            $owaspFindings = $scanner->scan();
            $findings      = array_merge($findings, $owaspFindings);
            $this->line("  Found {$this->countFindings($owaspFindings)} issues");
        }

        if ('all' === $type || 'dependencies' === $type) {
            $this->info('Running dependency scan...');
            $scanner     = new DependencyScanner;
            $depFindings = $scanner->scan();
            $findings    = array_merge($findings, $depFindings);
            $this->line("  Found {$this->countFindings($depFindings)} issues");
        }

        if ('all' === $type || 'config' === $type) {
            $this->info('Running configuration scan...');
            $scanner        = new ConfigurationScanner;
            $configFindings = $scanner->scan();
            $findings       = array_merge($findings, $configFindings);
            $this->line("  Found {$this->countFindings($configFindings)} issues");
        }

        if ('all' === $type || 'headers' === $type) {
            $this->info('Running security headers scan...');
            $scanner        = new HeaderScanner;
            $headerFindings = $scanner->scan();
            $findings       = array_merge($findings, $headerFindings);
            $this->line("  Found {$this->countFindings($headerFindings)} issues");
        }

        // Apply baseline if provided
        if ($baseline = $this->option('baseline')) {
            $originalCount = count($findings);
            $findings      = $this->applyBaseline($findings, $baseline);
            $filteredCount = $originalCount - count($findings);

            if ($filteredCount > 0) {
                $this->info("Filtered {$filteredCount} baseline issues");
            }
        }

        // Generate report
        $report = new SecurityReportGenerator(
            projectName: config('app.name', 'Application'),
            version: config('app.version', '1.0.0'),
        );

        $report->addFindings($findings)->sortBySeverity();
        $format = $this->option('format');
        $output = $report->generate($format);

        // Output results
        if ($outputPath = $this->option('output')) {
            $bytes = @file_put_contents($outputPath, $output);
            if (false === $bytes) {
                $this->error("Failed to save report to: {$outputPath}");

                return self::FAILURE;
            }
            $this->info("Report saved to: {$outputPath}");
        } else {
            $this->newLine();
            $this->line($output);
        }

        // Display summary
        $this->displaySummary($report->getSummary());

        // Determine exit code based on findings
        return $this->determineExitCode($findings);
    }

    /**
     * Count findings in an array.
     *
     * @param  array<\ArtisanPackUI\Security\Testing\Reporting\SecurityFinding>  $findings
     */
    protected function countFindings(array $findings): int
    {
        return count($findings);
    }

    /**
     * Display summary table.
     *
     * @param  array<string, mixed>  $summary
     */
    protected function displaySummary(array $summary): void
    {
        $this->newLine();
        $this->info('=== Scan Summary ===');
        $this->newLine();

        $rows = [];
        foreach ($summary['bySeverity'] as $severity => $count) {
            $icon = match ($severity) {
                'critical' => '<fg=red>●</>',
                'high'     => '<fg=yellow>●</>',
                'medium'   => '<fg=blue>●</>',
                'low'      => '<fg=cyan>●</>',
                'info'     => '<fg=gray>●</>',
                default    => '●',
            };
            $rows[] = [$icon.' '.ucfirst($severity), $count];
        }

        $this->table(['Severity', 'Count'], $rows);

        $this->newLine();
        $this->line("Total findings: <fg=white;options=bold>{$summary['total']}</>");
    }

    /**
     * Determine exit code based on findings.
     *
     * @param  array<\ArtisanPackUI\Security\Testing\Reporting\SecurityFinding>  $findings
     */
    protected function determineExitCode(array $findings): int
    {
        $failOn        = $this->option('fail-on');
        $severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
        $threshold     = array_search($failOn, $severityOrder);

        if (false === $threshold) {
            $this->warn("Invalid --fail-on value: {$failOn}. Using 'high' as default.");
            $threshold = array_search('high', $severityOrder);
        }

        foreach ($findings as $finding) {
            $findingSeverity = array_search($finding->severity, $severityOrder);

            if (false !== $findingSeverity && false !== $threshold && $findingSeverity <= $threshold) {
                $this->newLine();
                $this->error("Scan failed: Found {$finding->severity} severity issue(s)");

                return self::FAILURE;
            }
        }

        $this->newLine();
        $this->info('Scan passed!');

        return self::SUCCESS;
    }

    /**
     * Apply baseline to filter known issues.
     *
     * @param  array<\ArtisanPackUI\Security\Testing\Reporting\SecurityFinding>  $findings
     *
     * @return array<\ArtisanPackUI\Security\Testing\Reporting\SecurityFinding>
     */
    protected function applyBaseline(array $findings, string $baselinePath): array
    {
        if (! file_exists($baselinePath)) {
            $this->warn("Baseline file not found: {$baselinePath}");

            return $findings;
        }

        $content = @file_get_contents($baselinePath);
        if (false === $content) {
            $this->warn("Unable to read baseline file: {$baselinePath}");

            return $findings;
        }

        $baseline = json_decode($content, true);

        if (JSON_ERROR_NONE !== json_last_error()) {
            $this->warn('Invalid baseline file format');

            return $findings;
        }

        $baselineIds = array_column($baseline['findings'] ?? [], 'id');

        return array_filter(
            $findings,
            fn ($f) => ! in_array($f->id, $baselineIds),
        );
    }
}
