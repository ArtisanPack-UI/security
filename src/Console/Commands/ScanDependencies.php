<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Console\Commands;

use ArtisanPackUI\Security\Testing\Reporting\SecurityFinding;
use ArtisanPackUI\Security\Testing\Scanners\DependencyScanner;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;

class ScanDependencies extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:scan-dependencies
                            {--composer : Only scan Composer dependencies}
                            {--npm : Only scan NPM dependencies}
                            {--severity= : Minimum severity (low, medium, high, critical)}
                            {--format=table : Output format (table, json, sarif)}
                            {--output= : Output file path}
                            {--advisories= : Path to local advisory database}
                            {--fail-on=high : Fail on severity level (none, low, medium, high, critical)}
                            {--include-outdated : Include outdated package warnings}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Scan Composer and NPM dependencies for known vulnerabilities';

    /**
     * Severity levels in order.
     *
     * @var array<string, int>
     */
    protected array $severityLevels = [
        'info' => 0,
        'low' => 1,
        'medium' => 2,
        'high' => 3,
        'critical' => 4,
    ];

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $this->info('Dependency Vulnerability Scanner');
        $this->newLine();

        $scanComposer = ! $this->option('npm');
        $scanNpm = ! $this->option('composer');

        // If both flags are set, scan both
        if ($this->option('composer') && $this->option('npm')) {
            $scanComposer = true;
            $scanNpm = true;
        }

        $composerLock = $scanComposer ? base_path('composer.lock') : null;
        $packageLock = $scanNpm ? base_path('package-lock.json') : null;

        // Check if files exist
        if ($scanComposer && ! File::exists(base_path('composer.lock'))) {
            $this->warn('composer.lock not found. Skipping Composer scan.');
            $composerLock = null;
        }

        if ($scanNpm && ! File::exists(base_path('package-lock.json'))) {
            $this->warn('package-lock.json not found. Skipping NPM scan.');
            $packageLock = null;
        }

        if ($composerLock === null && $packageLock === null) {
            $this->error('No lock files found to scan.');

            return self::FAILURE;
        }

        $scanner = new DependencyScanner(
            $composerLock ?? 'composer.lock',
            $packageLock ?? 'package-lock.json'
        );

        // Use local advisories if provided
        if ($advisoriesPath = $this->option('advisories')) {
            if (File::exists($advisoriesPath)) {
                $scanner->useLocalAdvisories($advisoriesPath);
                $this->line("<fg=cyan>Using local advisories:</> {$advisoriesPath}");
            } else {
                $this->warn("Advisory database not found: {$advisoriesPath}");
            }
        }

        $this->task('Scanning dependencies', function () use ($scanner, &$findings) {
            $findings = $scanner->scan();

            return true;
        });

        // Filter by severity
        $findings = $this->filterBySeverity($findings);

        // Filter outdated if not requested
        if (! $this->option('include-outdated')) {
            $findings = array_filter($findings, function ($finding) {
                return ! str_contains($finding->title ?? '', 'Outdated');
            });
        }

        $findings = array_values($findings);

        $this->newLine();

        // Output results
        $format = $this->option('format');
        $output = $this->formatOutput($findings, $format);

        if ($outputPath = $this->option('output')) {
            File::put($outputPath, $output);
            $this->info("Report saved to: {$outputPath}");
        }

        // Always display summary
        $this->displayResults($findings);

        // Determine exit code
        return $this->determineExitCode($findings);
    }

    /**
     * Run a task with visual feedback.
     */
    protected function task(string $title, callable $task): void
    {
        $this->output->write("  {$title}... ");

        try {
            $result = $task();
            $this->output->writeln($result ? '<fg=green>DONE</>' : '<fg=yellow>SKIPPED</>');
        } catch (\Exception $e) {
            $this->output->writeln('<fg=red>FAILED</>');
            $this->error("    Error: {$e->getMessage()}");
        }
    }

    /**
     * Filter findings by minimum severity.
     *
     * @param  array<SecurityFinding>  $findings
     * @return array<SecurityFinding>
     */
    protected function filterBySeverity(array $findings): array
    {
        $minSeverity = $this->option('severity');
        if (! $minSeverity) {
            return $findings;
        }

        $minLevel = $this->severityLevels[$minSeverity] ?? 0;

        return array_filter($findings, function ($finding) use ($minLevel) {
            $findingSeverity = strtolower($finding->severity ?? 'info');
            $findingLevel = $this->severityLevels[$findingSeverity] ?? 0;

            return $findingLevel >= $minLevel;
        });
    }

    /**
     * Format output based on format option.
     *
     * @param  array<SecurityFinding>  $findings
     */
    protected function formatOutput(array $findings, string $format): string
    {
        return match ($format) {
            'json' => $this->formatAsJson($findings),
            'sarif' => $this->formatAsSarif($findings),
            default => $this->formatAsText($findings),
        };
    }

    /**
     * Format findings as JSON.
     *
     * @param  array<SecurityFinding>  $findings
     */
    protected function formatAsJson(array $findings): string
    {
        $data = [
            'scan_date' => now()->toIso8601String(),
            'total_findings' => count($findings),
            'summary' => $this->getSummary($findings),
            'findings' => array_map(fn ($f) => [
                'id' => $f->id ?? null,
                'title' => $f->title ?? '',
                'description' => $f->description ?? '',
                'severity' => $f->severity ?? 'unknown',
                'category' => $f->category ?? '',
                'location' => $f->location ?? '',
                'remediation' => $f->remediation ?? '',
            ], $findings),
        ];

        return json_encode($data, JSON_PRETTY_PRINT);
    }

    /**
     * Format findings as SARIF.
     *
     * @param  array<SecurityFinding>  $findings
     */
    protected function formatAsSarif(array $findings): string
    {
        $results = [];

        foreach ($findings as $finding) {
            $results[] = [
                'ruleId' => $finding->id ?? 'UNKNOWN',
                'level' => $this->sarifLevel($finding->severity ?? 'info'),
                'message' => [
                    'text' => ($finding->title ?? '').' - '.($finding->description ?? ''),
                ],
                'locations' => [
                    [
                        'physicalLocation' => [
                            'artifactLocation' => [
                                'uri' => $finding->location ?? 'unknown',
                            ],
                        ],
                    ],
                ],
            ];
        }

        $sarif = [
            '$schema' => 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
            'version' => '2.1.0',
            'runs' => [
                [
                    'tool' => [
                        'driver' => [
                            'name' => 'ArtisanPackUI Security - Dependency Scanner',
                            'version' => '2.0.0',
                        ],
                    ],
                    'results' => $results,
                ],
            ],
        ];

        return json_encode($sarif, JSON_PRETTY_PRINT);
    }

    /**
     * Convert severity to SARIF level.
     */
    protected function sarifLevel(string $severity): string
    {
        return match (strtolower($severity)) {
            'critical', 'high' => 'error',
            'medium' => 'warning',
            default => 'note',
        };
    }

    /**
     * Format findings as text.
     *
     * @param  array<SecurityFinding>  $findings
     */
    protected function formatAsText(array $findings): string
    {
        $output = "Dependency Vulnerability Scan Results\n";
        $output .= "=====================================\n\n";
        $output .= 'Scan Date: '.now()->toDateTimeString()."\n\n";

        if (empty($findings)) {
            $output .= "No vulnerabilities found.\n";

            return $output;
        }

        // Group by source type
        $composer = [];
        $npm = [];

        foreach ($findings as $finding) {
            $location = $finding->location ?? '';
            if (str_contains($location, '(npm)')) {
                $npm[] = $finding;
            } else {
                $composer[] = $finding;
            }
        }

        if (! empty($composer)) {
            $output .= "Composer Dependencies\n";
            $output .= "---------------------\n";
            foreach ($composer as $finding) {
                $output .= $this->formatFindingText($finding);
            }
            $output .= "\n";
        }

        if (! empty($npm)) {
            $output .= "NPM Dependencies\n";
            $output .= "----------------\n";
            foreach ($npm as $finding) {
                $output .= $this->formatFindingText($finding);
            }
            $output .= "\n";
        }

        $summary = $this->getSummary($findings);
        $output .= "Summary\n";
        $output .= "-------\n";
        $output .= " Critical: {$summary['critical']}\n";
        $output .= " High: {$summary['high']}\n";
        $output .= " Medium: {$summary['medium']}\n";
        $output .= " Low: {$summary['low']}\n";
        $output .= " Info: {$summary['info']}\n";

        return $output;
    }

    /**
     * Format a single finding as text.
     */
    protected function formatFindingText(SecurityFinding $finding): string
    {
        $severity = strtoupper($finding->severity ?? 'UNKNOWN');
        $output = " x {$finding->location}\n";
        $output .= "   {$finding->id} ({$severity}): {$finding->title}\n";
        if ($finding->remediation) {
            $output .= "   Fix: {$finding->remediation}\n";
        }
        $output .= "\n";

        return $output;
    }

    /**
     * Display results in table format.
     *
     * @param  array<SecurityFinding>  $findings
     */
    protected function displayResults(array $findings): void
    {
        $summary = $this->getSummary($findings);

        $this->info('Scan Results');
        $this->newLine();

        // Summary table
        $this->table(
            ['Severity', 'Count'],
            [
                ['<fg=red>Critical</>', $summary['critical']],
                ['<fg=yellow>High</>', $summary['high']],
                ['<fg=blue>Medium</>', $summary['medium']],
                ['<fg=cyan>Low</>', $summary['low']],
                ['<fg=gray>Info</>', $summary['info']],
                ['<fg=white;options=bold>Total</>', '<fg=white;options=bold>'.$summary['total'].'</>'],
            ]
        );

        if (empty($findings)) {
            $this->newLine();
            $this->info('No vulnerabilities found!');

            return;
        }

        $this->newLine();
        $this->info('Vulnerabilities Found:');
        $this->newLine();

        // Group findings
        $composerFindings = [];
        $npmFindings = [];

        foreach ($findings as $finding) {
            $location = $finding->location ?? '';
            if (str_contains($location, '(npm)')) {
                $npmFindings[] = $finding;
            } else {
                $composerFindings[] = $finding;
            }
        }

        if (! empty($composerFindings)) {
            $this->line('<fg=white;options=bold>Composer Dependencies:</>');
            $this->displayFindingsTable($composerFindings);
        }

        if (! empty($npmFindings)) {
            $this->line('<fg=white;options=bold>NPM Dependencies:</>');
            $this->displayFindingsTable($npmFindings);
        }
    }

    /**
     * Display findings in a table.
     *
     * @param  array<SecurityFinding>  $findings
     */
    protected function displayFindingsTable(array $findings): void
    {
        $rows = [];

        foreach ($findings as $finding) {
            $severityColor = match (strtolower($finding->severity ?? 'info')) {
                'critical' => 'red',
                'high' => 'yellow',
                'medium' => 'blue',
                'low' => 'cyan',
                default => 'gray',
            };

            $rows[] = [
                $finding->location ?? 'Unknown',
                $finding->id ?? 'N/A',
                "<fg={$severityColor}>".strtoupper($finding->severity ?? 'INFO').'</>',
                $this->truncate($finding->title ?? '', 40),
            ];
        }

        $this->table(['Package', 'CVE/ID', 'Severity', 'Description'], $rows);
        $this->newLine();
    }

    /**
     * Get summary counts.
     *
     * @param  array<SecurityFinding>  $findings
     * @return array<string, int>
     */
    protected function getSummary(array $findings): array
    {
        $summary = [
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0,
            'info' => 0,
            'total' => count($findings),
        ];

        foreach ($findings as $finding) {
            $severity = strtolower($finding->severity ?? 'info');
            if (isset($summary[$severity])) {
                $summary[$severity]++;
            } else {
                $summary['info']++;
            }
        }

        return $summary;
    }

    /**
     * Truncate a string.
     */
    protected function truncate(string $text, int $length): string
    {
        if (strlen($text) <= $length) {
            return $text;
        }

        return substr($text, 0, $length - 3).'...';
    }

    /**
     * Determine exit code based on findings and fail-on option.
     *
     * @param  array<SecurityFinding>  $findings
     */
    protected function determineExitCode(array $findings): int
    {
        $failOn = $this->option('fail-on');

        if ($failOn === 'none') {
            return self::SUCCESS;
        }

        $failLevel = $this->severityLevels[$failOn] ?? 3; // Default to high

        foreach ($findings as $finding) {
            $findingSeverity = strtolower($finding->severity ?? 'info');
            $findingLevel = $this->severityLevels[$findingSeverity] ?? 0;

            if ($findingLevel >= $failLevel) {
                $this->newLine();
                $this->error("Scan failed: Found {$findingSeverity} severity vulnerability (fail-on: {$failOn})");

                return self::FAILURE;
            }
        }

        $this->newLine();
        $this->info('Scan passed: No vulnerabilities at or above fail threshold.');

        return self::SUCCESS;
    }
}
