<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Console\Commands;

use ArtisanPackUI\Security\Testing\CiCd\SecurityGate;
use ArtisanPackUI\Security\Testing\Performance\ImpactAnalyzer;
use ArtisanPackUI\Security\Testing\Performance\SecurityBenchmark;
use ArtisanPackUI\Security\Testing\Reporting\SecurityFinding;
use ArtisanPackUI\Security\Testing\Reporting\SecurityReportGenerator;
use ArtisanPackUI\Security\Testing\Scanners\ConfigurationScanner;
use ArtisanPackUI\Security\Testing\Scanners\DependencyScanner;
use ArtisanPackUI\Security\Testing\Scanners\OwaspScanner;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

class SecurityAudit extends Command
{
    protected $signature = 'security:audit
                            {--format=json : Output format (json, html, sarif, junit, markdown)}
                            {--output= : Output file path}
                            {--benchmark : Include performance benchmarks}
                            {--no-fail : Do not exit with error code on findings}
                            {--scanners= : Comma-separated list of scanners to run (owasp,dependencies,config,headers)}
                            {--severity= : Minimum severity to report (low, medium, high, critical)}
                            {--include-recommendations : Include remediation recommendations in output}
                            {--silent : Suppress console output, only write to file}';

    protected $description = 'Run a comprehensive security audit with all scanners';

    /**
     * Available scanners.
     *
     * @var array<string, string>
     */
    protected array $availableScanners = [
        'owasp' => 'OWASP Top 10 Scanner',
        'dependencies' => 'Dependency Scanner',
        'config' => 'Configuration Scanner',
        'headers' => 'Security Headers Scanner',
    ];

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

    public function handle(): int
    {
        $silent = $this->option('silent');

        if (! $silent) {
            $this->info('Starting comprehensive security audit...');
            $this->newLine();
        }

        $startTime = microtime(true);
        $findings = [];

        // Determine which scanners to run
        $scannersToRun = $this->getScannersToRun();

        // Run selected scanners
        if (in_array('owasp', $scannersToRun, true)) {
            $this->runTask('OWASP Top 10 Scanner', function () use (&$findings) {
                $scanner = new OwaspScanner;
                $findings = array_merge($findings, $scanner->scan());

                return true;
            }, $silent);
        }

        if (in_array('dependencies', $scannersToRun, true)) {
            $this->runTask('Dependency Scanner', function () use (&$findings) {
                $scanner = new DependencyScanner;
                $findings = array_merge($findings, $scanner->scan());

                return true;
            }, $silent);
        }

        if (in_array('config', $scannersToRun, true)) {
            $this->runTask('Configuration Scanner', function () use (&$findings) {
                $scanner = new ConfigurationScanner;
                $findings = array_merge($findings, $scanner->scan());

                return true;
            }, $silent);
        }

        if (in_array('headers', $scannersToRun, true)) {
            $this->runTask('Security Headers Scanner', function () use (&$findings) {
                $headerFindings = $this->runHeadersScanner();
                $findings = array_merge($findings, $headerFindings);

                return true;
            }, $silent);
        }

        // Optional performance benchmarks
        $benchmarkResults = [];
        if ($this->option('benchmark')) {
            $this->runTask('Performance Benchmarks', function () use (&$benchmarkResults) {
                $benchmark = new SecurityBenchmark;
                $benchmarkResults = $benchmark->runFullSuite();

                return true;
            }, $silent);

            // Analyze performance impact
            $analyzer = new ImpactAnalyzer($benchmarkResults);
            $performanceFindings = $analyzer->analyze();
            $findings = array_merge($findings, $performanceFindings);
        }

        // Filter by severity if specified
        $findings = $this->filterBySeverity($findings);

        $duration = round(microtime(true) - $startTime, 2);

        // Generate report
        $report = new SecurityReportGenerator(
            projectName: config('app.name', 'Application'),
            version: config('app.version', '1.0.0')
        );

        $metadata = [
            'auditDuration' => $duration,
            'benchmarksIncluded' => $this->option('benchmark'),
            'scannersRun' => $scannersToRun,
        ];

        if ($this->option('include-recommendations')) {
            $metadata['includeRecommendations'] = true;
        }

        $report->addFindings($findings)
            ->withMetadata($metadata)
            ->sortBySeverity();

        $format = $this->option('format');
        $output = $report->generate($format);

        // Output results
        if ($outputPath = $this->option('output')) {
            $result = file_put_contents($outputPath, $output);
            if ($result === false) {
                $this->error("Failed to write report to: {$outputPath}");
            } elseif (! $silent) {
                $this->info("Report saved to: {$outputPath}");
            }
        }

        // Display results (unless silent mode)
        if (! $silent) {
            $this->displayResults($report->getSummary(), $benchmarkResults, $duration);

            // Show recommendations if requested
            if ($this->option('include-recommendations')) {
                $this->displayRecommendations($findings);
            }
        }

        // Run security gate
        $gate = new SecurityGate(
            maxCritical: (int) config('artisanpack.security.testing.gate.maxCritical', 0),
            maxHigh: (int) config('artisanpack.security.testing.gate.maxHigh', 0),
            maxMedium: (int) config('artisanpack.security.testing.gate.maxMedium', 10)
        );

        $gateResult = $gate->evaluate($findings, $benchmarkResults);

        if (! $silent) {
            $this->newLine();
            if ($gateResult->passed) {
                $this->info('Security audit passed!');
            } else {
                $this->error('Security audit failed!');
                foreach ($gateResult->failures as $failure) {
                    $this->line("  - {$failure}");
                }
            }
        }

        if ($this->option('no-fail')) {
            return self::SUCCESS;
        }

        return $gateResult->getExitCode();
    }

    /**
     * Get the list of scanners to run.
     *
     * @return array<string>
     */
    protected function getScannersToRun(): array
    {
        if ($scanners = $this->option('scanners')) {
            $requested = array_map('trim', explode(',', $scanners));

            return array_intersect($requested, array_keys($this->availableScanners));
        }

        // Default: run all except headers (for backward compatibility)
        return ['owasp', 'dependencies', 'config'];
    }

    /**
     * Run a task with optional output.
     */
    protected function runTask(string $title, callable $task, bool $silent): void
    {
        if ($silent) {
            try {
                $task();
            } catch (\Throwable $e) {
                Log::error("Security audit task '{$title}' failed: {$e->getMessage()}", [
                    'task' => $title,
                    'exception' => get_class($e),
                    'message' => $e->getMessage(),
                    'file' => $e->getFile(),
                    'line' => $e->getLine(),
                ]);
            }

            return;
        }

        $this->task($title, $task);
    }

    /**
     * Run the security headers scanner.
     *
     * @return array<SecurityFinding>
     */
    protected function runHeadersScanner(): array
    {
        $findings = [];
        $configuredHeaders = config('artisanpack.security.security-headers', []);

        $requiredHeaders = [
            'Strict-Transport-Security' => [
                'severity' => 'high',
                'category' => 'Security Headers',
            ],
            'X-Frame-Options' => [
                'severity' => 'high',
                'category' => 'Security Headers',
            ],
            'X-Content-Type-Options' => [
                'severity' => 'medium',
                'category' => 'Security Headers',
            ],
            'Content-Security-Policy' => [
                'severity' => 'high',
                'category' => 'Security Headers',
            ],
        ];

        foreach ($requiredHeaders as $header => $config) {
            if (empty($configuredHeaders[$header])) {
                $findings[] = SecurityFinding::fromArray([
                    'id' => 'HEADERS-'.strtoupper(str_replace('-', '', $header)),
                    'title' => "Missing {$header} header",
                    'description' => "The {$header} security header is not configured",
                    'severity' => $config['severity'],
                    'category' => $config['category'],
                    'location' => 'config/artisanpack/security.php',
                    'remediation' => "Add {$header} to security-headers configuration",
                ]);
            }
        }

        // Check CSP for unsafe values
        $csp = $configuredHeaders['Content-Security-Policy'] ?? '';
        if ($csp && str_contains($csp, "'unsafe-inline'") && ! str_contains($csp, "'strict-dynamic'")) {
            $findings[] = SecurityFinding::fromArray([
                'id' => 'HEADERS-CSP-UNSAFE-INLINE',
                'title' => 'CSP uses unsafe-inline',
                'description' => "Content-Security-Policy contains 'unsafe-inline' without strict-dynamic",
                'severity' => 'medium',
                'category' => 'Security Headers',
                'location' => 'config/artisanpack/security.php',
                'remediation' => "Consider using nonces or 'strict-dynamic' instead of 'unsafe-inline'",
            ]);
        }

        if ($csp && str_contains($csp, "'unsafe-eval'")) {
            $findings[] = SecurityFinding::fromArray([
                'id' => 'HEADERS-CSP-UNSAFE-EVAL',
                'title' => 'CSP uses unsafe-eval',
                'description' => "Content-Security-Policy contains 'unsafe-eval' which allows eval()",
                'severity' => 'medium',
                'category' => 'Security Headers',
                'location' => 'config/artisanpack/security.php',
                'remediation' => "Remove 'unsafe-eval' if not required by your framework",
            ]);
        }

        return $findings;
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
     * Display remediation recommendations.
     *
     * @param  array<SecurityFinding>  $findings
     */
    protected function displayRecommendations(array $findings): void
    {
        $recommendations = [];

        foreach ($findings as $finding) {
            if (! empty($finding->remediation)) {
                $recommendations[] = [
                    'severity' => $finding->severity ?? 'info',
                    'title' => $finding->title ?? 'Unknown',
                    'remediation' => $finding->remediation,
                ];
            }
        }

        if (empty($recommendations)) {
            return;
        }

        $this->newLine();
        $this->line('<fg=white;options=bold>Remediation Recommendations:</>');
        $this->newLine();

        // Sort by severity (critical first)
        usort($recommendations, function ($a, $b) {
            return ($this->severityLevels[$b['severity']] ?? 0) <=> ($this->severityLevels[$a['severity']] ?? 0);
        });

        foreach (array_slice($recommendations, 0, 10) as $i => $rec) {
            $severityColor = match ($rec['severity']) {
                'critical' => 'red',
                'high' => 'yellow',
                'medium' => 'blue',
                default => 'cyan',
            };

            $this->line(($i + 1).". <fg={$severityColor}>[{$rec['severity']}]</> {$rec['title']}");
            $this->line("   {$rec['remediation']}");
        }

        if (count($recommendations) > 10) {
            $this->line('   ... and '.(count($recommendations) - 10).' more recommendations');
        }
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
     * Display audit results.
     *
     * @param  array<string, mixed>  $summary
     * @param  array<\ArtisanPackUI\Security\Testing\Performance\BenchmarkResult>  $benchmarks
     */
    protected function displayResults(array $summary, array $benchmarks, float $duration): void
    {
        $this->newLine();
        $this->info("=== Security Audit Results ({$duration}s) ===");
        $this->newLine();

        // Findings summary
        $this->line('<fg=white;options=bold>Findings Summary:</>');
        $this->newLine();

        $rows = [];
        foreach ($summary['bySeverity'] as $severity => $count) {
            $color = match ($severity) {
                'critical' => 'red',
                'high' => 'yellow',
                'medium' => 'blue',
                'low' => 'cyan',
                default => 'gray',
            };
            $rows[] = ["<fg={$color}>".ucfirst($severity).'</>', $count];
        }
        $rows[] = ['<fg=white;options=bold>Total</>', "<fg=white;options=bold>{$summary['total']}</>"];

        $this->table(['Severity', 'Count'], $rows);

        // Category breakdown
        if (! empty($summary['byCategory'])) {
            $this->newLine();
            $this->line('<fg=white;options=bold>Findings by Category:</>');
            $this->newLine();

            $categoryRows = [];
            foreach ($summary['byCategory'] as $category => $count) {
                $categoryRows[] = [$category, $count];
            }

            $this->table(['Category', 'Count'], $categoryRows);
        }

        // Benchmark results
        if (! empty($benchmarks)) {
            $this->newLine();
            $this->line('<fg=white;options=bold>Performance Benchmarks:</>');
            $this->newLine();

            $benchmarkRows = [];
            foreach ($benchmarks as $result) {
                $benchmarkRows[] = $result->toTableRow();
            }

            $this->table(['Benchmark', 'With Security', 'Without', 'Overhead', 'Status'], $benchmarkRows);
        }
    }
}
