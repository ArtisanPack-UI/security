<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Console\Commands;

use ArtisanPackUI\Security\Testing\Performance\ImpactAnalyzer;
use ArtisanPackUI\Security\Testing\Performance\SecurityBenchmark;
use Exception;
use Illuminate\Console\Command;

class SecurityBenchmarkCommand extends Command
{
    protected $signature = 'security:benchmark
                            {--iterations=1000 : Number of iterations per benchmark}
                            {--format=table : Output format (table, json)}
                            {--output= : Output file path}
                            {--threshold=15 : Maximum acceptable overhead percentage}';

    protected $description = 'Run performance benchmarks for security features';

    public function handle(): int
    {
        $iterations = (int) $this->option('iterations');
        $threshold  = (float) $this->option('threshold');

        $this->info('Running security performance benchmarks...');
        $this->line("Iterations: {$iterations}");
        $this->line("Overhead threshold: {$threshold}%");
        $this->newLine();

        $benchmark = new SecurityBenchmark;

        // Run benchmarks with progress
        $this->task('Encryption/Decryption', function () use ($benchmark, $iterations): void {
            $benchmark->benchmarkEncryption('Test data for encryption benchmark', $iterations);
        });

        $this->task('Password Hashing', function () use ($benchmark): void {
            // Fewer iterations for hashing as it's intentionally slow
            $benchmark->benchmarkHashing('SecurePassword123!', 50);
        });

        $this->task('Nonce Generation', function () use ($benchmark, $iterations): void {
            $benchmark->benchmarkNonceGeneration($iterations);
        });

        $this->task('Validation Rules', function () use ($benchmark, $iterations): void {
            $benchmark->benchmarkValidation('required|string|min:8', 'test-value-here', $iterations);
        });

        // Benchmark middleware if available
        $middlewareClasses = [
            \ArtisanPackUI\Security\Http\Middleware\SecurityHeaders::class,
            \ArtisanPackUI\Security\Http\Middleware\ContentSecurityPolicy::class,
        ];

        foreach ($middlewareClasses as $middlewareClass) {
            if (class_exists($middlewareClass)) {
                $shortName = class_basename($middlewareClass);
                $this->task("Middleware: {$shortName}", function () use ($benchmark, $middlewareClass, $iterations): void {
                    $benchmark->benchmarkMiddleware($middlewareClass, null, $iterations);
                });
            }
        }

        $results = $benchmark->getResults();

        // Analyze results
        $analyzer = new ImpactAnalyzer($results, ['default' => $threshold]);
        $summary  = $analyzer->getSummary();

        // Output results
        $format = $this->option('format');

        if ('json' === $format) {
            $output = json_encode([
                'results'         => $benchmark->generateReport(),
                'summary'         => $summary,
                'recommendations' => $analyzer->getRecommendations(),
            ], JSON_PRETTY_PRINT);

            if ($outputPath = $this->option('output')) {
                file_put_contents($outputPath, $output);
                $this->info("Results saved to: {$outputPath}");
            } else {
                $this->line($output);
            }
        } else {
            $this->displayTable($results, $summary);
        }

        // Display recommendations
        $recommendations = $analyzer->getRecommendations();
        if (! empty($recommendations)) {
            $this->newLine();
            $this->warn('Recommendations:');
            foreach ($recommendations as $name => $recommendation) {
                $this->line("  - <fg=yellow>{$name}</>: {$recommendation}");
            }
        }

        // Return status
        $this->newLine();
        if ($analyzer->isAcceptable()) {
            $this->info('All benchmarks within acceptable threshold!');

            return self::SUCCESS;
        }

        $this->error("Some benchmarks exceeded the {$threshold}% overhead threshold.");

        return self::FAILURE;
    }

    /**
     * Run a task with visual feedback.
     */
    protected function task(string $title, callable $task): void
    {
        $this->output->write("  {$title}... ");

        try {
            $task();
            $this->output->writeln('<fg=green>DONE</>');
        } catch (Exception $e) {
            $this->output->writeln('<fg=red>FAILED</>');
        }
    }

    /**
     * Display results as a table.
     *
     * @param  array<\ArtisanPackUI\Security\Testing\Performance\BenchmarkResult>  $results
     * @param  array<string, mixed>  $summary
     */
    protected function displayTable(array $results, array $summary): void
    {
        $this->newLine();
        $this->info('=== Benchmark Results ===');
        $this->newLine();

        $rows = [];
        foreach ($results as $result) {
            $status = $result->isAcceptable() ? '<fg=green>PASS</>' : '<fg=red>FAIL</>';
            $rows[] = [
                $result->name,
                sprintf('%.3fms', $result->withSecurity['mean']),
                sprintf('%.3fms', $result->withoutSecurity['mean']),
                sprintf('%.2f%%', $result->getOverhead()),
                $status,
            ];
        }

        $this->table(
            ['Benchmark', 'With Security', 'Without', 'Overhead', 'Status'],
            $rows,
        );

        $this->newLine();
        $this->line(sprintf(
            'Pass rate: <fg=%s>%.1f%%</> (%d/%d)',
            100 === $summary['pass_rate'] ? 'green' : 'yellow',
            $summary['pass_rate'],
            $summary['acceptable'],
            $summary['total_benchmarks'],
        ));

        $this->line(sprintf(
            'Average overhead: %.2f%%',
            $summary['average_overhead'],
        ));
    }
}
