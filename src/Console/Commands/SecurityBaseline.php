<?php

/**
 * `SecurityBaseline` Artisan command.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Console\Commands;

use ArtisanPackUI\Security\Testing\Scanners\ConfigurationScanner;
use ArtisanPackUI\Security\Testing\Scanners\DependencyScanner;
use ArtisanPackUI\Security\Testing\Scanners\OwaspScanner;
use Illuminate\Console\Command;

class SecurityBaseline extends Command
{
    protected $signature = 'security:baseline
                            {action=show : Action to perform (show, create, update, clear)}
                            {--path= : Path to baseline file}';

    protected $description = 'Manage security baseline for differential scanning';

    protected string $defaultPath;

    public function __construct()
    {
        parent::__construct();
        $this->defaultPath = base_path('.security-baseline.json');
    }

    public function handle(): int
    {
        $action = $this->argument('action');
        $path   = $this->option('path') ?? $this->defaultPath;

        return match ($action) {
            'show'   => $this->showBaseline($path),
            'create' => $this->createBaseline($path),
            'update' => $this->updateBaseline($path),
            'clear'  => $this->clearBaseline($path),
            default  => $this->invalidAction($action),
        };
    }

    /**
     * Show current baseline.
     */
    protected function showBaseline(string $path): int
    {
        if (! file_exists($path)) {
            $this->warn('No baseline file found.');
            $this->line("Run 'php artisan security:baseline create' to create one.");

            return self::SUCCESS;
        }

        $baseline = json_decode(file_get_contents($path), true);

        if (JSON_ERROR_NONE !== json_last_error()) {
            $this->error('Invalid baseline file format.');

            return self::FAILURE;
        }

        $this->info('Current Security Baseline');
        $this->line("Path: {$path}");
        $this->line('Created: '.($baseline['metadata']['createdAt'] ?? 'Unknown'));
        $this->line('Updated: '.($baseline['metadata']['updatedAt'] ?? 'Never'));
        $this->newLine();

        $findings = $baseline['findings'] ?? [];
        $this->line('Baselined findings: <fg=yellow>'.count($findings).'</>');
        $this->newLine();

        if (! empty($findings)) {
            $rows = [];
            foreach ($findings as $finding) {
                $rows[] = [
                    $finding['id'],
                    $finding['severity'],
                    substr($finding['title'], 0, 50),
                ];
            }

            $this->table(['ID', 'Severity', 'Title'], $rows);
        }

        return self::SUCCESS;
    }

    /**
     * Create a new baseline from current scan.
     */
    protected function createBaseline(string $path): int
    {
        if (file_exists($path)) {
            if (! $this->confirm('Baseline file already exists. Overwrite?')) {
                $this->line('Operation cancelled.');

                return self::SUCCESS;
            }
        }

        $this->info('Running security scan to create baseline...');

        $findings = $this->runScan();

        $baseline = [
            'metadata' => [
                'createdAt' => now()->toIso8601String(),
                'updatedAt' => now()->toIso8601String(),
                'version'   => '1.0',
            ],
            'findings' => array_map(fn ($f) => $f->toArray(), $findings),
        ];

        $result = file_put_contents($path, json_encode($baseline, JSON_PRETTY_PRINT));

        if (false === $result) {
            $this->error("Failed to write baseline file: {$path}");

            return self::FAILURE;
        }

        $this->info('Baseline created with '.count($findings).' findings.');
        $this->line("Path: {$path}");

        return self::SUCCESS;
    }

    /**
     * Update baseline with new findings.
     */
    protected function updateBaseline(string $path): int
    {
        $existingBaseline = [];
        if (file_exists($path)) {
            $existingBaseline = json_decode(file_get_contents($path), true) ?? [];
        }

        $this->info('Running security scan...');

        $findings    = $this->runScan();
        $newFindings = [];
        $existingIds = array_column($existingBaseline['findings'] ?? [], 'id');

        foreach ($findings as $finding) {
            if (! in_array($finding->id, $existingIds)) {
                $newFindings[] = $finding;
            }
        }

        if (empty($newFindings)) {
            $this->info('No new findings to add to baseline.');

            return self::SUCCESS;
        }

        $this->warn('Found '.count($newFindings).' new findings:');
        foreach ($newFindings as $finding) {
            $this->line("  - [{$finding->severity}] {$finding->title}");
        }
        $this->newLine();

        if (! $this->confirm('Add these findings to the baseline?')) {
            $this->line('Operation cancelled.');

            return self::SUCCESS;
        }

        $baseline = [
            'metadata' => [
                'createdAt' => $existingBaseline['metadata']['createdAt'] ?? now()->toIso8601String(),
                'updatedAt' => now()->toIso8601String(),
                'version'   => '1.0',
            ],
            'findings' => array_merge(
                $existingBaseline['findings'] ?? [],
                array_map(fn ($f) => $f->toArray(), $newFindings),
            ),
        ];

        file_put_contents($path, json_encode($baseline, JSON_PRETTY_PRINT));

        $this->info('Baseline updated with '.count($newFindings).' new findings.');

        return self::SUCCESS;
    }

    /**
     * Clear baseline file.
     */
    protected function clearBaseline(string $path): int
    {
        if (! file_exists($path)) {
            $this->info('No baseline file to clear.');

            return self::SUCCESS;
        }

        if (! $this->confirm('Are you sure you want to clear the baseline?')) {
            $this->line('Operation cancelled.');

            return self::SUCCESS;
        }

        unlink($path);
        $this->info('Baseline cleared.');

        return self::SUCCESS;
    }

    /**
     * Handle invalid action.
     */
    protected function invalidAction(string $action): int
    {
        $this->error("Unknown action: {$action}");
        $this->line('Valid actions: show, create, update, clear');

        return self::FAILURE;
    }

    /**
     * Run security scan and return findings.
     *
     * @return array<\ArtisanPackUI\Security\Testing\Reporting\SecurityFinding>
     */
    protected function runScan(): array
    {
        $findings = [];

        $this->output->write('  OWASP scan... ');
        $scanner  = new OwaspScanner;
        $findings = array_merge($findings, $scanner->scan());
        $this->output->writeln('<fg=green>done</>');

        $this->output->write('  Dependency scan... ');
        $scanner  = new DependencyScanner;
        $findings = array_merge($findings, $scanner->scan());
        $this->output->writeln('<fg=green>done</>');

        $this->output->write('  Configuration scan... ');
        $scanner  = new ConfigurationScanner;
        $findings = array_merge($findings, $scanner->scan());
        $this->output->writeln('<fg=green>done</>');

        return $findings;
    }
}
