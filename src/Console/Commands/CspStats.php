<?php

/**
 * `CspStats` Artisan command.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Console\Commands;

use ArtisanPackUI\Security\Models\CspViolationReport;
use Illuminate\Console\Command;

class CspStats extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:csp:stats
                            {--days=7 : Number of days to analyze}
                            {--detailed : Show detailed breakdown}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Display CSP violation statistics';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $days = (int) $this->option('days');

        if ($days < 1) {
            $this->error('Days must be a positive integer.');

            return self::FAILURE;
        }

        if ($days > 365) {
            $this->warn('Querying more than 365 days may impact performance.');
        }

        $hours = $days * 24;

        $this->info("CSP Violation Statistics (Last {$days} days)");
        $this->newLine();

        // Summary statistics
        $totalCount = CspViolationReport::getTotalCount($hours);
        $uniqueCount = CspViolationReport::getUniqueCount($hours);

        $this->line("<fg=cyan>Total Occurrences:</> {$totalCount}");
        $this->line("<fg=cyan>Unique Violations:</> {$uniqueCount}");
        $this->newLine();

        // Violations by directive
        $byDirective = CspViolationReport::query()
            ->where('last_seen_at', '>=', now()->subHours($hours))
            ->selectRaw('violated_directive, SUM(occurrence_count) as total')
            ->groupBy('violated_directive')
            ->orderByDesc('total')
            ->pluck('total', 'violated_directive');
        if ($byDirective->isNotEmpty()) {
            $this->info('Violations by Directive:');
            $rows = $byDirective->map(function ($count, $directive) {
                return [$this->formatDirective($directive), $count];
            })->toArray();
            $this->table(['Directive', 'Count'], $rows);
        }

        // Top blocked URIs
        $topBlocked = CspViolationReport::getTopBlockedUris(10);
        if ($topBlocked->isNotEmpty()) {
            $this->info('Top Blocked URIs:');
            $rows = $topBlocked->map(function ($count, $uri) {
                // Truncate long URIs
                $displayUri = strlen($uri) > 60 ? substr($uri, 0, 57).'...' : $uri;

                return [$displayUri, $count];
            })->toArray();
            $this->table(['Blocked URI', 'Count'], $rows);
        }

        // Detailed breakdown if requested
        if ($this->option('detailed')) {
            $this->displayDetailedStats($hours);
        }

        // Trend data
        $this->displayTrend($days);

        return self::SUCCESS;
    }

    /**
     * Display detailed violation statistics.
     */
    protected function displayDetailedStats(int $hours): void
    {
        $this->newLine();
        $this->info('Detailed Breakdown:');

        // By disposition
        $enforced = CspViolationReport::query()
            ->where('last_seen_at', '>=', now()->subHours($hours))
            ->where('disposition', 'enforce')
            ->sum('occurrence_count');

        $reportOnly = CspViolationReport::query()
            ->where('last_seen_at', '>=', now()->subHours($hours))
            ->where('disposition', 'report')
            ->sum('occurrence_count');

        $this->table(
            ['Disposition', 'Count'],
            [
                ['<fg=red>Enforced</>', $enforced],
                ['<fg=yellow>Report Only</>', $reportOnly],
            ],
        );

        // Top source files
        $topSources = CspViolationReport::query()
            ->whereNotNull('source_file')
            ->where('source_file', '!=', '')
            ->where('last_seen_at', '>=', now()->subHours($hours))
            ->selectRaw('source_file, SUM(occurrence_count) as total')
            ->groupBy('source_file')
            ->orderByDesc('total')
            ->limit(10)
            ->pluck('total', 'source_file');

        if ($topSources->isNotEmpty()) {
            $this->newLine();
            $this->info('Top Source Files:');
            $rows = $topSources->map(function ($count, $file) {
                $displayFile = strlen($file) > 50 ? '...'.substr($file, -47) : $file;

                return [$displayFile, $count];
            })->toArray();
            $this->table(['Source File', 'Count'], $rows);
        }
    }

    /**
     * Display violation trend.
     */
    protected function displayTrend(int $days): void
    {
        $trend = CspViolationReport::getViolationTrend($days);

        if (empty($trend)) {
            return;
        }

        $this->newLine();
        $this->info('Daily Trend:');

        $maxCount = max($trend) ?: 1;
        $barWidth = 30;

        foreach ($trend as $date => $count) {
            $bar = str_repeat('█', (int) (($count / $maxCount) * $barWidth));
            $bar = $bar ?: '░';
            $this->line(sprintf(
                '%s  %s %d',
                $date,
                "<fg=cyan>{$bar}</>",
                $count,
            ));
        }
    }

    /**
     * Format directive with color.
     */
    protected function formatDirective(string $directive): string
    {
        return match (true) {
            str_starts_with($directive, 'script-src') => "<fg=red>{$directive}</>",
            str_starts_with($directive, 'style-src') => "<fg=yellow>{$directive}</>",
            str_starts_with($directive, 'img-src') => "<fg=blue>{$directive}</>",
            str_starts_with($directive, 'connect-src') => "<fg=magenta>{$directive}</>",
            str_starts_with($directive, 'font-src') => "<fg=cyan>{$directive}</>",
            default => $directive,
        };
    }
}
