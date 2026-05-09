<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Console\Commands;

use ArtisanPackUI\Security\Models\CspViolationReport;
use Illuminate\Console\Command;

class CspPrune extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:csp:prune
                            {--days=30 : Number of days to retain violations}
                            {--force : Skip confirmation prompt}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Prune old CSP violation reports';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $days = (int) $this->option('days');

        if ($days < 1) {
            $this->error('Retention days must be a positive integer.');

            return self::FAILURE;
        }

        // Count records to be deleted
        $count = CspViolationReport::query()
            ->where('last_seen_at', '<', now()->subDays($days))
            ->count();

        if (0 === $count) {
            $this->info('No violation reports to prune.');

            return self::SUCCESS;
        }

        $this->info("Found {$count} violation reports older than {$days} days.");

        if (! $this->option('force')) {
            if (! $this->confirm('Do you want to delete these records?')) {
                $this->info('Operation cancelled.');

                return self::SUCCESS;
            }
        }

        $deleted = CspViolationReport::prune($days);

        $this->info("Successfully pruned {$deleted} CSP violation reports.");

        return self::SUCCESS;
    }
}
