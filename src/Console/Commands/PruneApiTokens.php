<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Console\Commands;

use ArtisanPackUI\Security\Models\ApiToken;
use Illuminate\Console\Command;

class PruneApiTokens extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'api:token:prune
                            {--days=30 : Delete tokens unused for this many days}
                            {--expired : Delete all expired tokens}
                            {--revoked : Delete all revoked tokens}
                            {--force : Skip confirmation}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Delete old, expired, or revoked API tokens';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $totalDeleted = 0;

        // Delete expired tokens
        if ($this->option('expired')) {
            $count = $this->pruneExpiredTokens();
            $totalDeleted += $count;
            $this->info("Deleted {$count} expired token(s).");
        }

        // Delete revoked tokens
        if ($this->option('revoked')) {
            $count = $this->pruneRevokedTokens();
            $totalDeleted += $count;
            $this->info("Deleted {$count} revoked token(s).");
        }

        // Delete unused tokens (if no other options specified or additionally)
        if (! $this->option('expired') && ! $this->option('revoked')) {
            $days = (int) $this->option('days');
            $count = $this->pruneUnusedTokens($days);
            $totalDeleted += $count;
            $this->info("Deleted {$count} token(s) unused for {$days}+ days.");
        }

        if ($totalDeleted === 0) {
            $this->info('No tokens to prune.');
        } else {
            $this->newLine();
            $this->info("Total deleted: {$totalDeleted} token(s).");
        }

        return self::SUCCESS;
    }

    /**
     * Prune expired tokens.
     */
    protected function pruneExpiredTokens(): int
    {
        $count = ApiToken::expired()->count();

        if ($count === 0) {
            return 0;
        }

        if (! $this->option('force') && ! $this->confirm("Delete {$count} expired token(s)?")) {
            return 0;
        }

        return ApiToken::expired()->delete();
    }

    /**
     * Prune revoked tokens.
     */
    protected function pruneRevokedTokens(): int
    {
        $count = ApiToken::revoked()->count();

        if ($count === 0) {
            return 0;
        }

        if (! $this->option('force') && ! $this->confirm("Delete {$count} revoked token(s)?")) {
            return 0;
        }

        return ApiToken::revoked()->delete();
    }

    /**
     * Prune tokens unused for a given number of days.
     */
    protected function pruneUnusedTokens(int $days): int
    {
        $count = ApiToken::unusedFor($days)->count();

        if ($count === 0) {
            return 0;
        }

        if (! $this->option('force') && ! $this->confirm("Delete {$count} token(s) unused for {$days}+ days?")) {
            return 0;
        }

        return ApiToken::unusedFor($days)->delete();
    }
}
