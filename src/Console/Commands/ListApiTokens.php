<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Console\Commands;

use ArtisanPackUI\Security\Models\ApiToken;
use Illuminate\Console\Command;

class ListApiTokens extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'api:token:list
                            {user? : Filter by user ID or email}
                            {--active : Show only active tokens}
                            {--expired : Show only expired tokens}
                            {--revoked : Show only revoked tokens}
                            {--limit=50 : Maximum number of tokens to display}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'List API tokens';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $query = ApiToken::query()->with('tokenable');

        // Filter by user if specified
        if ($userIdentifier = $this->argument('user')) {
            $userModel = config('auth.providers.users.model');
            $user = is_numeric($userIdentifier)
                ? $userModel::find($userIdentifier)
                : $userModel::where('email', $userIdentifier)->first();

            if (! $user) {
                $this->error("User not found: {$userIdentifier}");

                return self::FAILURE;
            }

            $query->where('tokenable_type', get_class($user))
                ->where('tokenable_id', $user->id);
        }

        // Apply filters
        if ($this->option('active')) {
            $query->active();
        } elseif ($this->option('expired')) {
            $query->expired();
        } elseif ($this->option('revoked')) {
            $query->revoked();
        }

        $tokens = $query->latest()->limit((int) $this->option('limit'))->get();

        if ($tokens->isEmpty()) {
            $this->info('No tokens found.');

            return self::SUCCESS;
        }

        $rows = $tokens->map(function ($token) {
            $user = $token->tokenable;
            $userDisplay = $user ? ($user->email ?? "ID: {$user->id}") : 'Unknown';

            return [
                $token->id,
                $userDisplay,
                $token->name,
                implode(', ', $token->abilities ?? ['*']),
                $this->getStatus($token),
                $token->last_used_at?->diffForHumans() ?? 'Never',
                $token->created_at->diffForHumans(),
            ];
        });

        $this->table(
            ['ID', 'User', 'Name', 'Abilities', 'Status', 'Last Used', 'Created'],
            $rows
        );

        $this->newLine();
        $this->info("Total: {$tokens->count()} token(s)");

        return self::SUCCESS;
    }

    /**
     * Get the status of a token.
     */
    protected function getStatus($token): string
    {
        if ($token->is_revoked) {
            return '<fg=red>Revoked</>';
        }

        if ($token->expires_at && $token->expires_at->isPast()) {
            return '<fg=yellow>Expired</>';
        }

        return '<fg=green>Active</>';
    }
}
