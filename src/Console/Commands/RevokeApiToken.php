<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Console\Commands;

use ArtisanPackUI\Security\Models\ApiToken;
use Illuminate\Console\Command;

class RevokeApiToken extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'api:token:revoke
                            {token? : The token ID to revoke}
                            {--user= : Revoke tokens for a specific user (ID or email)}
                            {--all : Revoke all tokens (requires --user or confirmation)}
                            {--expired : Revoke all expired tokens}
                            {--force : Skip confirmation}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Revoke API tokens';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        // Revoke specific token by ID
        if ($tokenId = $this->argument('token')) {
            return $this->revokeTokenById((int) $tokenId);
        }

        // Revoke all expired tokens
        if ($this->option('expired')) {
            return $this->revokeExpiredTokens();
        }

        // Revoke tokens for a specific user
        if ($userIdentifier = $this->option('user')) {
            return $this->revokeUserTokens($userIdentifier);
        }

        // Revoke all tokens (requires confirmation)
        if ($this->option('all')) {
            return $this->revokeAllTokens();
        }

        $this->error('Please specify a token ID, --user, --expired, or --all option.');

        return self::FAILURE;
    }

    /**
     * Revoke a specific token by ID.
     */
    protected function revokeTokenById(int $tokenId): int
    {
        $token = ApiToken::find($tokenId);

        if (! $token) {
            $this->error("Token not found: {$tokenId}");

            return self::FAILURE;
        }

        if ($token->is_revoked) {
            $this->warn("Token {$tokenId} is already revoked.");

            return self::SUCCESS;
        }

        $token->revoke();

        $this->info("Token {$tokenId} has been revoked.");

        return self::SUCCESS;
    }

    /**
     * Revoke all expired tokens.
     */
    protected function revokeExpiredTokens(): int
    {
        $count = ApiToken::expired()
            ->where('is_revoked', false)
            ->count();

        if ($count === 0) {
            $this->info('No expired tokens to revoke.');

            return self::SUCCESS;
        }

        if (! $this->option('force') && ! $this->confirm("Revoke {$count} expired token(s)?")) {
            $this->info('Operation cancelled.');

            return self::SUCCESS;
        }

        $revoked = ApiToken::expired()
            ->where('is_revoked', false)
            ->update([
                'is_revoked' => true,
                'revoked_at' => now(),
            ]);

        $this->info("Revoked {$revoked} expired token(s).");

        return self::SUCCESS;
    }

    /**
     * Revoke all tokens for a specific user.
     */
    protected function revokeUserTokens(string $userIdentifier): int
    {
        $userModel = config('auth.providers.users.model');
        $user = is_numeric($userIdentifier)
            ? $userModel::find($userIdentifier)
            : $userModel::where('email', $userIdentifier)->first();

        if (! $user) {
            $this->error("User not found: {$userIdentifier}");

            return self::FAILURE;
        }

        $query = ApiToken::where('tokenable_type', get_class($user))
            ->where('tokenable_id', $user->id)
            ->where('is_revoked', false);

        if (! $this->option('all')) {
            $this->error('Use --all flag to revoke all tokens for a user.');

            return self::FAILURE;
        }

        $count = $query->count();

        if ($count === 0) {
            $this->info('No active tokens to revoke for this user.');

            return self::SUCCESS;
        }

        if (! $this->option('force') && ! $this->confirm("Revoke {$count} token(s) for user {$userIdentifier}?")) {
            $this->info('Operation cancelled.');

            return self::SUCCESS;
        }

        $revoked = $query->update([
            'is_revoked' => true,
            'revoked_at' => now(),
        ]);

        $this->info("Revoked {$revoked} token(s) for user {$userIdentifier}.");

        return self::SUCCESS;
    }

    /**
     * Revoke all tokens.
     */
    protected function revokeAllTokens(): int
    {
        $count = ApiToken::where('is_revoked', false)->count();

        if ($count === 0) {
            $this->info('No active tokens to revoke.');

            return self::SUCCESS;
        }

        if (! $this->option('force') && ! $this->confirm("Are you sure you want to revoke ALL {$count} token(s)?")) {
            $this->info('Operation cancelled.');

            return self::SUCCESS;
        }

        $revoked = ApiToken::where('is_revoked', false)
            ->update([
                'is_revoked' => true,
                'revoked_at' => now(),
            ]);

        $this->info("Revoked {$revoked} token(s).");

        return self::SUCCESS;
    }
}
