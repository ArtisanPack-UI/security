<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Console\Commands;

use Illuminate\Console\Command;

class CreateApiToken extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'api:token:create
                            {user : The user ID or email}
                            {--name= : The token name}
                            {--abilities=* : The token abilities}
                            {--group= : Use an ability group instead of individual abilities}
                            {--expires= : Token expiration in minutes}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Create a new API token for a user';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $userModel = config('auth.providers.users.model');

        if (! $userModel) {
            $this->error('User model not configured in auth.providers.users.model');

            return self::FAILURE;
        }

        $userIdentifier = $this->argument('user');

        // Find user by ID or email
        $user = is_numeric($userIdentifier)
            ? $userModel::find($userIdentifier)
            : $userModel::where('email', $userIdentifier)->first();

        if (! $user) {
            $this->error("User not found: {$userIdentifier}");

            return self::FAILURE;
        }

        // Check if user has the HasApiTokens trait
        if (! method_exists($user, 'createApiToken') && ! method_exists($user, 'createToken')) {
            $this->error('User model does not have API token capabilities. Add the HasApiTokens trait.');

            return self::FAILURE;
        }

        $name = $this->option('name') ?? 'cli-generated-' . now()->timestamp;
        $expires = $this->option('expires') ? (int) $this->option('expires') : null;
        $group = $this->option('group');
        $abilities = $this->option('abilities');

        // Determine abilities from group or direct input
        if ($group) {
            $groups = config('artisanpack.security.api.ability_groups', []);
            if (! isset($groups[$group])) {
                $this->error("Unknown ability group: {$group}");
                $this->info('Available groups: ' . implode(', ', array_keys($groups)));

                return self::FAILURE;
            }
            $abilities = $groups[$group];
        } elseif (empty($abilities)) {
            $abilities = ['*'];
        }

        // Create the token
        if (method_exists($user, 'createApiToken')) {
            $token = $user->createApiToken($name, $abilities, $expires);
        } else {
            // Fallback to standard Sanctum
            if ($expires !== null) {
                $this->warn('Warning: Standard Sanctum tokens do not support the --expires option.');
                $this->warn('The token will be created without expiration. Use the HasApiTokens trait from this package for expiration support.');
            }
            $token = $user->createToken($name, $abilities);

            // If expiration was requested, attempt to set it manually on the token record
            if ($expires !== null && $token->accessToken && method_exists($token->accessToken, 'forceFill')) {
                $token->accessToken->forceFill([
                    'expires_at' => now()->addMinutes($expires),
                ])->save();
                $this->info('Expiration has been set manually on the token record.');
            }
        }

        $this->info('API token created successfully!');
        $this->newLine();

        $this->table(
            ['Property', 'Value'],
            [
                ['User', $user->email ?? $user->id],
                ['Token Name', $name],
                ['Abilities', implode(', ', $abilities)],
                ['Expires', $expires ? "In {$expires} minutes" : 'Never'],
            ]
        );

        $this->newLine();
        $this->warn('Make sure to copy the token now. You won\'t be able to see it again!');
        $this->newLine();
        $this->line('<fg=green>Token:</> ' . $token->plainTextToken);

        return self::SUCCESS;
    }
}
