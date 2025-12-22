<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Console\Commands;

use Illuminate\Console\Command;

class CheckApiSecurity extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'api:security:check';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Check API security configuration';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $this->info('Checking API Security Configuration...');
        $this->newLine();

        $errors = [];
        $warnings = [];
        $passes = [];

        // Check if API security is enabled
        if (! config('artisanpack.security.api.enabled')) {
            $warnings[] = 'API Security Layer is disabled.';
        } else {
            $passes[] = 'API Security Layer is enabled.';
        }

        // Check if Sanctum is installed
        if (! class_exists(\Laravel\Sanctum\Sanctum::class)) {
            $errors[] = 'Laravel Sanctum is not installed. Run: composer require laravel/sanctum';
        } else {
            $passes[] = 'Laravel Sanctum is installed.';
        }

        // Check token expiration configuration
        $expiration = config('artisanpack.security.api.tokens.expiration');
        if ($expiration === null) {
            $warnings[] = 'Token expiration is not set. Tokens will never expire.';
        } elseif ($expiration > 60 * 24 * 30) {
            $warnings[] = "Token expiration is set to {$expiration} minutes (more than 30 days).";
        } else {
            $passes[] = "Token expiration is set to {$expiration} minutes.";
        }

        // Check rate limiting
        if (! config('artisanpack.security.api.rate_limiting.enabled')) {
            $warnings[] = 'API rate limiting is disabled.';
        } else {
            $passes[] = 'API rate limiting is enabled.';
        }

        // Check HTTPS in production
        if (app()->isProduction()) {
            if (! request()->secure() && ! app()->runningInConsole()) {
                $errors[] = 'Application is not using HTTPS in production.';
            } else {
                $passes[] = 'HTTPS check passed (or running in console).';
            }
        }

        // Check ability groups are defined
        $groups = config('artisanpack.security.api.ability_groups', []);
        if (empty($groups)) {
            $warnings[] = 'No ability groups defined.';
        } else {
            $passes[] = count($groups) . ' ability group(s) defined.';
        }

        // Check abilities are defined
        $abilities = config('artisanpack.security.api.abilities', []);
        if (empty($abilities)) {
            $warnings[] = 'No abilities defined.';
        } else {
            $passes[] = count($abilities) . ' ability(ies) defined.';
        }

        // Display results
        if (! empty($passes)) {
            $this->info('Passes:');
            foreach ($passes as $pass) {
                $this->line("  <fg=green>✓</> {$pass}");
            }
            $this->newLine();
        }

        if (! empty($warnings)) {
            $this->warn('Warnings:');
            foreach ($warnings as $warning) {
                $this->line("  <fg=yellow>!</> {$warning}");
            }
            $this->newLine();
        }

        if (! empty($errors)) {
            $this->error('Errors:');
            foreach ($errors as $error) {
                $this->line("  <fg=red>✗</> {$error}");
            }
            $this->newLine();
        }

        // Summary
        $this->line('─────────────────────────────────────');
        $this->line(sprintf(
            '<fg=green>%d passed</>, <fg=yellow>%d warning(s)</>, <fg=red>%d error(s)</>',
            count($passes),
            count($warnings),
            count($errors)
        ));

        return empty($errors) ? self::SUCCESS : self::FAILURE;
    }
}
