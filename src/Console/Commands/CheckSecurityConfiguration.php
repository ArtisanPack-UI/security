<?php

namespace ArtisanPackUI\Security\Console\Commands;

use ArtisanPackUI\Security\Services\EnvironmentValidationService;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\App;

class CheckSecurityConfiguration extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:check-config';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Check the security configuration of the application.';

    /**
     * @var EnvironmentValidationService
     */
    protected $validator;

    public function __construct(EnvironmentValidationService $validator)
    {
        parent::__construct();
        $this->validator = $validator;
    }

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(): int
    {
        $environment = App::environment();
        $this->info("Checking security configuration for the '{$environment}' environment...");

        $results = $this->validator->validate($environment);
        $errors = $results['errors'];
        $warnings = $results['warnings'];

        if (empty($errors) && empty($warnings)) {
            $this->info('All security checks passed!');
            return 0;
        }

        if (!empty($errors)) {
            $this->error('Errors found:');
            foreach ($errors as $error) {
                $this->line("- {$error}");
            }
        }

        if (!empty($warnings)) {
            $this->warn('Warnings found:');
            foreach ($warnings as $warning) {
                $this->line("- {$warning}");
            }
        }

        if (!empty($errors)) {
            $this->error('Security configuration check failed.');
            return 1;
        }

        $this->warn('Security configuration check passed with warnings.');
        return 0;
    }
}
