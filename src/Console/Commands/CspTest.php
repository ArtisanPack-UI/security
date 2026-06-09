<?php

/**
 * `CspTest` Artisan command.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Console\Commands;

use ArtisanPackUI\Security\Contracts\CspPolicyInterface;
use Illuminate\Console\Command;

class CspTest extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:csp:test
                            {--preset= : Preset to test (livewire, strict, relaxed)}
                            {--show-policy : Display the full policy string}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Test and display CSP policy configuration';

    /**
     * Execute the console command.
     */
    public function handle(CspPolicyInterface $csp): int
    {
        $preset = $this->option('preset');

        $this->info('CSP Policy Test');
        $this->newLine();

        // Show configuration
        $this->displayConfiguration();

        // Apply preset if specified
        if ($preset) {
            $availablePresets = array_keys($csp->getPresets());

            if (! in_array($preset, $availablePresets, true)) {
                $this->error("Invalid preset: {$preset}");
                $this->line('Available presets: '.implode(', ', $availablePresets));

                return self::FAILURE;
            }

            $csp->usePreset($preset);
            $this->line("<fg=cyan>Using preset:</> {$preset}");
        }

        $this->newLine();

        // Get headers
        $headers = $csp->toHeader();

        // Display policy info
        $this->info('Policy Headers:');
        foreach ($headers as $name => $value) {
            $this->line("<fg=cyan>{$name}:</>");
            if ($this->option('show-policy')) {
                $this->line($value);
            } else {
                $this->line($this->truncatePolicy($value));
            }
            $this->newLine();
        }

        // Show nonce
        $this->info('Generated Nonce:');
        $this->line($csp->getNonce());
        $this->newLine();

        // Analyze the policy
        $this->analyzePolicy($csp->getPolicy());

        // Security recommendations
        $this->displayRecommendations($csp->getPolicy());

        return self::SUCCESS;
    }

    /**
     * Display current CSP configuration.
     */
    protected function displayConfiguration(): void
    {
        $this->info('Current Configuration:');

        $config = [
            ['Enabled', config('artisanpack.security.csp.enabled', true) ? '<fg=green>Yes</>' : '<fg=red>No</>'],
            ['Report Only', config('artisanpack.security.csp.reportOnly', false) ? '<fg=yellow>Yes</>' : '<fg=green>No (Enforcing)</>'],
            ['Default Preset', config('artisanpack.security.csp.preset', 'livewire')],
            ['Report URI', config('artisanpack.security.csp.reporting.uri', '/csp-violation')],
            ['Store Violations', config('artisanpack.security.csp.reporting.storeViolations', true) ? 'Yes' : 'No'],
        ];

        $this->table(['Setting', 'Value'], $config);
    }

    /**
     * Truncate policy for display.
     */
    protected function truncatePolicy(string $policy): string
    {
        if (strlen($policy) <= 100) {
            return $policy;
        }

        return substr($policy, 0, 97).'...';
    }

    /**
     * Analyze the policy and display breakdown.
     */
    protected function analyzePolicy(string $policy): void
    {
        $this->info('Policy Analysis:');

        $directives = $this->parseDirectives($policy);

        if (empty($directives)) {
            $this->warn('No directives found in policy.');

            return;
        }

        $rows = [];
        foreach ($directives as $directive => $values) {
            $status = $this->analyzeDirective($directive, $values);
            $rows[] = [
                $directive,
                $this->formatValues($values),
                $status,
            ];
        }

        $this->table(['Directive', 'Values', 'Status'], $rows);
    }

    /**
     * Parse directives from policy string.
     *
     * @return array<string, array<string>>
     */
    protected function parseDirectives(string $policy): array
    {
        $directives = [];
        $parts = explode(';', $policy);

        foreach ($parts as $part) {
            $part = trim($part);
            if (empty($part)) {
                continue;
            }

            $tokens = preg_split('/\s+/', $part);
            $directive = array_shift($tokens);
            $directives[$directive] = $tokens;
        }

        return $directives;
    }

    /**
     * Analyze a single directive.
     *
     * @param  array<string>  $values
     */
    protected function analyzeDirective(string $directive, array $values): string
    {
        // Check for unsafe practices
        if (in_array("'unsafe-inline'", $values, true) && ! in_array("'strict-dynamic'", $values, true)) {
            return '<fg=red>Unsafe (inline)</>';
        }

        if (in_array("'unsafe-eval'", $values, true)) {
            return '<fg=red>Unsafe (eval)</>';
        }

        // Check for wildcards
        if (in_array('*', $values, true)) {
            return '<fg=yellow>Permissive (*)</>';
        }

        // Check for data: URIs
        if (in_array('data:', $values, true) && in_array($directive, ['script-src', 'object-src'], true)) {
            return '<fg=yellow>Has data: URI</>';
        }

        // Check for strict-dynamic (good for scripts)
        if ($directive === 'script-src' && in_array("'strict-dynamic'", $values, true)) {
            return '<fg=green>Strict Dynamic</>';
        }

        // Check for nonce
        $hasNonce = false;
        foreach ($values as $value) {
            if (str_starts_with($value, "'nonce-")) {
                $hasNonce = true;
                break;
            }
        }

        if ($hasNonce) {
            return '<fg=green>Nonce-based</>';
        }

        // Check for none
        if (in_array("'none'", $values, true)) {
            return '<fg=green>Blocked</>';
        }

        // Check for self only
        if (count($values) === 1 && $values[0] === "'self'") {
            return '<fg=green>Self only</>';
        }

        return '<fg=blue>Configured</>';
    }

    /**
     * Format values for display.
     *
     * @param  array<string>  $values
     */
    protected function formatValues(array $values): string
    {
        $display = implode(' ', array_slice($values, 0, 3));

        if (count($values) > 3) {
            $display .= ' (+'.(count($values) - 3).' more)';
        }

        return $display;
    }

    /**
     * Display security recommendations.
     */
    protected function displayRecommendations(string $policy): void
    {
        $this->newLine();
        $this->info('Security Recommendations:');

        $recommendations = [];
        $directives = $this->parseDirectives($policy);

        // Check for missing important directives
        $important = ['default-src', 'script-src', 'style-src', 'object-src', 'base-uri', 'frame-ancestors'];
        foreach ($important as $directive) {
            if (! isset($directives[$directive])) {
                $recommendations[] = "<fg=yellow>Consider adding {$directive} directive</>";
            }
        }

        // Check for upgrade-insecure-requests
        if (! isset($directives['upgrade-insecure-requests'])) {
            $recommendations[] = '<fg=blue>Consider adding upgrade-insecure-requests for HTTPS migration</>';
        }

        // Check for report-uri
        if (! isset($directives['report-uri']) && ! isset($directives['report-to'])) {
            $recommendations[] = '<fg=blue>Consider enabling violation reporting</>';
        }

        // Check for unsafe inline without nonce
        if (isset($directives['script-src'])) {
            $scriptSrc = $directives['script-src'];
            $hasNonce = false;
            foreach ($scriptSrc as $value) {
                if (str_starts_with($value, "'nonce-")) {
                    $hasNonce = true;
                    break;
                }
            }

            if (in_array("'unsafe-inline'", $scriptSrc, true) && ! $hasNonce && ! in_array("'strict-dynamic'", $scriptSrc, true)) {
                $recommendations[] = "<fg=red>script-src uses 'unsafe-inline' without nonce - consider nonce-based approach</>";
            }
        }

        if (empty($recommendations)) {
            $this->line('<fg=green>No immediate recommendations. Policy looks well-configured.</>');
        } else {
            foreach ($recommendations as $rec) {
                $this->line("  - {$rec}");
            }
        }
    }
}
