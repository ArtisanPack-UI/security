<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Console\Commands;

use ArtisanPackUI\Security\Contracts\CspPolicyInterface;
use ArtisanPackUI\Security\Services\Csp\CspPolicyBuilder;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;

class GenerateCspPolicy extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:generate-csp
                            {--preset=livewire : Base preset (livewire, strict, relaxed)}
                            {--analyze : Analyze application for required sources}
                            {--output= : Output file path for generated policy}
                            {--format=config : Output format (config, header, meta, nginx, apache, json)}
                            {--interactive : Interactive mode to build policy step-by-step}
                            {--report-only : Generate as report-only policy}
                            {--include-report-uri : Include violation reporting endpoint}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Generate Content Security Policy configurations based on presets or application analysis';

    /**
     * Detected sources from application analysis.
     *
     * @var array<string, array<string>>
     */
    protected array $detectedSources = [];

    /**
     * Execute the console command.
     */
    public function handle(CspPolicyInterface $csp): int
    {
        $this->info('CSP Policy Generator');
        $this->newLine();

        $preset = $this->option('preset');
        $availablePresets = array_keys($csp->getPresets());

        if (! in_array($preset, $availablePresets, true)) {
            $this->error("Invalid preset: {$preset}");
            $this->line('Available presets: '.implode(', ', $availablePresets));

            return self::FAILURE;
        }

        // Interactive mode
        if ($this->option('interactive')) {
            return $this->runInteractiveMode($csp);
        }

        // Apply preset
        $csp->usePreset($preset);
        $this->line("<fg=cyan>Using preset:</> {$preset}");

        // Analyze application if requested
        if ($this->option('analyze')) {
            $this->task('Analyzing application', function () {
                $this->analyzeApplication();

                return true;
            });

            if (! empty($this->detectedSources)) {
                $this->displayDetectedSources();
            }
        }

        // Include report URI if requested
        if ($this->option('include-report-uri')) {
            $reportUri = config('artisanpack.security.csp.reporting.uri', '/csp-violation');
            $csp->getBuilder()->reportUri(url($reportUri));
            $this->line('<fg=cyan>Report URI:</> '.url($reportUri));
        }

        $policy = $csp->getPolicy();
        $format = $this->option('format');
        $output = $this->formatOutput($policy, $format);

        $this->newLine();

        // Output to file or display
        if ($outputPath = $this->option('output')) {
            $result = File::put($outputPath, $output);
            if ($result === false) {
                $this->error("Failed to write policy to: {$outputPath}");

                return self::FAILURE;
            }
            $this->info("Policy saved to: {$outputPath}");
        } else {
            $this->displayOutput($output, $format);
        }

        // Show recommendations
        $this->displayRecommendations($policy);

        return self::SUCCESS;
    }

    /**
     * Run a task with visual feedback.
     */
    protected function task(string $title, callable $task): void
    {
        $this->output->write("  {$title}... ");

        try {
            $result = $task();
            $this->output->writeln($result ? '<fg=green>DONE</>' : '<fg=yellow>SKIPPED</>');
        } catch (\Exception $e) {
            $this->output->writeln('<fg=red>FAILED</>');
            $this->error("    Error: {$e->getMessage()}");
        }
    }

    /**
     * Run interactive mode to build policy step-by-step.
     */
    protected function runInteractiveMode(CspPolicyInterface $csp): int
    {
        $this->info('Interactive CSP Builder');
        $this->line('Build your Content Security Policy step by step.');
        $this->newLine();

        $builder = new CspPolicyBuilder;

        // Default source
        $defaultSrc = $this->choice(
            'What should be the default source policy?',
            ["'self'", "'none'", "'self' https:"],
            0
        );
        $builder->defaultSrc($defaultSrc);

        // Script sources
        $scriptChoice = $this->choice(
            'Script source policy?',
            [
                "'self' (same origin only)",
                "'self' 'unsafe-inline' (allow inline scripts)",
                "'self' 'nonce-...' (nonce-based)",
                "'self' 'strict-dynamic' (strict dynamic)",
                'Custom',
            ],
            2
        );
        $this->applyScriptChoice($builder, $scriptChoice, $csp->getNonce());

        // Style sources
        $styleChoice = $this->choice(
            'Style source policy?',
            [
                "'self' (same origin only)",
                "'self' 'unsafe-inline' (allow inline styles)",
                "'self' 'nonce-...' (nonce-based)",
                'Custom',
            ],
            1
        );
        $this->applyStyleChoice($builder, $styleChoice, $csp->getNonce());

        // Image sources
        $imgChoice = $this->choice(
            'Image source policy?',
            [
                "'self'",
                "'self' data:",
                "'self' data: https:",
                'Custom',
            ],
            1
        );
        $this->applyImgChoice($builder, $imgChoice);

        // Font sources
        $fontChoice = $this->choice(
            'Font source policy?',
            [
                "'self'",
                "'self' data:",
                "'self' https://fonts.gstatic.com https://fonts.bunny.net",
                'Custom',
            ],
            2
        );
        $this->applyFontChoice($builder, $fontChoice);

        // Frame ancestors
        $frameAncestors = $this->choice(
            'Who can embed your site in frames?',
            ["'none' (nobody)", "'self' (same origin)", 'Custom'],
            0
        );
        $this->applyFrameAncestorsChoice($builder, $frameAncestors);

        // Upgrade insecure requests
        if ($this->confirm('Upgrade insecure requests to HTTPS?', true)) {
            $builder->upgradeInsecureRequests();
        }

        // Report URI
        if ($this->confirm('Include violation reporting?', true)) {
            $reportUri = $this->ask('Report URI', '/csp-violation');
            $builder->reportUri(url($reportUri));
        }

        $policy = $builder->build();

        $this->newLine();
        $this->info('Generated Policy:');
        $this->line($policy);
        $this->newLine();

        // Output format
        $format = $this->choice(
            'Output format?',
            ['config', 'header', 'meta', 'nginx', 'apache', 'json'],
            0
        );

        $output = $this->formatOutput($policy, $format);

        if ($outputPath = $this->ask('Save to file? (leave empty to display)')) {
            $result = File::put($outputPath, $output);
            if ($result === false) {
                $this->error("Failed to save policy to: {$outputPath}");

                return self::FAILURE;
            }
            $this->info("Policy saved to: {$outputPath}");
        } else {
            $this->displayOutput($output, $format);
        }

        return self::SUCCESS;
    }

    /**
     * Apply script choice to builder.
     */
    protected function applyScriptChoice(CspPolicyBuilder $builder, string $choice, string $nonce): void
    {
        $nonceValue = "'nonce-{$nonce}'";

        if (str_contains($choice, 'same origin only')) {
            $builder->scriptSrc("'self'");
        } elseif (str_contains($choice, 'unsafe-inline')) {
            $builder->scriptSrc("'self'", "'unsafe-inline'");
        } elseif (str_contains($choice, 'nonce-based')) {
            $builder->scriptSrc("'self'", $nonceValue);
        } elseif (str_contains($choice, 'strict-dynamic')) {
            $builder->scriptSrc("'self'", "'strict-dynamic'", $nonceValue);
        } else {
            $custom = $this->ask('Enter custom script-src values (space-separated)');
            $builder->scriptSrc(...explode(' ', $custom));
        }
    }

    /**
     * Apply style choice to builder.
     */
    protected function applyStyleChoice(CspPolicyBuilder $builder, string $choice, string $nonce): void
    {
        $nonceValue = "'nonce-{$nonce}'";

        if (str_contains($choice, 'same origin only')) {
            $builder->styleSrc("'self'");
        } elseif (str_contains($choice, 'unsafe-inline')) {
            $builder->styleSrc("'self'", "'unsafe-inline'");
        } elseif (str_contains($choice, 'nonce-based')) {
            $builder->styleSrc("'self'", $nonceValue);
        } else {
            $custom = $this->ask('Enter custom style-src values (space-separated)');
            $builder->styleSrc(...explode(' ', $custom));
        }
    }

    /**
     * Apply image choice to builder.
     */
    protected function applyImgChoice(CspPolicyBuilder $builder, string $choice): void
    {
        if ($choice === "'self'") {
            $builder->imgSrc("'self'");
        } elseif ($choice === "'self' data:") {
            $builder->imgSrc("'self'", 'data:');
        } elseif ($choice === "'self' data: https:") {
            $builder->imgSrc("'self'", 'data:', 'https:');
        } else {
            $custom = $this->ask('Enter custom img-src values (space-separated)');
            $builder->imgSrc(...explode(' ', $custom));
        }
    }

    /**
     * Apply font choice to builder.
     */
    protected function applyFontChoice(CspPolicyBuilder $builder, string $choice): void
    {
        if ($choice === "'self'") {
            $builder->fontSrc("'self'");
        } elseif ($choice === "'self' data:") {
            $builder->fontSrc("'self'", 'data:');
        } elseif (str_contains($choice, 'fonts.gstatic.com')) {
            $builder->fontSrc("'self'", 'https://fonts.gstatic.com', 'https://fonts.bunny.net');
        } else {
            $custom = $this->ask('Enter custom font-src values (space-separated)');
            $builder->fontSrc(...explode(' ', $custom));
        }
    }

    /**
     * Apply frame ancestors choice to builder.
     */
    protected function applyFrameAncestorsChoice(CspPolicyBuilder $builder, string $choice): void
    {
        if (str_contains($choice, 'nobody')) {
            $builder->frameAncestors("'none'");
        } elseif (str_contains($choice, 'same origin')) {
            $builder->frameAncestors("'self'");
        } else {
            $custom = $this->ask('Enter custom frame-ancestors values (space-separated)');
            $builder->frameAncestors(...explode(' ', $custom));
        }
    }

    /**
     * Analyze application for required CSP sources.
     */
    protected function analyzeApplication(): void
    {
        $this->detectedSources = [
            'script-src' => [],
            'style-src' => [],
            'img-src' => [],
            'font-src' => [],
            'connect-src' => [],
            'frame-src' => [],
        ];

        $viewsPath = resource_path('views');

        if (! File::isDirectory($viewsPath)) {
            return;
        }

        $files = File::allFiles($viewsPath);

        foreach ($files as $file) {
            if ($file->getExtension() !== 'php') {
                continue;
            }

            $content = File::get($file->getPathname());
            $this->analyzeContent($content);
        }

        // Check public assets
        $this->analyzePublicAssets();

        // Deduplicate
        foreach ($this->detectedSources as $directive => $sources) {
            $this->detectedSources[$directive] = array_unique($sources);
        }
    }

    /**
     * Analyze content for external sources.
     */
    protected function analyzeContent(string $content): void
    {
        // Scripts
        preg_match_all('/<script[^>]*src=["\']([^"\']+)["\'][^>]*>/i', $content, $scripts);
        foreach ($scripts[1] as $src) {
            $this->addDetectedSource('script-src', $src);
        }

        // Check for inline scripts
        if (preg_match('/<script(?![^>]*src)[^>]*>/i', $content)) {
            $this->detectedSources['script-src'][] = "'unsafe-inline' or nonce required";
        }

        // Styles
        preg_match_all('/<link[^>]*href=["\']([^"\']+\.css[^"\']*)["\'][^>]*>/i', $content, $styles);
        foreach ($styles[1] as $href) {
            $this->addDetectedSource('style-src', $href);
        }

        // Check for inline styles
        if (preg_match('/<style[^>]*>/i', $content) || preg_match('/style=["\'][^"\']+["\']/i', $content)) {
            $this->detectedSources['style-src'][] = "'unsafe-inline' or nonce required";
        }

        // Images
        preg_match_all('/<img[^>]*src=["\']([^"\']+)["\'][^>]*>/i', $content, $images);
        foreach ($images[1] as $src) {
            $this->addDetectedSource('img-src', $src);
        }

        // Fonts (from CSS @font-face or link preload)
        preg_match_all('/<link[^>]*href=["\']([^"\']*fonts[^"\']*)["\'][^>]*>/i', $content, $fonts);
        foreach ($fonts[1] as $href) {
            $this->addDetectedSource('font-src', $href);
        }

        // Iframes
        preg_match_all('/<iframe[^>]*src=["\']([^"\']+)["\'][^>]*>/i', $content, $iframes);
        foreach ($iframes[1] as $src) {
            $this->addDetectedSource('frame-src', $src);
        }

        // Fetch/XHR (common patterns)
        preg_match_all('/fetch\s*\(\s*["\']([^"\']+)["\']/i', $content, $fetches);
        foreach ($fetches[1] as $url) {
            $this->addDetectedSource('connect-src', $url);
        }
    }

    /**
     * Add a detected source to the appropriate directive.
     */
    protected function addDetectedSource(string $directive, string $source): void
    {
        // Skip Blade variables
        if (str_contains($source, '{{') || str_contains($source, '{!!')) {
            return;
        }

        // Skip relative URLs (covered by 'self')
        if (str_starts_with($source, '/') && ! str_starts_with($source, '//')) {
            return;
        }

        // Extract domain from absolute URLs
        if (str_starts_with($source, 'http://') || str_starts_with($source, 'https://') || str_starts_with($source, '//')) {
            $parsed = parse_url($source);
            if (isset($parsed['host'])) {
                $scheme = $parsed['scheme'] ?? 'https';
                $this->detectedSources[$directive][] = "{$scheme}://{$parsed['host']}";
            }
        } elseif (str_starts_with($source, 'data:')) {
            $this->detectedSources[$directive][] = 'data:';
        }
    }

    /**
     * Analyze public assets for external dependencies.
     */
    protected function analyzePublicAssets(): void
    {
        // Check for common CDN patterns in mix-manifest or vite manifest
        $manifestPaths = [
            public_path('mix-manifest.json'),
            public_path('build/manifest.json'),
            public_path('.vite/manifest.json'),
        ];

        foreach ($manifestPaths as $path) {
            if (File::exists($path)) {
                $content = File::get($path);
                // Assets from manifest are typically self-hosted
                // Just note that we found a manifest
                break;
            }
        }

        // Check package.json for common CDN-based packages
        $packageJson = base_path('package.json');
        if (File::exists($packageJson)) {
            $package = json_decode(File::get($packageJson), true);
            $dependencies = array_merge(
                $package['dependencies'] ?? [],
                $package['devDependencies'] ?? []
            );

            // Note common packages that might suggest CDN usage
            $cdnPackages = ['alpinejs', 'livewire', 'htmx.org'];
            foreach ($cdnPackages as $pkg) {
                if (isset($dependencies[$pkg])) {
                    // These are typically bundled, but note for reference
                }
            }
        }
    }

    /**
     * Display detected sources from analysis.
     */
    protected function displayDetectedSources(): void
    {
        $this->newLine();
        $this->info('Detected External Sources:');
        $this->newLine();

        $hasFindings = false;
        foreach ($this->detectedSources as $directive => $sources) {
            $sources = array_filter($sources);
            if (empty($sources)) {
                continue;
            }

            $hasFindings = true;
            $this->line("<fg=cyan>{$directive}:</>");
            foreach ($sources as $source) {
                $this->line("  - {$source}");
            }
        }

        if (! $hasFindings) {
            $this->line('<fg=green>No external sources detected. Your app may be fully self-contained.</>');
        }

        $this->newLine();
    }

    /**
     * Format the policy output based on format option.
     */
    protected function formatOutput(string $policy, string $format): string
    {
        $isReportOnly = $this->option('report-only');
        $headerName = $isReportOnly ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';

        return match ($format) {
            'header' => "{$headerName}: {$policy}",
            'meta' => '<meta http-equiv="'.$headerName.'" content="'.htmlspecialchars($policy, ENT_QUOTES).'">',
            'nginx' => "add_header {$headerName} \"{$policy}\" always;",
            'apache' => "Header always set {$headerName} \"{$policy}\"",
            'json' => json_encode([
                'header_name' => $headerName,
                'policy' => $policy,
                'directives' => $this->parseDirectives($policy),
                'report_only' => $isReportOnly,
            ], JSON_PRETTY_PRINT),
            default => $this->formatAsConfig($policy, $isReportOnly), // 'config'
        };
    }

    /**
     * Format policy as PHP config array.
     */
    protected function formatAsConfig(string $policy, bool $isReportOnly): string
    {
        $directives = $this->parseDirectives($policy);
        $headerName = $isReportOnly ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';

        $output = "<?php\n\n";
        $output .= "// Generated CSP Configuration\n";
        $output .= "// Add this to your config/artisanpack/security.php 'security-headers' section\n\n";
        $output .= "return [\n";
        $output .= "    'security-headers' => [\n";
        $output .= "        // ... other headers ...\n";
        $output .= "        '{$headerName}' => implode('; ', [\n";

        foreach ($directives as $directive => $values) {
            $valuesStr = implode(' ', $values);
            $output .= "            \"{$directive} {$valuesStr}\",\n";
        }

        $output .= "        ]),\n";
        $output .= "    ],\n";
        $output .= "];\n";

        return $output;
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
            if ($tokens === false) {
                continue;
            }
            $directive = array_shift($tokens);
            $directives[$directive] = $tokens;
        }

        return $directives;
    }

    /**
     * Display formatted output.
     */
    protected function displayOutput(string $output, string $format): void
    {
        $this->info("Generated Policy ({$format} format):");
        $this->newLine();

        if ($format === 'json') {
            $this->line($output);
        } else {
            $this->line('<fg=yellow>'.$output.'</>');
        }

        $this->newLine();
    }

    /**
     * Display recommendations based on the policy.
     */
    protected function displayRecommendations(string $policy): void
    {
        $this->newLine();
        $this->info('Recommendations:');

        $recommendations = [];
        $directives = $this->parseDirectives($policy);

        // Check for unsafe-inline without nonce
        if (isset($directives['script-src'])) {
            if (in_array("'unsafe-inline'", $directives['script-src'], true)) {
                $hasNonce = false;
                foreach ($directives['script-src'] as $value) {
                    if (str_starts_with($value, "'nonce-")) {
                        $hasNonce = true;
                        break;
                    }
                }
                if (! $hasNonce && ! in_array("'strict-dynamic'", $directives['script-src'], true)) {
                    $recommendations[] = "<fg=yellow>Consider using nonces instead of 'unsafe-inline' for scripts</>";
                }
            }
        }

        // Check for unsafe-eval
        if (isset($directives['script-src']) && in_array("'unsafe-eval'", $directives['script-src'], true)) {
            $recommendations[] = "<fg=yellow>Consider removing 'unsafe-eval' if not required by your framework</>";
        }

        // Check for missing directives
        $important = ['default-src', 'script-src', 'style-src', 'frame-ancestors'];
        foreach ($important as $directive) {
            if (! isset($directives[$directive])) {
                $recommendations[] = "<fg=blue>Consider adding {$directive} directive</>";
            }
        }

        // Check for upgrade-insecure-requests
        if (! isset($directives['upgrade-insecure-requests'])) {
            $recommendations[] = '<fg=blue>Consider adding upgrade-insecure-requests for HTTPS migration</>';
        }

        if (empty($recommendations)) {
            $this->line('<fg=green>Policy looks well-configured!</>');
        } else {
            foreach ($recommendations as $rec) {
                $this->line("  - {$rec}");
            }
        }
    }
}
