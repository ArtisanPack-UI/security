<?php

/**
 * CspPolicyService CSP service.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Services\Csp;

use ArtisanPackUI\Security\Contracts\CspPolicyInterface;
use ArtisanPackUI\Security\Contracts\SecurityEventLoggerInterface;
use ArtisanPackUI\Security\Services\Csp\Presets\CspPresetInterface;
use ArtisanPackUI\Security\Services\Csp\Presets\LivewirePreset;
use ArtisanPackUI\Security\Services\Csp\Presets\RelaxedPreset;
use ArtisanPackUI\Security\Services\Csp\Presets\StrictPreset;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

/**
 * Main CSP policy service that coordinates policy generation.
 */
class CspPolicyService implements CspPolicyInterface
{
    /**
     * The policy builder instance.
     */
    protected CspPolicyBuilder $builder;

    /**
     * Available presets.
     *
     * @var array<string, CspPresetInterface>
     */
    protected array $presets = [];

    /**
     * The current preset name.
     */
    protected ?string $currentPreset = null;

    /**
     * Whether the policy has been built for the current request.
     */
    protected bool $isBuilt = false;

    /**
     * The request the policy was configured for, if any.
     */
    protected ?Request $request = null;

    /**
     * Create a new CSP policy service instance.
     */
    public function __construct(
        protected CspNonceGenerator $nonceGenerator,
        protected ?SecurityEventLoggerInterface $logger = null,
    ) {
        $this->builder = new CspPolicyBuilder;
        $this->registerDefaultPresets();
    }

    /**
     * Register a custom preset.
     */
    public function registerPreset(string $name, CspPresetInterface $preset): self
    {
        $this->presets[$name] = $preset;

        return $this;
    }

    /**
     * Get the nonce for the current request.
     */
    public function getNonce(): string
    {
        return $this->nonceGenerator->get();
    }

    /**
     * Add a value to a CSP directive.
     *
     * @param  array<string>|string  $values
     */
    public function addDirective(string $directive, string|array $values): self
    {
        $this->builder->addDirective($directive, $values);

        return $this;
    }

    /**
     * Remove a directive from the policy.
     */
    public function removeDirective(string $directive): self
    {
        $this->builder->removeDirective($directive);

        return $this;
    }

    /**
     * Configure the policy for a specific request.
     */
    public function forRequest(Request $request): self
    {
        $this->request = $request;

        if ($this->isBuilt) {
            return $this;
        }

        // Check for excluded routes
        if ($this->isExcludedRoute($request)) {
            return $this;
        }

        // Determine which preset to use
        $presetName = $this->determinePreset($request);

        // Apply the preset
        $this->usePreset($presetName);

        // Apply additional sources from config
        $this->applyAdditionalSources();

        // Add report URI if reporting is enabled
        $this->applyReportingConfig();

        $this->isBuilt = true;

        // Log policy if debugging is enabled (nonce excluded for security)
        if (config('artisanpack.security.csp.debug.logPolicy', false)) {
            Log::debug('CSP Policy Generated', [
                'preset' => $presetName,
                'policy' => $this->getPolicy(),
            ]);
        }

        return $this;
    }

    /**
     * Apply a named preset to the policy.
     */
    public function usePreset(string $preset): self
    {
        if (! isset($this->presets[$preset])) {
            $preset = 'livewire'; // Default fallback
        }

        $this->currentPreset = $preset;
        $this->builder->reset();
        $this->presets[$preset]->apply($this->builder, $this->getNonce());

        return $this;
    }

    /**
     * Get the full CSP policy string.
     *
     * Fires the `ap.security.csp.directives` filter with the assembled
     * directive array and the current `Request` (or a fresh instance if
     * the policy hasn't been configured for a specific request) so host
     * apps can add, remove, or rewrite directives before the header is
     * serialized.
     */
    public function getPolicy(): string
    {
        $directives = applyFilters(
            'ap.security.csp.directives',
            $this->builder->getDirectives(),
            $this->request ?? request(),
        );

        if (! is_array($directives)) {
            return $this->builder->build();
        }

        return CspPolicyBuilder::buildFrom($directives);
    }

    /**
     * Get the policy as a report-only header value.
     */
    public function getReportOnlyPolicy(): string
    {
        return $this->getPolicy();
    }

    /**
     * Get the headers to apply to the response.
     *
     * @return array<string, string>
     */
    public function toHeader(): array
    {
        $policy = $this->getPolicy();
        $headers = [];

        if (empty($policy)) {
            return $headers;
        }

        if (config('artisanpack.security.csp.reportOnly', false)) {
            $headers['Content-Security-Policy-Report-Only'] = $policy;
        } else {
            $headers['Content-Security-Policy'] = $policy;

            // Optionally also send report-only for monitoring
            if (config('artisanpack.security.csp.dualHeader', false)) {
                $headers['Content-Security-Policy-Report-Only'] = $policy;
            }
        }

        return $headers;
    }

    /**
     * Render a meta tag containing the nonce for JavaScript access.
     */
    public function renderMetaTag(): string
    {
        if (! config('artisanpack.security.csp.nonce.metaTag', true)) {
            return '';
        }

        $nonce = $this->getNonce();

        return '<meta name="csp-nonce" content="'.$nonce.'">';
    }

    /**
     * Reset the policy to defaults.
     */
    public function reset(): self
    {
        $this->builder->reset();
        $this->nonceGenerator->reset();
        $this->isBuilt = false;
        $this->currentPreset = null;
        $this->request = null;

        return $this;
    }

    /**
     * Get the policy builder for advanced customization.
     */
    public function getBuilder(): CspPolicyBuilder
    {
        return $this->builder;
    }

    /**
     * Get the current preset name.
     */
    public function getCurrentPreset(): ?string
    {
        return $this->currentPreset;
    }

    /**
     * Get all registered presets.
     *
     * @return array<string, CspPresetInterface>
     */
    public function getPresets(): array
    {
        return $this->presets;
    }

    /**
     * Check if CSP is enabled.
     */
    public function isEnabled(): bool
    {
        return config('artisanpack.security.csp.enabled', true);
    }

    /**
     * Check if report-only mode is enabled.
     */
    public function isReportOnly(): bool
    {
        return config('artisanpack.security.csp.reportOnly', false);
    }

    /**
     * Register the default presets.
     */
    protected function registerDefaultPresets(): void
    {
        $this->presets = [
            'livewire' => new LivewirePreset,
            'strict' => new StrictPreset,
            'relaxed' => new RelaxedPreset,
        ];
    }

    /**
     * Determine which preset to use for the request.
     */
    protected function determinePreset(Request $request): string
    {
        $routePolicies = config('artisanpack.security.csp.routePolicies', []);
        $path = $request->path();

        foreach ($routePolicies as $pattern => $preset) {
            if ($this->matchesPattern($path, $pattern)) {
                return $preset;
            }
        }

        return config('artisanpack.security.csp.preset', 'livewire');
    }

    /**
     * Check if a path matches a pattern.
     */
    protected function matchesPattern(string $path, string $pattern): bool
    {
        $pattern = str_replace('*', '.*', $pattern);

        return (bool) preg_match('#^'.$pattern.'$#', $path);
    }

    /**
     * Check if the route is excluded from CSP.
     */
    protected function isExcludedRoute(Request $request): bool
    {
        $excludedRoutes = config('artisanpack.security.csp.excludedRoutes', []);
        $path = $request->path();

        foreach ($excludedRoutes as $pattern) {
            if ($this->matchesPattern($path, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Apply additional sources from configuration.
     */
    protected function applyAdditionalSources(): void
    {
        $additionalSources = config('artisanpack.security.csp.additionalSources', []);

        foreach ($additionalSources as $directive => $sources) {
            if (! empty($sources)) {
                $this->builder->addDirective($directive, $sources);
            }
        }
    }

    /**
     * Apply reporting configuration.
     */
    protected function applyReportingConfig(): void
    {
        if (config('artisanpack.security.csp.reporting.enabled', true)) {
            $reportUri = config('artisanpack.security.csp.reporting.uri', '/csp-violation');
            $this->builder->reportUri(url($reportUri));
        }
    }
}
