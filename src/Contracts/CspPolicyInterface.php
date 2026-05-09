<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Contracts;

use Illuminate\Http\Request;

interface CspPolicyInterface
{
    /**
     * Get the nonce for the current request.
     */
    public function getNonce(): string;

    /**
     * Add a value to a CSP directive.
     *
     * @param  array<string>|string  $values
     */
    public function addDirective(string $directive, string|array $values): self;

    /**
     * Remove a directive from the policy.
     */
    public function removeDirective(string $directive): self;

    /**
     * Get the full CSP policy string.
     */
    public function getPolicy(): string;

    /**
     * Get the policy as a report-only header value.
     */
    public function getReportOnlyPolicy(): string;

    /**
     * Get the headers to apply to the response.
     *
     * @return array<string, string>
     */
    public function toHeader(): array;

    /**
     * Configure the policy for a specific request.
     */
    public function forRequest(Request $request): self;

    /**
     * Apply a named preset to the policy.
     */
    public function usePreset(string $preset): self;

    /**
     * Get all registered presets.
     *
     * @return array<string, \ArtisanPackUI\Security\Services\Csp\Presets\CspPresetInterface>
     */
    public function getPresets(): array;

    /**
     * Render a meta tag containing the nonce for JavaScript access.
     */
    public function renderMetaTag(): string;

    /**
     * Reset the policy to defaults.
     */
    public function reset(): self;
}
