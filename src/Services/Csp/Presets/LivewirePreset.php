<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Services\Csp\Presets;

use ArtisanPackUI\Security\Services\Csp\CspPolicyBuilder;

/**
 * CSP preset optimized for Livewire and Alpine.js applications.
 *
 * This preset uses nonces and 'strict-dynamic' to allow Livewire's
 * dynamic script loading while avoiding 'unsafe-inline' and 'unsafe-eval'.
 */
class LivewirePreset implements CspPresetInterface
{
    /**
     * Apply the Livewire-optimized preset to a policy builder.
     */
    public function apply(CspPolicyBuilder $builder, string $nonce): CspPolicyBuilder
    {
        $nonceValue = "'nonce-{$nonce}'";

        return $builder
            ->defaultSrc("'self'")
            ->scriptSrc("'self'", $nonceValue, "'strict-dynamic'")
            ->scriptSrcElem("'self'", $nonceValue)
            ->styleSrc("'self'", $nonceValue)
            ->styleSrcElem("'self'", $nonceValue)
            ->imgSrc("'self'", 'data:', 'blob:')
            ->fontSrc("'self'", 'data:')
            ->connectSrc("'self'", 'wss:', 'ws:')
            ->mediaSrc("'self'")
            ->objectSrc("'none'")
            ->baseUri("'self'")
            ->formAction("'self'")
            ->frameAncestors("'self'")
            ->upgradeInsecureRequests();
    }

    /**
     * Get the preset name.
     */
    public function getName(): string
    {
        return 'livewire';
    }

    /**
     * Get the preset description.
     */
    public function getDescription(): string
    {
        return 'Optimized for Livewire and Alpine.js applications with nonce-based security.';
    }
}
