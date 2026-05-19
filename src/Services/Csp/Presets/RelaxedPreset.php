<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Services\Csp\Presets;

use ArtisanPackUI\Security\Services\Csp\CspPolicyBuilder;

/**
 * Relaxed CSP preset for development and testing.
 *
 * This preset is more permissive and suitable for development environments
 * or applications that need to load resources from various sources.
 * Not recommended for production use without modification.
 */
class RelaxedPreset implements CspPresetInterface
{
    /**
     * Apply the relaxed preset to a policy builder.
     */
    public function apply(CspPolicyBuilder $builder, string $nonce): CspPolicyBuilder
    {
        $nonceValue = "'nonce-{$nonce}'";

        return $builder
            ->defaultSrc("'self'")
            ->scriptSrc("'self'", $nonceValue, "'strict-dynamic'", 'https:')
            ->styleSrc("'self'", $nonceValue, 'https:')
            ->imgSrc("'self'", 'data:', 'blob:', 'https:')
            ->fontSrc("'self'", 'data:', 'https:')
            ->connectSrc("'self'", 'https:', 'wss:', 'ws:')
            ->mediaSrc("'self'", 'https:')
            ->objectSrc("'none'")
            ->frameSrc("'self'", 'https:')
            ->baseUri("'self'")
            ->formAction("'self'", 'https:')
            ->frameAncestors("'self'");
    }

    /**
     * Get the preset name.
     */
    public function getName(): string
    {
        return 'relaxed';
    }

    /**
     * Get the preset description.
     */
    public function getDescription(): string
    {
        return 'Development-friendly preset with permissive rules. Not recommended for production.';
    }
}
