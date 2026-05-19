<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Services\Csp\Presets;

use ArtisanPackUI\Security\Services\Csp\CspPolicyBuilder;

/**
 * Strict CSP preset for maximum security.
 *
 * This preset is highly restrictive and may break some functionality.
 * Use for high-security areas where content is tightly controlled.
 */
class StrictPreset implements CspPresetInterface
{
    /**
     * Apply the strict preset to a policy builder.
     */
    public function apply(CspPolicyBuilder $builder, string $nonce): CspPolicyBuilder
    {
        $nonceValue = "'nonce-{$nonce}'";

        return $builder
            ->defaultSrc("'none'")
            ->scriptSrc("'self'", $nonceValue)
            ->styleSrc("'self'", $nonceValue)
            ->imgSrc("'self'")
            ->fontSrc("'self'")
            ->connectSrc("'self'")
            ->mediaSrc("'self'")
            ->objectSrc("'none'")
            ->frameSrc("'none'")
            ->childSrc("'none'")
            ->workerSrc("'self'")
            ->baseUri("'none'")
            ->formAction("'self'")
            ->frameAncestors("'none'")
            ->upgradeInsecureRequests()
            ->blockAllMixedContent();
    }

    /**
     * Get the preset name.
     */
    public function getName(): string
    {
        return 'strict';
    }

    /**
     * Get the preset description.
     */
    public function getDescription(): string
    {
        return 'Maximum security preset with highly restrictive rules. May break some functionality.';
    }
}
