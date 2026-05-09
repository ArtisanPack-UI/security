<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\View\Components;

use ArtisanPackUI\Security\Contracts\CspPolicyInterface;
use Illuminate\View\Component;

class CspNonce extends Component
{
    /**
     * The CSP nonce value.
     */
    public string $nonce;

    /**
     * Create a new component instance.
     */
    public function __construct(?CspPolicyInterface $csp = null)
    {
        $csp         = $csp ?? app(CspPolicyInterface::class);
        $this->nonce = $csp->getNonce();
    }

    /**
     * Get the view / contents that represent the component.
     */
    public function render(): string
    {
        return $this->nonce;
    }
}
