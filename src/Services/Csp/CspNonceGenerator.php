<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Services\Csp;

/**
 * Generates cryptographically secure nonces for CSP.
 *
 * This service is registered as a scoped singleton to ensure
 * the same nonce is used throughout a single request lifecycle.
 */
class CspNonceGenerator
{
    /**
     * The generated nonce for the current request.
     */
    protected ?string $nonce = null;

    /**
     * The byte length for nonce generation.
     */
    protected int $length;

    /**
     * Create a new nonce generator instance.
     */
    public function __construct(?int $length = null)
    {
        $this->length = $length ?? config('artisanpack.security.csp.nonce.length', 16);
    }

    /**
     * Generate a new nonce.
     *
     * If a nonce has already been generated for this request,
     * the existing nonce will be returned.
     */
    public function generate(): string
    {
        if ($this->nonce === null) {
            $this->nonce = base64_encode(random_bytes($this->length));
        }

        return $this->nonce;
    }

    /**
     * Get the current nonce, generating one if necessary.
     */
    public function get(): string
    {
        return $this->nonce ?? $this->generate();
    }

    /**
     * Check if a nonce has been generated.
     */
    public function hasNonce(): bool
    {
        return $this->nonce !== null;
    }

    /**
     * Reset the nonce for a new request.
     */
    public function reset(): void
    {
        $this->nonce = null;
    }

    /**
     * Get the nonce formatted for CSP header use.
     */
    public function getFormatted(): string
    {
        return "'nonce-".$this->get()."'";
    }
}
