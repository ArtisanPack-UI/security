<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Services\Csp;

/**
 * Fluent builder for constructing Content Security Policy directives.
 */
class CspPolicyBuilder
{
    /**
     * Valid CSP directives.
     *
     * @var array<string>
     */
    protected const VALID_DIRECTIVES = [
        'default-src',
        'script-src',
        'script-src-elem',
        'script-src-attr',
        'style-src',
        'style-src-elem',
        'style-src-attr',
        'img-src',
        'font-src',
        'connect-src',
        'media-src',
        'object-src',
        'prefetch-src',
        'child-src',
        'frame-src',
        'worker-src',
        'frame-ancestors',
        'form-action',
        'base-uri',
        'sandbox',
        'report-uri',
        'report-to',
        'manifest-src',
        'navigate-to',
        'upgrade-insecure-requests',
        'block-all-mixed-content',
    ];

    /**
     * Boolean-only directives (no values).
     *
     * @var array<string>
     */
    protected const BOOLEAN_DIRECTIVES = [
        'upgrade-insecure-requests',
        'block-all-mixed-content',
    ];

    /**
     * The CSP directives being built.
     *
     * @var array<string, array<string>|bool>
     */
    protected array $directives = [];

    /**
     * Convert to string.
     */
    public function __toString(): string
    {
        return $this->build();
    }

    /**
     * Create a new policy builder instance.
     */
    public static function create(): self
    {
        return new self;
    }

    /**
     * Add values to a directive.
     *
     * @param  array<string>|string  $values
     */
    public function addDirective(string $directive, string|array $values): self
    {
        $directive = strtolower($directive);

        if (! in_array($directive, self::VALID_DIRECTIVES, true)) {
            return $this;
        }

        // Handle boolean directives
        if (in_array($directive, self::BOOLEAN_DIRECTIVES, true)) {
            $this->directives[$directive] = true;

            return $this;
        }

        $values = is_array($values) ? $values : [$values];

        if (! isset($this->directives[$directive])) {
            $this->directives[$directive] = [];
        }

        foreach ($values as $value) {
            if (! in_array($value, $this->directives[$directive], true)) {
                $this->directives[$directive][] = $value;
            }
        }

        return $this;
    }

    /**
     * Remove a directive.
     */
    public function removeDirective(string $directive): self
    {
        unset($this->directives[strtolower($directive)]);

        return $this;
    }

    /**
     * Set default-src directive.
     */
    public function defaultSrc(string ...$values): self
    {
        return $this->addDirective('default-src', $values);
    }

    /**
     * Set script-src directive.
     */
    public function scriptSrc(string ...$values): self
    {
        return $this->addDirective('script-src', $values);
    }

    /**
     * Set script-src-elem directive.
     */
    public function scriptSrcElem(string ...$values): self
    {
        return $this->addDirective('script-src-elem', $values);
    }

    /**
     * Set script-src-attr directive.
     */
    public function scriptSrcAttr(string ...$values): self
    {
        return $this->addDirective('script-src-attr', $values);
    }

    /**
     * Set style-src directive.
     */
    public function styleSrc(string ...$values): self
    {
        return $this->addDirective('style-src', $values);
    }

    /**
     * Set style-src-elem directive.
     */
    public function styleSrcElem(string ...$values): self
    {
        return $this->addDirective('style-src-elem', $values);
    }

    /**
     * Set style-src-attr directive.
     */
    public function styleSrcAttr(string ...$values): self
    {
        return $this->addDirective('style-src-attr', $values);
    }

    /**
     * Set img-src directive.
     */
    public function imgSrc(string ...$values): self
    {
        return $this->addDirective('img-src', $values);
    }

    /**
     * Set font-src directive.
     */
    public function fontSrc(string ...$values): self
    {
        return $this->addDirective('font-src', $values);
    }

    /**
     * Set connect-src directive.
     */
    public function connectSrc(string ...$values): self
    {
        return $this->addDirective('connect-src', $values);
    }

    /**
     * Set media-src directive.
     */
    public function mediaSrc(string ...$values): self
    {
        return $this->addDirective('media-src', $values);
    }

    /**
     * Set object-src directive.
     */
    public function objectSrc(string ...$values): self
    {
        return $this->addDirective('object-src', $values);
    }

    /**
     * Set frame-src directive.
     */
    public function frameSrc(string ...$values): self
    {
        return $this->addDirective('frame-src', $values);
    }

    /**
     * Set child-src directive.
     */
    public function childSrc(string ...$values): self
    {
        return $this->addDirective('child-src', $values);
    }

    /**
     * Set worker-src directive.
     */
    public function workerSrc(string ...$values): self
    {
        return $this->addDirective('worker-src', $values);
    }

    /**
     * Set frame-ancestors directive.
     */
    public function frameAncestors(string ...$values): self
    {
        return $this->addDirective('frame-ancestors', $values);
    }

    /**
     * Set form-action directive.
     */
    public function formAction(string ...$values): self
    {
        return $this->addDirective('form-action', $values);
    }

    /**
     * Set base-uri directive.
     */
    public function baseUri(string ...$values): self
    {
        return $this->addDirective('base-uri', $values);
    }

    /**
     * Set sandbox directive.
     */
    public function sandbox(string ...$values): self
    {
        return $this->addDirective('sandbox', $values);
    }

    /**
     * Set report-uri directive.
     */
    public function reportUri(string $uri): self
    {
        return $this->addDirective('report-uri', $uri);
    }

    /**
     * Set report-to directive.
     */
    public function reportTo(string $groupName): self
    {
        return $this->addDirective('report-to', $groupName);
    }

    /**
     * Set manifest-src directive.
     */
    public function manifestSrc(string ...$values): self
    {
        return $this->addDirective('manifest-src', $values);
    }

    /**
     * Enable upgrade-insecure-requests directive.
     */
    public function upgradeInsecureRequests(bool $enable = true): self
    {
        if ($enable) {
            $this->directives['upgrade-insecure-requests'] = true;
        } else {
            unset($this->directives['upgrade-insecure-requests']);
        }

        return $this;
    }

    /**
     * Enable block-all-mixed-content directive.
     */
    public function blockAllMixedContent(bool $enable = true): self
    {
        if ($enable) {
            $this->directives['block-all-mixed-content'] = true;
        } else {
            unset($this->directives['block-all-mixed-content']);
        }

        return $this;
    }

    /**
     * Add a nonce to script-src and style-src directives.
     */
    public function withNonce(string $nonce): self
    {
        $nonceValue = "'nonce-{$nonce}'";

        $this->addDirective('script-src', $nonceValue);
        $this->addDirective('style-src', $nonceValue);

        return $this;
    }

    /**
     * Add a hash for an inline script.
     */
    public function addScriptHash(string $hash, string $algorithm = 'sha256'): self
    {
        return $this->addDirective('script-src', "'{$algorithm}-{$hash}'");
    }

    /**
     * Add a hash for an inline style.
     */
    public function addStyleHash(string $hash, string $algorithm = 'sha256'): self
    {
        return $this->addDirective('style-src', "'{$algorithm}-{$hash}'");
    }

    /**
     * Calculate and add hash for inline script content.
     */
    public function hashScript(string $script, string $algorithm = 'sha256'): self
    {
        $hash = base64_encode(hash($algorithm, $script, true));

        return $this->addScriptHash($hash, $algorithm);
    }

    /**
     * Calculate and add hash for inline style content.
     */
    public function hashStyle(string $style, string $algorithm = 'sha256'): self
    {
        $hash = base64_encode(hash($algorithm, $style, true));

        return $this->addStyleHash($hash, $algorithm);
    }

    /**
     * Merge another builder's directives into this one.
     */
    public function merge(self $other): self
    {
        foreach ($other->getDirectives() as $directive => $values) {
            if (is_bool($values)) {
                $this->directives[$directive] = $values;
            } else {
                $this->addDirective($directive, $values);
            }
        }

        return $this;
    }

    /**
     * Get all directives.
     *
     * @return array<string, array<string>|bool>
     */
    public function getDirectives(): array
    {
        return $this->directives;
    }

    /**
     * Check if a directive exists.
     */
    public function hasDirective(string $directive): bool
    {
        return isset($this->directives[strtolower($directive)]);
    }

    /**
     * Get values for a specific directive.
     *
     * @return array<string>|bool|null
     */
    public function getDirective(string $directive): array|bool|null
    {
        return $this->directives[strtolower($directive)] ?? null;
    }

    /**
     * Build the CSP header string.
     */
    public function build(): string
    {
        $parts = [];

        foreach ($this->directives as $directive => $values) {
            if (true === $values) {
                $parts[] = $directive;
            } elseif (is_array($values) && ! empty($values)) {
                $parts[] = $directive.' '.implode(' ', $values);
            }
        }

        return implode('; ', $parts);
    }

    /**
     * Reset all directives.
     */
    public function reset(): self
    {
        $this->directives = [];

        return $this;
    }
}
