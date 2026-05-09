<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Http\Middleware;

use ArtisanPackUI\Security\Contracts\CspPolicyInterface;
use ArtisanPackUI\Security\Events\CspPolicyApplied;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class ContentSecurityPolicy
{
    /**
     * Create a new middleware instance.
     */
    public function __construct(
        protected CspPolicyInterface $csp,
    ) {}

    /**
     * Handle an incoming request.
     *
     * @param  Closure(Request): (Response)  $next
     */
    public function handle(Request $request, Closure $next, ?string $preset = null): Response
    {
        // Skip if CSP is disabled
        if (! config('artisanpack.security.csp.enabled', true)) {
            return $next($request);
        }

        // Build policy for this request
        $this->csp->forRequest($request);

        // Apply preset if specified via middleware parameter
        if (null !== $preset) {
            $this->csp->usePreset($preset);
        }

        // Get response
        $response = $next($request);

        // Apply CSP headers
        return $this->applyHeaders($response);
    }

    /**
     * Apply CSP headers to the response.
     */
    protected function applyHeaders(Response $response): Response
    {
        $headers = $this->csp->toHeader();

        if (empty($headers)) {
            return $response;
        }

        foreach ($headers as $name => $value) {
            $response->headers->set($name, $value);
        }

        // Dispatch policy applied event
        event(new CspPolicyApplied(
            $this->csp->getPolicy(),
            $this->csp->getNonce(),
        ));

        return $response;
    }
}
