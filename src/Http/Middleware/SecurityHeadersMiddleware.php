<?php

/**
 * SecurityHeadersMiddleware route middleware.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class SecurityHeadersMiddleware
{
    public function handle(Request $request, Closure $next): Response
    {
        /** @var Response $response */
        $response = $next($request);

        $headers = config('artisanpack.security.security-headers', []);

        foreach ($headers as $key => $value) {
            if (null !== $value && '' !== $value) {
                $response->headers->set($key, $value);
            }
        }

        return $response;
    }
}
