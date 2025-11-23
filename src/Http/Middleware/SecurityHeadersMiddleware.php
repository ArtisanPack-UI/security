<?php

namespace ArtisanPackUI\Security\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

class SecurityHeadersMiddleware
{
    public function handle(Request $request, Closure $next): Response
    {
        /** @var Response $response */
        $response = $next($request);

        $headers = config('security.security-headers', []);

        foreach ($headers as $key => $value) {
            if ($value !== null && $value !== '') {
                $response->headers->set($key, $value);
            }
        }

        return $response;
    }
}
