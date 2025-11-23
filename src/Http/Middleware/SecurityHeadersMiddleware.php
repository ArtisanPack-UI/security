<?php

namespace ArtisanPackUI\Security\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class SecurityHeadersMiddleware
{
    public function handle(Request $request, Closure $next): \Symfony\Component\HttpFoundation\Response
    {
        /** @var \Symfony\Component\HttpFoundation\Response $response */
        $response = $next($request);

        $headers = config('artisanpack.security.security-headers', []);

        foreach ($headers as $key => $value) {
            if ($value !== null && $value !== '') {
                $response->headers->set($key, $value);
            }
        }

        return $response;
    }
}
