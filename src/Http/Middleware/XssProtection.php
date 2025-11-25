<?php

namespace ArtisanPackUI\Security\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class XssProtection
{
    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        if (config('artisanpack.security.xss.enabled', false)) {
            $input = $request->all();
            array_walk_recursive($input, function (&$input) {
                if (is_string($input)) {
                    $input = kses($input);
                }
            });
            $request->merge($input);
        }

        return $next($request);
    }
}
