<?php

/**
 * XssProtection route middleware.
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

class XssProtection
{
    /**
     * Handle an incoming request.
     *
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        if (config('artisanpack.security.xss.enabled', false)) {
            $input = $request->all();
            array_walk_recursive($input, function (&$input): void {
                if (is_string($input)) {
                    $input = kses($input);
                }
            });
            $request->merge($input);
        }

        return $next($request);
    }
}
