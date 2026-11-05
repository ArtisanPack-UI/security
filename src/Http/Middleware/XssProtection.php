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
     * Input keys left unfiltered when `artisanpack.security.xss.except` isn't set.
     *
     * @since 2.2.0
     *
     * @var list<string>
     */
    protected const DEFAULT_EXCEPT = ['password', 'password_confirmation', 'current_password'];

    /**
     * Handle an incoming request.
     *
     * Runs every string input through `kses()`, except keys listed in
     * `artisanpack.security.xss.except` (credentials by default), which are
     * skipped at any nesting depth.
     *
     * @since 2.0.0
     * @since 2.2.0 Skips the keys in `artisanpack.security.xss.except`.
     *
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        if (config('artisanpack.security.xss.enabled', false)) {
            $except = array_map('strval', (array) config('artisanpack.security.xss.except', self::DEFAULT_EXCEPT));

            $request->merge($this->filterInput($request->all(), $except));
        }

        return $next($request);
    }

    /**
     * Runs the string values of an input array through `kses()`.
     *
     * @param  array<array-key, mixed>  $input  The request input.
     * @param  list<string>  $except  Keys to leave unchanged.
     * @return array<array-key, mixed> The filtered input.
     *
     * @since 2.2.0
     */
    protected function filterInput(array $input, array $except): array
    {
        foreach ($input as $key => $value) {
            if (in_array((string) $key, $except, true)) {
                continue;
            }

            if (is_array($value)) {
                $input[$key] = $this->filterInput($value, $except);
            } elseif (is_string($value)) {
                $input[$key] = kses($value);
            }
        }

        return $input;
    }
}
