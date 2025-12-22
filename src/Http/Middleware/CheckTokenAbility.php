<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class CheckTokenAbility
{
    /**
     * Handle an incoming request.
     *
     * Check if the current token has ALL of the required abilities.
     *
     * Usage:
     *   ->middleware('token.ability:write')
     *   ->middleware('token.ability:read,write') // requires both
     */
    public function handle(Request $request, Closure $next, ...$abilities): Response
    {
        if (empty($abilities)) {
            return $next($request);
        }

        $user = $request->user();

        if (! $user) {
            return response()->json([
                'message' => 'Unauthenticated.',
                'error' => 'unauthenticated',
            ], 401);
        }

        $token = $user->currentAccessToken();

        if (! $token) {
            return response()->json([
                'message' => 'No access token present.',
                'error' => 'no_token',
            ], 401);
        }

        // Check each required ability
        foreach ($abilities as $ability) {
            if (! $this->tokenHasAbility($token, $ability)) {
                return response()->json([
                    'message' => 'Token does not have the required ability: ' . $ability,
                    'error' => 'insufficient_ability',
                    'required_ability' => $ability,
                ], 403);
            }
        }

        return $next($request);
    }

    /**
     * Check if the token has a specific ability.
     */
    protected function tokenHasAbility($token, string $ability): bool
    {
        // Use our extended method if available
        if (method_exists($token, 'hasAbility')) {
            return $token->hasAbility($ability);
        }

        // Fallback to Sanctum's tokenCan method
        $abilities = $token->abilities ?? [];

        return in_array('*', $abilities, true)
            || in_array($ability, $abilities, true);
    }
}
