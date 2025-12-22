<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class ApiSecurity
{
    /**
     * Handle an incoming API request.
     *
     * This middleware:
     * - Validates token expiration
     * - Checks token revocation status
     * - Records token usage (last_used_at, IP, user agent)
     * - Applies API-specific security headers
     */
    public function handle(Request $request, Closure $next): Response
    {
        // Get the current access token
        $token = $request->user()?->currentAccessToken();

        if ($token) {
            // Check if token is revoked
            if ($token->is_revoked ?? false) {
                return response()->json([
                    'message' => 'Token has been revoked.',
                    'error' => 'token_revoked',
                ], 401);
            }

            // Check if token is expired
            if ($token->expires_at && $token->expires_at->isPast()) {
                return response()->json([
                    'message' => 'Token has expired.',
                    'error' => 'token_expired',
                ], 401);
            }

            // Record token usage
            if (method_exists($token, 'recordUsage')) {
                $token->recordUsage($request->ip(), $request->userAgent());
            } else {
                // Fallback for standard Sanctum tokens
                $token->forceFill(['last_used_at' => now()])->save();
            }
        }

        $response = $next($request);

        // Apply API-specific security headers
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
        $response->headers->set('Pragma', 'no-cache');

        return $response;
    }
}
