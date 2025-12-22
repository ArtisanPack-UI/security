<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Http\Middleware;

use Closure;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Symfony\Component\HttpFoundation\Response;

class ApiRateLimiting
{
    /**
     * Handle an incoming request.
     *
     * Apply API-specific rate limiting based on authentication status:
     * - Authenticated users: higher limits, keyed by user ID + token ID
     * - Guest users: lower limits, keyed by IP address
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (! config('artisanpack.security.api.rate_limiting.enabled', true)) {
            return $next($request);
        }

        $user = $request->user();
        $token = $user?->currentAccessToken();

        if ($user && $token) {
            // Authenticated request - use higher limits
            $config = config('artisanpack.security.api.rate_limiting.authenticated', [
                'max_attempts' => 60,
                'decay_minutes' => 1,
            ]);
            $key = 'api_auth_' . $user->id . '_' . $token->id;
        } else {
            // Guest request - use lower limits
            $config = config('artisanpack.security.api.rate_limiting.guest', [
                'max_attempts' => 30,
                'decay_minutes' => 1,
            ]);
            $key = 'api_guest_' . $request->ip();
        }

        $maxAttempts = $config['max_attempts'] ?? 60;
        $decayMinutes = $config['decay_minutes'] ?? 1;

        if (RateLimiter::tooManyAttempts($key, $maxAttempts)) {
            $retryAfter = RateLimiter::availableIn($key);

            return response()->json([
                'message' => 'Too many requests. Please try again later.',
                'error' => 'rate_limit_exceeded',
                'retry_after' => $retryAfter,
            ], 429)->withHeaders([
                'Retry-After' => $retryAfter,
                'X-RateLimit-Limit' => $maxAttempts,
                'X-RateLimit-Remaining' => 0,
                'X-RateLimit-Reset' => now()->addSeconds($retryAfter)->timestamp,
            ]);
        }

        RateLimiter::hit($key, $decayMinutes * 60);

        $response = $next($request);

        // Add rate limit headers to response
        $remaining = RateLimiter::remaining($key, $maxAttempts);

        $response->headers->set('X-RateLimit-Limit', (string) $maxAttempts);
        $response->headers->set('X-RateLimit-Remaining', (string) max(0, $remaining));

        return $response;
    }
}
