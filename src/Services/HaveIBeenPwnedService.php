<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Services;

use ArtisanPackUI\Security\Contracts\BreachCheckerInterface;
use Exception;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class HaveIBeenPwnedService implements BreachCheckerInterface
{
    /**
     * The HaveIBeenPwned API URL.
     */
    protected const API_URL = 'https://api.pwnedpasswords.com/range/';

    /**
     * Check if a password has been exposed in known data breaches.
     *
     * Uses k-Anonymity model - only first 5 chars of SHA1 hash are sent.
     *
     * @param  string  $password  The plain-text password to check
     * @return int Number of times password has been seen in breaches
     */
    public function check(string $password): int
    {
        if (! config('artisanpack.security.passwordSecurity.breachChecking.enabled', true)) {
            return 0;
        }

        $sha1 = strtoupper(sha1($password));
        $prefix = substr($sha1, 0, 5);
        $suffix = substr($sha1, 5);

        // Check cache first
        if (config('artisanpack.security.passwordSecurity.breachChecking.cacheResults', true)) {
            $cacheKey = "hibp_prefix_{$prefix}";
            $ttl = config('artisanpack.security.passwordSecurity.breachChecking.cacheTtl', 86400);

            $results = Cache::remember($cacheKey, $ttl, fn () => $this->fetchFromApi($prefix));
        } else {
            $results = $this->fetchFromApi($prefix);
        }

        if ($results === null) {
            // API failed, fail open (don't block user)
            return 0;
        }

        // Search for our suffix in the results
        foreach (explode("\n", $results) as $line) {
            $line = trim($line);
            if (empty($line)) {
                continue;
            }

            $parts = explode(':', $line);
            if (count($parts) !== 2) {
                continue;
            }

            [$hashSuffix, $count] = $parts;

            if (strtoupper($hashSuffix) === $suffix) {
                return (int) $count;
            }
        }

        return 0;
    }

    /**
     * Check if password is compromised.
     */
    public function isCompromised(string $password): bool
    {
        return $this->check($password) > 0;
    }

    /**
     * Fetch hash range from HIBP API.
     */
    protected function fetchFromApi(string $prefix): ?string
    {
        try {
            $timeout = config('artisanpack.security.passwordSecurity.breachChecking.apiTimeout', 5);

            $response = Http::timeout($timeout)
                ->withHeaders([
                    'User-Agent' => 'ArtisanPack-Security-Laravel-Package',
                    'Add-Padding' => 'true', // Enable padding for privacy
                ])
                ->get(self::API_URL . $prefix);

            if ($response->successful()) {
                return $response->body();
            }

            Log::warning('HIBP API returned non-success status', [
                'status' => $response->status(),
                'prefix' => $prefix,
            ]);

            return null;
        } catch (Exception $e) {
            Log::error('HIBP API request failed', [
                'error' => $e->getMessage(),
                'prefix' => $prefix,
            ]);

            return null;
        }
    }
}
