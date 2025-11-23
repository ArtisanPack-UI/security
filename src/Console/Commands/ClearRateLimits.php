<?php

namespace ArtisanPackUI\Security\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\RateLimiter;

class ClearRateLimits extends Command
{
    protected $signature = 'security:rate-limit:clear {--ip=} {--user=}';
    protected $description = 'Clear the rate limiter cache for a given IP address or user ID';

    public function handle(): int
    {
        $ip = $this->option('ip');
        $user = $this->option('user');

        if (!$ip && !$user) {
            $this->error('You must provide either an --ip or a --user option.');
            return 1;
        }

        if ($ip) {
            RateLimiter::clear($ip);
            $this->info("Cleared rate limit for IP: {$ip}");
        }

        if ($user) {
            RateLimiter::clear($user);
            $this->info("Cleared rate limit for User ID: {$user}");
        }

        return 0;
    }
}
