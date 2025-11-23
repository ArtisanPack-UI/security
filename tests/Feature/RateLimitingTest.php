<?php

namespace Tests\Feature;

use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Config;
use Tests\TestCase;

class RateLimitingTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [
            \ArtisanPackUI\Security\SecurityServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app): void
    {
        // Enable rate limiting and define a test route with a limiter
        Config::set('artisanpack.security.rateLimiting.enabled', true);
        Config::set('artisanpack.security.rateLimiting.limiters.test', [
            'maxAttempts' => 3,
            'decayMinutes' => 1,
        ]);
    }

    /** @test */
    public function it_rate_limits_requests_from_the_same_ip()
    {
        Route::get('/_test/rate-limited-route', function () {
            return 'Success';
        })->middleware('throttle:test');

        $response = null;
        for ($i = 0; $i < 3; $i++) {
            $response = $this->get('/_test/rate-limited-route');
            $response->assertStatus(200);
        }

        // The 4th request should be throttled
        $response = $this->get('/_test/rate-limited-route');
        $response->assertStatus(429); // Too Many Requests
    }

    /** @test */
    public function it_rate_limits_requests_for_an_authenticated_user()
    {
        Route::get('/_test/rate-limited-route', function () {
            return 'Success';
        })->middleware('throttle:test');

        $user = new User();
        $user->id = 1;
        $this->actingAs($user);

        $response = null;
        for ($i = 0; $i < 3; $i++) {
            $response = $this->get('/_test/rate-limited-route');
            $response->assertStatus(200);
        }

        // The 4th request should be throttled
        $response = $this->get('/_test/rate-limited-route');
        $response->assertStatus(429);
    }
}
