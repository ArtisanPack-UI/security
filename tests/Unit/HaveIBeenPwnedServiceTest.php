<?php

namespace Tests\Unit;

use ArtisanPackUI\Security\Services\HaveIBeenPwnedService;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class HaveIBeenPwnedServiceTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Config::set('artisanpack.security.passwordSecurity.breachChecking.enabled', true);
        Config::set('artisanpack.security.passwordSecurity.breachChecking.cacheResults', false);
        Config::set('artisanpack.security.passwordSecurity.breachChecking.apiTimeout', 5);
    }

    #[Test]
    public function it_returns_zero_when_password_not_found()
    {
        // "password" has SHA1: 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        // Prefix: 5BAA6, Suffix: 1E4C9B93F3F0682250B6CF8331B7EE68FD8
        Http::fake([
            'api.pwnedpasswords.com/range/5BAA6' => Http::response(
                "0123456789ABCDEF0123456789ABCDEF123:100\n" .
                "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH123:50\n",
                200
            ),
        ]);

        $service = new HaveIBeenPwnedService();
        $count = $service->check('password');

        // The suffix doesn't match any in the mock response
        $this->assertEquals(0, $count);
    }

    #[Test]
    public function it_returns_count_when_password_found()
    {
        // "test" has SHA1: A94A8FE5CCB19BA61C4C0873D391E987982FBBD3
        // Prefix: A94A8, Suffix: FE5CCB19BA61C4C0873D391E987982FBBD3
        Http::fake([
            'api.pwnedpasswords.com/range/A94A8' => Http::response(
                "FE5CCB19BA61C4C0873D391E987982FBBD3:86453\n" .
                "0123456789ABCDEF0123456789ABCDEF123:100\n",
                200
            ),
        ]);

        $service = new HaveIBeenPwnedService();
        $count = $service->check('test');

        $this->assertEquals(86453, $count);
    }

    #[Test]
    public function it_returns_zero_when_api_fails()
    {
        Http::fake([
            'api.pwnedpasswords.com/*' => Http::response('', 500),
        ]);

        $service = new HaveIBeenPwnedService();
        $count = $service->check('anypassword');

        // Should fail open
        $this->assertEquals(0, $count);
    }

    #[Test]
    public function it_returns_zero_when_api_times_out()
    {
        Http::fake([
            'api.pwnedpasswords.com/*' => function () {
                throw new \Illuminate\Http\Client\ConnectionException('Connection timed out');
            },
        ]);

        $service = new HaveIBeenPwnedService();
        $count = $service->check('anypassword');

        // Should fail open
        $this->assertEquals(0, $count);
    }

    #[Test]
    public function it_returns_zero_when_breach_checking_disabled()
    {
        Config::set('artisanpack.security.passwordSecurity.breachChecking.enabled', false);

        Http::fake([
            'api.pwnedpasswords.com/*' => Http::response('NEVER_CALLED:1', 200),
        ]);

        $service = new HaveIBeenPwnedService();
        $count = $service->check('password');

        $this->assertEquals(0, $count);

        // Verify no HTTP request was made
        Http::assertNothingSent();
    }

    #[Test]
    public function it_caches_results_when_enabled()
    {
        Config::set('artisanpack.security.passwordSecurity.breachChecking.cacheResults', true);
        Config::set('artisanpack.security.passwordSecurity.breachChecking.cacheTtl', 3600);

        Cache::flush();

        Http::fake([
            'api.pwnedpasswords.com/range/A94A8' => Http::response(
                "FE5CCB19BA61C4C0873D391E987982FBBD3:100\n",
                200
            ),
        ]);

        $service = new HaveIBeenPwnedService();

        // First call
        $service->check('test');

        // Second call - should use cache
        $service->check('test');

        // Only one HTTP request should have been made
        Http::assertSentCount(1);
    }

    #[Test]
    public function is_compromised_returns_boolean()
    {
        Http::fake([
            'api.pwnedpasswords.com/range/A94A8' => Http::response(
                "FE5CCB19BA61C4C0873D391E987982FBBD3:100\n",
                200
            ),
        ]);

        $service = new HaveIBeenPwnedService();

        $this->assertTrue($service->isCompromised('test'));
    }

    #[Test]
    public function it_handles_empty_response_lines()
    {
        Http::fake([
            'api.pwnedpasswords.com/*' => Http::response(
                "\n\nFE5CCB19BA61C4C0873D391E987982FBBD3:100\n\n",
                200
            ),
        ]);

        $service = new HaveIBeenPwnedService();
        $count = $service->check('test');

        $this->assertEquals(100, $count);
    }

    #[Test]
    public function it_handles_malformed_response_lines()
    {
        Http::fake([
            'api.pwnedpasswords.com/*' => Http::response(
                "MALFORMED_LINE_NO_COLON\n" .
                "FE5CCB19BA61C4C0873D391E987982FBBD3:100\n",
                200
            ),
        ]);

        $service = new HaveIBeenPwnedService();
        $count = $service->check('test');

        $this->assertEquals(100, $count);
    }
}
