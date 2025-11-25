<?php

namespace Tests\Feature;

use ArtisanPackUI\Security\Http\Middleware\EnsureSessionIsEncrypted;
use Tests\TestCase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;

class EnsureSessionIsEncryptedMiddlewareTest extends TestCase
{
    #[Test]
    public function it_allows_requests_when_encryption_is_enabled_in_production()
    {
        Config::set('artisanpack.security.encrypt', true);
        $this->app->detectEnvironment(function () {
            return 'production';
        });

        $request = new Request();
        $middleware = new EnsureSessionIsEncrypted();

        $response = $middleware->handle($request, function () {
            return 'OK';
        });

        $this->assertEquals('OK', $response);
    }

    #[Test]
    public function it_throws_exception_when_encryption_is_disabled_in_production()
    {
        $this->expectException(RuntimeException::class);

        Config::set('artisanpack.security.encrypt', false);
        $this->app->detectEnvironment(function () {
            return 'production';
        });

        $request = new Request();
        $middleware = new EnsureSessionIsEncrypted();

        $middleware->handle($request, function () {
            //
        });
    }

    #[Test]
    public function it_allows_requests_when_encryption_is_disabled_in_local_environment()
    {
        Config::set('artisanpack.security.encrypt', false);
        $this->app->detectEnvironment(function () {
            return 'local';
        });

        $request = new Request();
        $middleware = new EnsureSessionIsEncrypted();

        $response = $middleware->handle($request, function () {
            return 'OK';
        });

        $this->assertEquals('OK', $response);
    }
}
