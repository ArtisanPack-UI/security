<?php

namespace Tests\Feature;

use ArtisanPackUI\Security\Http\Middleware\SecurityHeadersMiddleware;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Config;
use Tests\TestCase;

class SecurityHeadersMiddlewareTest extends TestCase
{
    /** @test */
    public function it_adds_configured_security_headers_to_the_response()
    {
        $headers = [
            'X-Frame-Options' => 'DENY',
            'X-Content-Type-Options' => 'nosniff',
            'Content-Security-Policy' => "default-src 'none'",
        ];
        Config::set('artisanpack.security.security-headers', $headers);

        $request = new Request();
        $middleware = new SecurityHeadersMiddleware();

        $response = $middleware->handle($request, function () {
            return new Response('Test Content');
        });

        $this->assertEquals('DENY', $response->headers->get('X-Frame-Options'));
        $this->assertEquals('nosniff', $response->headers->get('X-Content-Type-Options'));
        $this->assertEquals("default-src 'none'", $response->headers->get('Content-Security-Policy'));
    }

    /** @test */
    public function it_does_not_add_headers_that_are_null_or_empty()
    {
        $headers = [
            'X-Frame-Options' => 'SAMEORIGIN',
            'X-Content-Type-Options' => null, // This should be ignored
            'Referrer-Policy' => '', // This should be ignored
        ];
        Config::set('artisanpack.security.security-headers', $headers);

        $request = new Request();
        $middleware = new SecurityHeadersMiddleware();

        $response = $middleware->handle($request, function () {
            return new Response('Test Content');
        });

        $this->assertEquals('SAMEORIGIN', $response->headers->get('X-Frame-Options'));
        $this->assertFalse($response->headers->has('X-Content-Type-Options'));
        $this->assertFalse($response->headers->has('Referrer-Policy'));
    }
}
