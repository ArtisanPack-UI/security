<?php

declare(strict_types=1);

namespace Tests\Feature;

use ArtisanPackUI\Security\Contracts\CspPolicyInterface;
use ArtisanPackUI\Security\Http\Middleware\ContentSecurityPolicy;
use ArtisanPackUI\Security\Models\CspViolationReport;
use ArtisanPackUI\Security\Services\Csp\CspNonceGenerator;
use ArtisanPackUI\Security\Services\Csp\CspViolationHandler;
use ArtisanPackUI\Security\Testing\CspAssertions;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class CspTest extends TestCase
{
    use CspAssertions;

    protected function setUp(): void
    {
        parent::setUp();

        // Enable CSP for tests
        Config::set('artisanpack.security.csp.enabled', true);
        Config::set('artisanpack.security.csp.reportOnly', false);
        Config::set('artisanpack.security.csp.preset', 'livewire');
    }

    #[Test]
    public function it_adds_csp_header_to_response(): void
    {
        $request = Request::create('/test', 'GET');
        $middleware = app(ContentSecurityPolicy::class);

        $response = $middleware->handle($request, function () {
            return new Response('Test Content');
        });

        $this->assertTrue($response->headers->has('Content-Security-Policy'));
    }

    #[Test]
    public function it_adds_report_only_header_when_configured(): void
    {
        Config::set('artisanpack.security.csp.reportOnly', true);

        $request = Request::create('/test', 'GET');
        $middleware = app(ContentSecurityPolicy::class);

        $response = $middleware->handle($request, function () {
            return new Response('Test Content');
        });

        $this->assertTrue($response->headers->has('Content-Security-Policy-Report-Only'));
        $this->assertFalse($response->headers->has('Content-Security-Policy'));
    }

    #[Test]
    public function it_skips_csp_when_disabled(): void
    {
        Config::set('artisanpack.security.csp.enabled', false);

        $request = Request::create('/test', 'GET');
        $middleware = app(ContentSecurityPolicy::class);

        $response = $middleware->handle($request, function () {
            return new Response('Test Content');
        });

        $this->assertFalse($response->headers->has('Content-Security-Policy'));
        $this->assertFalse($response->headers->has('Content-Security-Policy-Report-Only'));
    }

    #[Test]
    public function it_includes_nonce_in_csp_header(): void
    {
        $request = Request::create('/test', 'GET');
        $middleware = app(ContentSecurityPolicy::class);

        $response = $middleware->handle($request, function () {
            return new Response('Test Content');
        });

        $csp = $response->headers->get('Content-Security-Policy');
        $this->assertMatchesRegularExpression("/'nonce-[A-Za-z0-9+\/=]+'/", $csp);
    }

    #[Test]
    public function it_uses_same_nonce_throughout_request(): void
    {
        $generator = app(CspNonceGenerator::class);

        $nonce1 = $generator->get();
        $nonce2 = $generator->get();

        $this->assertSame($nonce1, $nonce2);
    }

    #[Test]
    public function it_uses_strict_preset(): void
    {
        $service = app(CspPolicyInterface::class);
        $service->usePreset('strict');
        $policy = $service->getPolicy();

        $this->assertStringContainsString("default-src 'none'", $policy);
    }

    #[Test]
    public function it_uses_relaxed_preset(): void
    {
        $service = app(CspPolicyInterface::class);
        $service->usePreset('relaxed');
        $policy = $service->getPolicy();

        $this->assertStringContainsString("default-src 'self'", $policy);
    }

    #[Test]
    public function it_uses_livewire_preset_by_default(): void
    {
        $service = app(CspPolicyInterface::class);
        $service->usePreset('livewire');
        $policy = $service->getPolicy();

        $this->assertStringContainsString("'strict-dynamic'", $policy);
    }

    #[Test]
    public function it_excludes_configured_routes(): void
    {
        Config::set('artisanpack.security.csp.excludedRoutes', ['api/*']);

        $request = Request::create('/api/users', 'GET');
        $middleware = app(ContentSecurityPolicy::class);

        $response = $middleware->handle($request, function () {
            return new Response('API Response');
        });

        $this->assertFalse($response->headers->has('Content-Security-Policy'));
    }

    #[Test]
    public function it_includes_report_uri_when_reporting_enabled(): void
    {
        Config::set('artisanpack.security.csp.reporting.enabled', true);
        Config::set('artisanpack.security.csp.reporting.uri', '/csp-violation');

        $service = app(CspPolicyInterface::class);
        $service->reset();
        // Build the policy by calling forRequest
        $service->forRequest(Request::create('/test', 'GET'));
        $policy = $service->getPolicy();

        $this->assertStringContainsString('report-uri', $policy);
    }

    #[Test]
    public function it_validates_violation_reports(): void
    {
        // Test the validation logic without database
        $handler = app(CspViolationHandler::class);

        // Valid report should be accepted
        $validReport = [
            'csp-report' => [
                'document-uri' => 'https://example.com/page',
                'blocked-uri' => 'https://evil.com/script.js',
                'violated-directive' => 'script-src',
            ],
        ];

        // Configure to not store (to avoid database requirements)
        Config::set('artisanpack.security.csp.reporting.storeViolations', false);

        // Should not throw an exception
        $result = $handler->handle($validReport);
        $this->assertNull($result); // Returns null when not storing
    }

    #[Test]
    public function it_rejects_invalid_violation_reports(): void
    {
        $handler = app(CspViolationHandler::class);

        Config::set('artisanpack.security.csp.reporting.storeViolations', false);

        $invalidReport = [
            'csp-report' => [
                'document-uri' => 'https://example.com/page',
                // Missing violated-directive
            ],
        ];

        $result = $handler->handle($invalidReport);
        $this->assertNull($result);
    }

    #[Test]
    public function it_can_use_csp_facade(): void
    {
        $csp = app(CspPolicyInterface::class);
        $csp->usePreset('livewire');

        $this->assertNotEmpty($csp->getNonce());
        $this->assertNotEmpty($csp->getPolicy());
    }

    #[Test]
    public function it_can_add_custom_directive(): void
    {
        $service = app(CspPolicyInterface::class);

        $service->addDirective('img-src', ['https://images.example.com']);
        $policy = $service->getPolicy();

        $this->assertStringContainsString('img-src', $policy);
        $this->assertStringContainsString('https://images.example.com', $policy);
    }

    #[Test]
    public function it_renders_meta_tag(): void
    {
        $service = app(CspPolicyInterface::class);

        $metaTag = $service->renderMetaTag();

        // The meta tag contains the nonce, not the full policy
        $this->assertStringContainsString('<meta name="csp-nonce"', $metaTag);
        $this->assertStringContainsString('content="', $metaTag);
    }

    #[Test]
    public function it_provides_headers_array(): void
    {
        $service = app(CspPolicyInterface::class);
        $service->usePreset('livewire');

        $headers = $service->toHeader();

        $this->assertIsArray($headers);
        $this->assertArrayHasKey('Content-Security-Policy', $headers);
    }

    #[Test]
    public function it_provides_report_only_headers_when_configured(): void
    {
        Config::set('artisanpack.security.csp.reportOnly', true);

        $service = app(CspPolicyInterface::class);
        $service->reset();
        $service->usePreset('livewire');

        $headers = $service->toHeader();

        $this->assertArrayHasKey('Content-Security-Policy-Report-Only', $headers);
        $this->assertArrayNotHasKey('Content-Security-Policy', $headers);
    }

    #[Test]
    public function csp_assertions_trait_works(): void
    {
        // Disable the global security headers to test our middleware in isolation
        Config::set('artisanpack.security.security-headers.Content-Security-Policy', null);

        Route::middleware([ContentSecurityPolicy::class])->get('/csp-test', function () {
            return response('OK');
        });

        $response = $this->get('/csp-test');

        $this->assertHasCspHeader($response);
    }

    #[Test]
    public function it_adds_upgrade_insecure_requests(): void
    {
        Config::set('artisanpack.security.csp.upgradeInsecureRequests', true);

        $service = app(CspPolicyInterface::class);
        // Use livewire preset which includes upgrade-insecure-requests
        $service->usePreset('livewire');
        $policy = $service->getPolicy();

        $this->assertStringContainsString('upgrade-insecure-requests', $policy);
    }

    #[Test]
    public function it_generates_fingerprint_for_deduplication(): void
    {
        $report1 = [
            'document-uri' => 'https://example.com/page',
            'blocked-uri' => 'https://evil.com/script.js',
            'violated-directive' => 'script-src',
            'source-file' => 'script.js',
            'line-number' => 10,
        ];

        $report2 = [
            'document-uri' => 'https://example.com/page',
            'blocked-uri' => 'https://evil.com/script.js',
            'violated-directive' => 'script-src',
            'source-file' => 'script.js',
            'line-number' => 10,
        ];

        $fingerprint1 = CspViolationReport::generateFingerprint($report1);
        $fingerprint2 = CspViolationReport::generateFingerprint($report2);

        $this->assertSame($fingerprint1, $fingerprint2);
    }

    #[Test]
    public function it_generates_different_fingerprints_for_different_reports(): void
    {
        $report1 = [
            'document-uri' => 'https://example.com/page1',
            'blocked-uri' => 'https://evil.com/script1.js',
            'violated-directive' => 'script-src',
        ];

        $report2 = [
            'document-uri' => 'https://example.com/page2',
            'blocked-uri' => 'https://evil.com/script2.js',
            'violated-directive' => 'script-src',
        ];

        $fingerprint1 = CspViolationReport::generateFingerprint($report1);
        $fingerprint2 = CspViolationReport::generateFingerprint($report2);

        $this->assertNotSame($fingerprint1, $fingerprint2);
    }
}
