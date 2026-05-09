<?php

declare(strict_types=1);

namespace Tests\Unit;

use ArtisanPackUI\Security\Services\Csp\CspPolicyBuilder;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class CspPolicyBuilderTest extends TestCase
{
    #[Test]
    public function it_builds_a_basic_policy(): void
    {
        $builder = new CspPolicyBuilder;

        $builder->defaultSrc("'self'");

        $policy = $builder->build();

        $this->assertStringContainsString("default-src 'self'", $policy);
    }

    #[Test]
    public function it_builds_multiple_directives(): void
    {
        $builder = new CspPolicyBuilder;

        $builder->defaultSrc("'self'")
            ->scriptSrc("'self'", "'unsafe-inline'")
            ->styleSrc("'self'", 'https://fonts.googleapis.com');

        $policy = $builder->build();

        $this->assertStringContainsString("default-src 'self'", $policy);
        $this->assertStringContainsString("script-src 'self' 'unsafe-inline'", $policy);
        $this->assertStringContainsString("style-src 'self' https://fonts.googleapis.com", $policy);
    }

    #[Test]
    public function it_adds_nonce_to_script_and_style_src(): void
    {
        $builder = new CspPolicyBuilder;

        $builder->scriptSrc("'self'")->withNonce('test-nonce-123');

        $policy = $builder->build();

        $this->assertStringContainsString("script-src 'self' 'nonce-test-nonce-123'", $policy);
        $this->assertStringContainsString("style-src 'nonce-test-nonce-123'", $policy);
    }

    #[Test]
    public function it_adds_strict_dynamic_to_script_src(): void
    {
        $builder = new CspPolicyBuilder;

        $builder->scriptSrc("'self'", "'strict-dynamic'");

        $policy = $builder->build();

        $this->assertStringContainsString("'strict-dynamic'", $policy);
    }

    #[Test]
    public function it_adds_report_uri(): void
    {
        $builder = new CspPolicyBuilder;

        $builder->defaultSrc("'self'")->reportUri('/csp-report');

        $policy = $builder->build();

        $this->assertStringContainsString('report-uri /csp-report', $policy);
    }

    #[Test]
    public function it_adds_upgrade_insecure_requests(): void
    {
        $builder = new CspPolicyBuilder;

        $builder->defaultSrc("'self'")->upgradeInsecureRequests();

        $policy = $builder->build();

        $this->assertStringContainsString('upgrade-insecure-requests', $policy);
    }

    #[Test]
    public function it_can_append_to_existing_directive(): void
    {
        $builder = new CspPolicyBuilder;

        $builder->scriptSrc("'self'");
        $builder->addDirective('script-src', 'https://cdn.example.com');

        $policy = $builder->build();

        $this->assertStringContainsString("script-src 'self' https://cdn.example.com", $policy);
    }

    #[Test]
    public function it_can_be_reset(): void
    {
        $builder = new CspPolicyBuilder;

        $builder->defaultSrc("'self'")->scriptSrc("'self'");
        $builder->reset();

        $policy = $builder->build();

        $this->assertEmpty($policy);
    }

    #[Test]
    public function it_can_check_if_directive_exists(): void
    {
        $builder = new CspPolicyBuilder;

        $builder->defaultSrc("'self'");

        $this->assertTrue($builder->hasDirective('default-src'));
        $this->assertFalse($builder->hasDirective('script-src'));
    }

    #[Test]
    public function it_builds_frame_ancestors_directive(): void
    {
        $builder = new CspPolicyBuilder;

        $builder->frameAncestors("'self'", 'https://example.com');

        $policy = $builder->build();

        $this->assertStringContainsString("frame-ancestors 'self' https://example.com", $policy);
    }

    #[Test]
    public function it_builds_base_uri_directive(): void
    {
        $builder = new CspPolicyBuilder;

        $builder->baseUri("'self'");

        $policy = $builder->build();

        $this->assertStringContainsString("base-uri 'self'", $policy);
    }

    #[Test]
    public function it_builds_form_action_directive(): void
    {
        $builder = new CspPolicyBuilder;

        $builder->formAction("'self'");

        $policy = $builder->build();

        $this->assertStringContainsString("form-action 'self'", $policy);
    }

    #[Test]
    public function it_builds_object_src_directive(): void
    {
        $builder = new CspPolicyBuilder;

        $builder->objectSrc("'none'");

        $policy = $builder->build();

        $this->assertStringContainsString("object-src 'none'", $policy);
    }
}
