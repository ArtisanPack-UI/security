<?php

declare(strict_types=1);

namespace Tests\Unit;

use ArtisanPackUI\Security\Services\Csp\CspNonceGenerator;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class CspNonceGeneratorTest extends TestCase
{
    #[Test]
    public function it_generates_a_nonce(): void
    {
        $generator = new CspNonceGenerator(16);

        $nonce = $generator->generate();

        $this->assertNotEmpty($nonce);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9+\/=]+$/', $nonce);
    }

    #[Test]
    public function it_returns_the_same_nonce_for_the_same_request(): void
    {
        $generator = new CspNonceGenerator(16);

        $nonce1 = $generator->get();
        $nonce2 = $generator->get();

        $this->assertSame($nonce1, $nonce2);
    }

    #[Test]
    public function it_returns_formatted_nonce(): void
    {
        $generator = new CspNonceGenerator(16);

        $formatted = $generator->getFormatted();

        $this->assertStringStartsWith("'nonce-", $formatted);
        $this->assertStringEndsWith("'", $formatted);
    }

    #[Test]
    public function it_generates_nonce_of_minimum_length(): void
    {
        $generator = new CspNonceGenerator(16);

        $nonce = $generator->generate();

        // 16 bytes base64 encoded = ~22 characters
        $this->assertGreaterThanOrEqual(22, strlen($nonce));
    }

    #[Test]
    public function it_can_reset_the_nonce(): void
    {
        $generator = new CspNonceGenerator(16);

        $nonce1 = $generator->get();
        $generator->reset();
        $nonce2 = $generator->get();

        $this->assertNotSame($nonce1, $nonce2);
    }

    #[Test]
    public function it_generates_nonce_of_requested_length(): void
    {
        $generator = new CspNonceGenerator(32); // 32 bytes

        $nonce = $generator->generate();

        $decoded = base64_decode($nonce);
        $this->assertEquals(32, strlen($decoded));
    }
}
