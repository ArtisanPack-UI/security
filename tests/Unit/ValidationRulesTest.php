<?php

declare(strict_types=1);

namespace Tests\Unit;

use ArtisanPackUI\Security\Rules\NoHtml;
use ArtisanPackUI\Security\Rules\SecureUrl;
use PHPUnit\Framework\Attributes\Test;
use Tests\Concerns\ValidatesInput;
use Tests\TestCase;

class ValidationRulesTest extends TestCase
{
    use ValidatesInput;

    #[Test]
    public function it_validates_secure_urls(): void
    {
        $rule = new SecureUrl;
        $this->assertFailsValidation($rule, 'javascript:alert(1)');
        $this->assertFailsValidation($rule, 'ftp://example.com');
        $this->assertValidates($rule, 'https://example.com');
    }

    #[Test]
    public function it_validates_no_html(): void
    {
        $rule = new NoHtml;
        $this->assertFailsValidation($rule, '<p>some text</p>');
        $this->assertValidates($rule, 'some text');
    }
}
