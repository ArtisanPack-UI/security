<?php

namespace Tests\Unit;

use ArtisanPackUI\Security\Rules\NoHtml;
use ArtisanPackUI\Security\Rules\PasswordPolicy;
use ArtisanPackUI\Security\Rules\SecureUrl;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\Test;
use Tests\Concerns\ValidatesInput;
use Tests\TestCase;
use ArtisanPackUI\Security\Rules\SecureFile;

class ValidationRulesTest extends TestCase
{
    use ValidatesInput;

    #[Test]
    public function it_validates_password_policy()
    {
        Http::fake([
            'api.pwnedpasswords.com/*' => Http::response('0', 200),
        ]);

        $rule = new PasswordPolicy();
        $this->assertFailsValidation($rule, 'password');
        $this->assertValidates($rule, 'Password123!');
    }

    #[Test]
    public function it_validates_secure_urls()
    {
        $rule = new SecureUrl();
        $this->assertFailsValidation($rule, 'javascript:alert(1)');
        $this->assertFailsValidation($rule, 'ftp://example.com');
        $this->assertValidates($rule, 'https://example.com');
    }

    #[Test]
    public function it_validates_no_html()
    {
        $rule = new NoHtml();
        $this->assertFailsValidation($rule, '<p>some text</p>');
        $this->assertValidates($rule, 'some text');
    }

    #[Test]
    public function it_validates_secure_files()
    {
        // Test with a default rule - valid jpg file
        $rule = new SecureFile();
        $file = UploadedFile::fake()->image('avatar.jpg', 100, 100);
        $this->assertValidates($rule, $file);

        // Test with blocked extension (php) - should fail
        $rule = new SecureFile();
        $file = UploadedFile::fake()->create('malware.php', 100, 'text/x-php');
        $this->assertFailsValidation($rule, $file);

        // Test with size limit exceeded
        $rule = (new SecureFile())->maxKilobytes(1); // 1KB max
        $file = UploadedFile::fake()->create('large.jpg', 2048, 'image/jpeg'); // 2MB file
        $this->assertFailsValidation($rule, $file);
    }
}
