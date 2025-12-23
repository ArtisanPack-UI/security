<?php

namespace Tests\Unit;

use ArtisanPackUI\Security\Contracts\FileValidatorInterface;
use ArtisanPackUI\Security\Services\FileValidationService;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Config;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\Test;

class FileValidationServiceTest extends TestCase
{
    protected FileValidationService $service;

    protected function getPackageProviders($app)
    {
        return [
            \ArtisanPackUI\Security\SecurityServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app)
    {
        Config::set('artisanpack.security.fileUpload.enabled', true);
        Config::set('artisanpack.security.fileUpload.allowedMimeTypes', [
            'image/jpeg',
            'image/png',
            'image/gif',
            'application/pdf',
        ]);
        Config::set('artisanpack.security.fileUpload.allowedExtensions', [
            'jpg', 'jpeg', 'png', 'gif', 'pdf',
        ]);
        Config::set('artisanpack.security.fileUpload.blockedExtensions', [
            'php', 'exe', 'sh', 'bat',
        ]);
        Config::set('artisanpack.security.fileUpload.blockedMimeTypes', [
            'application/x-msdownload',
            'application/x-php',
        ]);
        Config::set('artisanpack.security.fileUpload.maxFileSize', 10 * 1024 * 1024);
        Config::set('artisanpack.security.fileUpload.checkForDoubleExtensions', true);
        Config::set('artisanpack.security.fileUpload.checkForNullBytes', true);
        Config::set('artisanpack.security.fileUpload.validateMimeByContent', false);
    }

    public function setUp(): void
    {
        parent::setUp();
        $this->service = new FileValidationService();
    }

    #[Test]
    public function it_validates_allowed_image_file()
    {
        $file = UploadedFile::fake()->image('test.jpg', 100, 100);

        $result = $this->service->validate($file);

        $this->assertTrue($result->passed);
        $this->assertEmpty($result->errors);
    }

    #[Test]
    public function it_rejects_blocked_extension()
    {
        $file = UploadedFile::fake()->create('malware.exe', 100, 'application/x-msdownload');

        $result = $this->service->validate($file);

        $this->assertFalse($result->passed);
        $this->assertTrue(
            collect($result->errors)->contains(fn ($e) => str_contains($e, 'not allowed for security reasons'))
        );
    }

    #[Test]
    public function it_rejects_files_exceeding_max_size()
    {
        Config::set('artisanpack.security.fileUpload.maxFileSize', 1024); // 1KB
        $this->service = new FileValidationService();

        $file = UploadedFile::fake()->create('large.pdf', 2048, 'application/pdf'); // 2KB

        $result = $this->service->validate($file);

        $this->assertFalse($result->passed);
        $this->assertTrue(
            collect($result->errors)->contains(fn ($e) => str_contains($e, 'exceeds the maximum'))
        );
    }

    #[Test]
    public function it_detects_double_extension_attack()
    {
        $file = UploadedFile::fake()->create('image.php.jpg', 100, 'image/jpeg');

        $result = $this->service->validate($file);

        $this->assertFalse($result->passed);
        $this->assertTrue(
            collect($result->errors)->contains(fn ($e) => str_contains($e, 'blocked extension'))
        );
    }

    #[Test]
    public function it_detects_null_byte_in_filename()
    {
        $filename = "test\x00.jpg";

        $hasNullByte = $this->service->hasUnsafeFilename($filename);

        $this->assertTrue($hasNullByte);
    }

    #[Test]
    public function it_detects_path_traversal_in_filename()
    {
        $unsafeName = '../../../etc/passwd';

        $hasUnsafe = $this->service->hasUnsafeFilename($unsafeName);

        $this->assertTrue($hasUnsafe);
    }

    #[Test]
    public function it_sanitizes_filename()
    {
        $unsafeName = 'test<script>alert("xss")</script>.jpg';
        $sanitized = $this->service->sanitizeFilename($unsafeName);

        $this->assertStringNotContainsString('<', $sanitized);
        $this->assertStringNotContainsString('>', $sanitized);
    }

    #[Test]
    public function it_sanitizes_filename_with_double_dots()
    {
        $unsafeName = 'file/../../../etc/passwd.txt';
        $sanitized = $this->service->sanitizeFilename($unsafeName);

        $this->assertStringNotContainsString('../', $sanitized);
    }

    #[Test]
    public function it_checks_extension_allowlist()
    {
        $this->assertTrue($this->service->isExtensionAllowed('jpg'));
        $this->assertTrue($this->service->isExtensionAllowed('png'));
        $this->assertFalse($this->service->isExtensionAllowed('exe'));
        $this->assertFalse($this->service->isExtensionAllowed('php'));
    }

    #[Test]
    public function it_checks_mime_type_allowlist()
    {
        $this->assertTrue($this->service->isMimeTypeAllowed('image/jpeg'));
        $this->assertTrue($this->service->isMimeTypeAllowed('image/png'));
        $this->assertFalse($this->service->isMimeTypeAllowed('application/x-php'));
    }

    #[Test]
    public function it_detects_mime_type_from_content()
    {
        $file = UploadedFile::fake()->image('test.jpg', 100, 100);

        $detected = $this->service->detectMimeType($file);

        $this->assertStringContainsString('image/', $detected);
    }

    #[Test]
    public function it_validates_with_custom_max_size_option()
    {
        // Using a jpg which is in the allowlist
        $file = UploadedFile::fake()->image('test.jpg', 100, 100);

        $result = $this->service->validate($file, [
            'maxFileSize' => 10 * 1024 * 1024, // 10MB
        ]);

        $this->assertTrue($result->passed);
    }

    #[Test]
    public function it_rejects_when_custom_max_size_exceeded()
    {
        $file = UploadedFile::fake()->create('document.pdf', 2048, 'application/pdf');

        $result = $this->service->validate($file, [
            'maxFileSize' => 1024, // 1KB
        ]);

        $this->assertFalse($result->passed);
    }

    #[Test]
    public function it_returns_sanitized_filename_in_result()
    {
        $file = UploadedFile::fake()->image('Test File (1).jpg', 100, 100);

        $result = $this->service->validate($file);

        $this->assertNotNull($result->sanitizedFilename);
    }

    #[Test]
    public function it_resolves_from_container()
    {
        $service = app(FileValidatorInterface::class);

        $this->assertInstanceOf(FileValidationService::class, $service);
    }

    #[Test]
    public function it_rejects_extension_not_in_allowlist()
    {
        $file = UploadedFile::fake()->create('document.doc', 100, 'application/msword');

        $result = $this->service->validate($file);

        $this->assertFalse($result->passed);
        $this->assertTrue(
            collect($result->errors)->contains(fn ($e) => str_contains($e, 'extension is not allowed'))
        );
    }
}
