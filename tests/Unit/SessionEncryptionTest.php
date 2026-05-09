<?php

declare(strict_types=1);

namespace Tests\Unit;

use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class SessionEncryptionTest extends TestCase
{
    #[Test]
    public function it_enables_session_encryption_by_default(): void
    {
        $this->assertTrue(Config::get('artisanpack.security.encrypt'));
    }
}
