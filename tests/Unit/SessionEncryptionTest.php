<?php

namespace Tests\Unit;

use Tests\TestCase;
use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\Test;

class SessionEncryptionTest extends TestCase
{
    #[Test]
    public function it_enables_session_encryption_by_default()
    {
        $this->assertTrue(Config::get('artisanpack.security.encrypt'));
    }
}
