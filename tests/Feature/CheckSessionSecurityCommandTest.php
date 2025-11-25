<?php

namespace Tests\Feature;

use Tests\TestCase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\Test;

class CheckSessionSecurityCommandTest extends TestCase
{
    #[Test]
    public function it_shows_success_message_when_encryption_is_enabled()
    {
        Config::set('artisanpack.security.encrypt', true);

        Artisan::call('security:check-session');

        $this->assertStringContainsString('Session encryption is enabled.', Artisan::output());
    }

    #[Test]
    public function it_shows_warning_message_when_encryption_is_disabled()
    {
        Config::set('artisanpack.security.encrypt', false);

        Artisan::call('security:check-session');

        $this->assertStringContainsString('Session encryption is disabled.', Artisan::output());
    }

    #[Test]
    public function it_shows_error_message_when_encryption_is_disabled_in_production()
    {
        Config::set('artisanpack.security.encrypt', false);
        $this->app->detectEnvironment(function () {
            return 'production';
        });

        Artisan::call('security:check-session');

        $this->assertStringContainsString('WARNING: Session encryption is disabled in a production environment.', Artisan::output());
    }
}
