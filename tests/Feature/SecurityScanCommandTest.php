<?php

declare(strict_types=1);

namespace Tests\Feature;

use Tests\TestCase;

class SecurityScanCommandTest extends TestCase
{
    public function test_security_scan_command_exists(): void
    {
        $this->artisan('security:scan --help')
            ->assertSuccessful();
    }

    public function test_security_audit_command_exists(): void
    {
        $this->artisan('security:audit --help')
            ->assertSuccessful();
    }

    public function test_security_benchmark_command_exists(): void
    {
        $this->artisan('security:benchmark --help')
            ->assertSuccessful();
    }

    public function test_security_baseline_command_exists(): void
    {
        $this->artisan('security:baseline --help')
            ->assertSuccessful();
    }

    public function test_security_baseline_show_action(): void
    {
        $this->artisan('security:baseline', ['action' => 'show'])
            ->assertSuccessful();
    }
}
