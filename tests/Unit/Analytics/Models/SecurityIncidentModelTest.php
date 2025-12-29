<?php

declare(strict_types=1);

namespace Tests\Unit\Analytics\Models;

use ArtisanPackUI\Security\Models\SecurityIncident;
use Tests\Unit\Analytics\AnalyticsTestCase;

class SecurityIncidentModelTest extends AnalyticsTestCase
{
    public function test_it_can_create_incident(): void
    {
        $incident = SecurityIncident::factory()->create([
            'title' => 'Test Incident',
            'status' => SecurityIncident::STATUS_OPEN,
            'severity' => SecurityIncident::SEVERITY_HIGH,
        ]);

        $this->assertDatabaseHas('security_incidents', [
            'id' => $incident->id,
            'title' => 'Test Incident',
            'status' => SecurityIncident::STATUS_OPEN,
        ]);
    }

    public function test_it_generates_incident_number(): void
    {
        $incident = SecurityIncident::factory()->create();

        $this->assertNotNull($incident->incident_number);
        $this->assertStringStartsWith('INC-', $incident->incident_number);
    }

    public function test_it_casts_arrays(): void
    {
        $incident = SecurityIncident::factory()->create([
            'affected_users' => [1, 2, 3],
            'affected_ips' => ['192.168.1.1', '10.0.0.1'],
        ]);

        $this->assertIsArray($incident->affected_users);
        $this->assertIsArray($incident->affected_ips);
    }

    public function test_it_casts_dates(): void
    {
        $incident = SecurityIncident::factory()->create([
            'opened_at' => now(),
            'resolved_at' => now()->addHour(),
        ]);

        $this->assertInstanceOf(\Carbon\Carbon::class, $incident->opened_at);
        $this->assertInstanceOf(\Carbon\Carbon::class, $incident->resolved_at);
    }

    public function test_it_checks_if_open(): void
    {
        $open = SecurityIncident::factory()->open()->create();
        $resolved = SecurityIncident::factory()->resolved()->create();

        $this->assertTrue($open->isOpen());
        $this->assertFalse($resolved->isOpen());
    }

    public function test_it_checks_if_closed(): void
    {
        $open = SecurityIncident::factory()->open()->create();
        $closed = SecurityIncident::factory()->closed()->create();

        $this->assertFalse($open->isClosed());
        $this->assertTrue($closed->isClosed());
    }

    public function test_it_adds_affected_user(): void
    {
        $incident = SecurityIncident::factory()->create([
            'affected_users' => [],
        ]);

        $incident->addAffectedUser(123);

        $this->assertContains(123, $incident->affected_users);
    }

    public function test_it_adds_affected_ip(): void
    {
        $incident = SecurityIncident::factory()->create([
            'affected_ips' => [],
        ]);

        $incident->addAffectedIp('192.168.1.100');

        $this->assertContains('192.168.1.100', $incident->affected_ips);
    }

    public function test_it_adds_action(): void
    {
        $incident = SecurityIncident::factory()->create([
            'actions_taken' => [],
        ]);

        $incident->addAction('block_ip', ['ip' => '192.168.1.1']);

        $actions = $incident->actions_taken;
        $this->assertCount(1, $actions);
        $this->assertEquals('block_ip', $actions[0]['action']);
    }

    public function test_it_scopes_by_status(): void
    {
        SecurityIncident::factory()->count(2)->create(['status' => SecurityIncident::STATUS_OPEN]);
        SecurityIncident::factory()->create(['status' => SecurityIncident::STATUS_RESOLVED]);

        $this->assertEquals(2, SecurityIncident::status(SecurityIncident::STATUS_OPEN)->count());
    }

    public function test_it_scopes_open_incidents(): void
    {
        SecurityIncident::factory()->count(3)->open()->create();
        SecurityIncident::factory()->count(2)->resolved()->create();

        $this->assertEquals(3, SecurityIncident::open()->count());
    }

    public function test_it_scopes_by_severity(): void
    {
        SecurityIncident::factory()->create(['severity' => SecurityIncident::SEVERITY_CRITICAL]);
        SecurityIncident::factory()->count(2)->create(['severity' => SecurityIncident::SEVERITY_HIGH]);

        $this->assertEquals(1, SecurityIncident::severity(SecurityIncident::SEVERITY_CRITICAL)->count());
        $this->assertEquals(2, SecurityIncident::severity(SecurityIncident::SEVERITY_HIGH)->count());
    }

    public function test_it_has_status_constants(): void
    {
        $this->assertEquals('open', SecurityIncident::STATUS_OPEN);
        $this->assertEquals('investigating', SecurityIncident::STATUS_INVESTIGATING);
        $this->assertEquals('contained', SecurityIncident::STATUS_CONTAINED);
        $this->assertEquals('resolved', SecurityIncident::STATUS_RESOLVED);
        $this->assertEquals('closed', SecurityIncident::STATUS_CLOSED);
    }

    public function test_it_has_severity_constants(): void
    {
        $this->assertEquals('info', SecurityIncident::SEVERITY_INFO);
        $this->assertEquals('low', SecurityIncident::SEVERITY_LOW);
        $this->assertEquals('medium', SecurityIncident::SEVERITY_MEDIUM);
        $this->assertEquals('high', SecurityIncident::SEVERITY_HIGH);
        $this->assertEquals('critical', SecurityIncident::SEVERITY_CRITICAL);
    }
}
