<?php

declare(strict_types=1);

namespace Tests\Unit\Analytics\Exporters;

use ArtisanPackUI\Security\Analytics\Siem\Exporters\SplunkExporter;
use Tests\Unit\Analytics\AnalyticsTestCase;

class SplunkExporterTest extends AnalyticsTestCase
{
    protected SplunkExporter $exporter;

    protected function setUp(): void
    {
        parent::setUp();
        $this->exporter = new SplunkExporter([
            'enabled' => true,
            'hec_url' => 'https://splunk.example.com:8088/services/collector',
            'hec_token' => 'test-token-12345',
            'index' => 'security',
            'source' => 'artisanpack-security',
            'sourcetype' => '_json',
            'verify_ssl' => false,
        ]);
    }

    public function test_it_has_correct_name(): void
    {
        $this->assertEquals('splunk', $this->exporter->getName());
    }

    public function test_it_can_be_enabled_and_disabled(): void
    {
        $this->assertTrue($this->exporter->isEnabled());

        $disabledExporter = new SplunkExporter(['enabled' => false]);
        $this->assertFalse($disabledExporter->isEnabled());
    }

    public function test_it_requires_hec_url_and_token(): void
    {
        $exporterNoUrl = new SplunkExporter([
            'enabled' => true,
            'hec_url' => null,
            'hec_token' => 'token',
        ]);
        $this->assertFalse($exporterNoUrl->isEnabled());

        $exporterNoToken = new SplunkExporter([
            'enabled' => true,
            'hec_url' => 'https://splunk.example.com',
            'hec_token' => null,
        ]);
        $this->assertFalse($exporterNoToken->isEnabled());
    }

    public function test_it_returns_error_when_disabled(): void
    {
        $disabledExporter = new SplunkExporter(['enabled' => false]);

        $result = $disabledExporter->export(['event_type' => 'test']);

        $this->assertFalse($result['success']);
        $this->assertStringContainsString('not configured', $result['error']);
    }

    public function test_it_returns_zero_for_empty_batch(): void
    {
        $result = $this->exporter->exportBatch([]);

        $this->assertTrue($result['success']);
        $this->assertEquals(0, $result['exported']);
    }

    public function test_it_returns_config(): void
    {
        $config = $this->exporter->getConfig();

        $this->assertArrayHasKey('enabled', $config);
        $this->assertArrayHasKey('hec_url', $config);
        $this->assertArrayHasKey('hec_token', $config);
        $this->assertArrayHasKey('index', $config);
        $this->assertArrayHasKey('source', $config);
        $this->assertArrayHasKey('sourcetype', $config);
    }

    public function test_it_handles_json_encoding_errors_gracefully(): void
    {
        // Create an event with non-UTF8 data that would fail JSON encoding
        $event = [
            'event_type' => 'test',
            'data' => "\xB1\x31", // Invalid UTF-8
        ];

        $result = $this->exporter->export($event);

        // Should return error for JSON encoding failure
        $this->assertFalse($result['success']);
        $this->assertArrayHasKey('error', $result);
    }
}
