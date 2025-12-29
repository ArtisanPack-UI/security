<?php

declare(strict_types=1);

namespace Tests\Unit\Analytics;

use ArtisanPackUI\Security\Analytics\Reports\Contracts\ReportInterface;
use ArtisanPackUI\Security\Analytics\Reports\ReportGenerator;
use ArtisanPackUI\Security\Models\ScheduledReport;

class ReportGeneratorTest extends AnalyticsTestCase
{
    protected ReportGenerator $generator;

    protected string $testStoragePath;

    protected function setUp(): void
    {
        parent::setUp();

        $this->testStoragePath = sys_get_temp_dir() . '/security-reports-test';

        $this->generator = new ReportGenerator([
            'storage_path' => $this->testStoragePath,
            'default_format' => 'json',
        ]);
    }

    protected function tearDown(): void
    {
        // Cleanup test files
        if (is_dir($this->testStoragePath)) {
            array_map('unlink', glob($this->testStoragePath . '/*') ?: []);
            @rmdir($this->testStoragePath);
        }

        parent::tearDown();
    }

    public function test_it_registers_default_report_types(): void
    {
        $availableTypes = $this->generator->getAvailableReportTypes();

        $this->assertContains(ScheduledReport::TYPE_EXECUTIVE, $availableTypes);
        $this->assertContains(ScheduledReport::TYPE_THREAT, $availableTypes);
        $this->assertContains(ScheduledReport::TYPE_INCIDENT, $availableTypes);
        $this->assertContains(ScheduledReport::TYPE_COMPLIANCE, $availableTypes);
        $this->assertContains(ScheduledReport::TYPE_USER_ACTIVITY, $availableTypes);
        $this->assertContains(ScheduledReport::TYPE_TREND, $availableTypes);
    }

    public function test_it_registers_custom_report_type(): void
    {
        $this->generator->registerReportType('custom_report', MockTestReport::class);

        $this->assertContains('custom_report', $this->generator->getAvailableReportTypes());
    }

    public function test_it_throws_exception_for_unknown_report_type(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Unknown report type: nonexistent');

        $this->generator->generate('nonexistent');
    }

    public function test_it_generates_report_with_default_format(): void
    {
        $this->generator->registerReportType('test_report', MockTestReport::class);

        $result = $this->generator->generate('test_report');

        $this->assertArrayHasKey('type', $result);
        $this->assertArrayHasKey('format', $result);
        $this->assertArrayHasKey('path', $result);
        $this->assertArrayHasKey('filename', $result);
        $this->assertArrayHasKey('generated_at', $result);
        $this->assertArrayHasKey('data', $result);

        $this->assertEquals('test_report', $result['type']);
        $this->assertEquals('json', $result['format']);
        $this->assertTrue(file_exists($result['path']));
    }

    public function test_it_generates_report_with_specified_format(): void
    {
        $this->generator->registerReportType('test_report', MockTestReport::class);

        $result = $this->generator->generate('test_report', ['format' => 'html']);

        $this->assertEquals('html', $result['format']);
        $this->assertStringEndsWith('.html', $result['filename']);
    }

    public function test_it_generates_correct_filename(): void
    {
        $this->generator->registerReportType('test_report', MockTestReport::class);

        $result = $this->generator->generate('test_report');

        $this->assertMatchesRegularExpression(
            '/security_test_report_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.json/',
            $result['filename']
        );
    }

    public function test_it_generates_scheduled_report(): void
    {
        $this->generator->registerReportType('test_type', MockTestReport::class);

        $scheduledReport = ScheduledReport::factory()->create([
            'report_type' => 'test_type',
            'name' => 'Test Scheduled Report',
            'format' => 'json',
            'options' => ['date_range' => '7d'],
        ]);

        $result = $this->generator->generateScheduledReport($scheduledReport);

        $this->assertArrayHasKey('scheduled_report_id', $result);
        $this->assertArrayHasKey('scheduled_report_name', $result);
        $this->assertEquals($scheduledReport->id, $result['scheduled_report_id']);
        $this->assertEquals('Test Scheduled Report', $result['scheduled_report_name']);

        // Verify scheduled report was marked as run
        $scheduledReport->refresh();
        $this->assertNotNull($scheduledReport->last_run_at);
    }

    public function test_it_runs_due_reports(): void
    {
        $this->generator->registerReportType('test_type', MockTestReport::class);

        ScheduledReport::factory()->due()->count(2)->create([
            'report_type' => 'test_type',
        ]);

        ScheduledReport::factory()->active()->create([
            'report_type' => 'test_type',
            'next_run_at' => now()->addDay(),
        ]);

        $results = $this->generator->runDueReports();

        $this->assertCount(2, $results);

        foreach ($results as $result) {
            $this->assertEquals('success', $result['status']);
        }
    }

    public function test_it_handles_report_generation_errors(): void
    {
        $this->generator->registerReportType('error_type', MockErrorReport::class);

        ScheduledReport::factory()->due()->create([
            'report_type' => 'error_type',
        ]);

        $results = $this->generator->runDueReports();

        $this->assertCount(1, $results);
        $this->assertEquals('error', $results[0]['status']);
        $this->assertArrayHasKey('error', $results[0]);
    }

    public function test_it_cleans_up_old_reports(): void
    {
        // Create some old test files
        if (! is_dir($this->testStoragePath)) {
            mkdir($this->testStoragePath, 0755, true);
        }

        $oldFile = $this->testStoragePath . '/security_test_2020-01-01_00-00-00.json';
        file_put_contents($oldFile, 'old content');
        touch($oldFile, strtotime('-60 days'));

        $recentFile = $this->testStoragePath . '/security_test_' . date('Y-m-d_H-i-s') . '.json';
        file_put_contents($recentFile, 'recent content');

        $deleted = $this->generator->cleanup(30);

        $this->assertEquals(1, $deleted);
        $this->assertFalse(file_exists($oldFile));
        $this->assertTrue(file_exists($recentFile));
    }

    public function test_cleanup_returns_zero_when_no_directory(): void
    {
        $generator = new ReportGenerator([
            'storage_path' => '/nonexistent/path',
        ]);

        $deleted = $generator->cleanup(30);

        $this->assertEquals(0, $deleted);
    }
}

/**
 * Mock test report class for testing.
 */
class MockTestReport implements ReportInterface
{
    public function __construct(array $options = [])
    {
    }

    public function generate(): array
    {
        return [
            'title' => 'Test Report',
            'generated_at' => now()->toIso8601String(),
            'data' => ['test' => 'data'],
        ];
    }

    public function toHtml(array $data): string
    {
        return '<html><body>' . json_encode($data) . '</body></html>';
    }

    public function toCsv(array $data): string
    {
        return "column1,column2\nvalue1,value2";
    }

    public function toPdf(array $data): string
    {
        return '%PDF-1.4 mock pdf content';
    }

    public function getTitle(): string
    {
        return 'Test Report';
    }

    public function getDescription(): string
    {
        return 'Test report description';
    }
}

/**
 * Mock error report class that throws an exception.
 */
class MockErrorReport implements ReportInterface
{
    public function __construct(array $options = [])
    {
    }

    public function generate(): array
    {
        throw new \RuntimeException('Test error');
    }

    public function toHtml(array $data): string
    {
        return '';
    }

    public function toCsv(array $data): string
    {
        return '';
    }

    public function toPdf(array $data): string
    {
        return '';
    }

    public function getTitle(): string
    {
        return 'Error Report';
    }

    public function getDescription(): string
    {
        return 'Error report description';
    }
}
