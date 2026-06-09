<?php

declare(strict_types=1);

namespace Tests\Unit\Testing\CiCd;

use ArtisanPackUI\Security\Testing\CiCd\GitHubActionsIntegration;
use ArtisanPackUI\Security\Testing\Reporting\SecurityFinding;
use Tests\TestCase;

class GitHubActionsIntegrationTest extends TestCase
{
    public function test_detects_github_actions_environment(): void
    {
        // When not in GitHub Actions
        $result = GitHubActionsIntegration::isGitHubActions();

        $this->assertIsBool($result);
    }

    public function test_gets_repository_returns_null_when_not_set(): void
    {
        putenv('GITHUB_REPOSITORY');

        $result = GitHubActionsIntegration::getRepository();

        $this->assertNull($result);
    }

    public function test_gets_ref_returns_null_when_not_set(): void
    {
        putenv('GITHUB_REF');

        $result = GitHubActionsIntegration::getRef();

        $this->assertNull($result);
    }

    public function test_gets_sha_returns_null_when_not_set(): void
    {
        putenv('GITHUB_SHA');

        $result = GitHubActionsIntegration::getSha();

        $this->assertNull($result);
    }

    public function test_generates_workflow_yaml(): void
    {
        $workflow = GitHubActionsIntegration::generateWorkflow();

        $this->assertIsString($workflow);
        $this->assertStringContainsString('name: Security Scan', $workflow);
        $this->assertStringContainsString('security-scan:', $workflow);
        $this->assertStringContainsString('runs-on: ubuntu-latest', $workflow);
        $this->assertStringContainsString('php artisan security:scan', $workflow);
    }

    public function test_workflow_includes_sarif_output(): void
    {
        $workflow = GitHubActionsIntegration::generateWorkflow();

        $this->assertStringContainsString('--format=sarif', $workflow);
        $this->assertStringContainsString('upload-sarif', $workflow);
    }

    public function test_workflow_includes_dependency_scanning(): void
    {
        $workflow = GitHubActionsIntegration::generateWorkflow();

        $this->assertStringContainsString('--type=dependencies', $workflow);
    }

    public function test_workflow_includes_scheduled_audit(): void
    {
        $workflow = GitHubActionsIntegration::generateWorkflow();

        $this->assertStringContainsString('schedule:', $workflow);
        $this->assertStringContainsString('cron:', $workflow);
        $this->assertStringContainsString('security:audit', $workflow);
    }

    public function test_generates_summary_markdown(): void
    {
        $findings = [
            SecurityFinding::critical('Critical Issue', 'Critical description', 'test'),
            SecurityFinding::high('High Issue', 'High description', 'test'),
        ];

        $summary = [
            'total' => 2,
            'bySeverity' => [
                'critical' => 1,
                'high' => 1,
                'medium' => 0,
                'low' => 0,
                'info' => 0,
            ],
        ];

        $markdown = GitHubActionsIntegration::generateSummary($findings, $summary);

        $this->assertStringContainsString('## Security Scan Results', $markdown);
        $this->assertStringContainsString('| Severity | Count |', $markdown);
        $this->assertStringContainsString('Critical', $markdown);
        $this->assertStringContainsString('**Status: Failed**', $markdown);
    }

    public function test_summary_shows_warning_for_high_severity(): void
    {
        $findings = [
            SecurityFinding::high('High Issue', 'Description', 'test'),
        ];

        $summary = [
            'total' => 1,
            'bySeverity' => [
                'critical' => 0,
                'high' => 1,
                'medium' => 0,
            ],
        ];

        $markdown = GitHubActionsIntegration::generateSummary($findings, $summary);

        $this->assertStringContainsString('**Status: Warning**', $markdown);
    }

    public function test_summary_shows_passed_for_no_critical_or_high(): void
    {
        $findings = [
            SecurityFinding::medium('Medium Issue', 'Description', 'test'),
        ];

        $summary = [
            'total' => 1,
            'bySeverity' => [
                'critical' => 0,
                'high' => 0,
                'medium' => 1,
            ],
        ];

        $markdown = GitHubActionsIntegration::generateSummary($findings, $summary);

        $this->assertStringContainsString('**Status: Passed**', $markdown);
    }

    public function test_summary_shows_top_findings(): void
    {
        $findings = [];
        for ($i = 1; $i <= 7; $i++) {
            $findings[] = SecurityFinding::medium("Finding {$i}", "Description {$i}", 'test');
        }

        $summary = [
            'total' => 7,
            'bySeverity' => ['medium' => 7],
        ];

        $markdown = GitHubActionsIntegration::generateSummary($findings, $summary);

        $this->assertStringContainsString('### Top Findings', $markdown);
        $this->assertStringContainsString('Finding 1', $markdown);
        $this->assertStringContainsString('Finding 5', $markdown);
        $this->assertStringContainsString('and 2 more findings', $markdown);
    }

    public function test_summary_handles_empty_findings(): void
    {
        $summary = [
            'total' => 0,
            'bySeverity' => [],
        ];

        $markdown = GitHubActionsIntegration::generateSummary([], $summary);

        $this->assertStringContainsString('## Security Scan Results', $markdown);
        $this->assertStringNotContainsString('### Top Findings', $markdown);
    }

    public function test_outputs_annotations_format(): void
    {
        $findings = [
            SecurityFinding::critical('Critical Issue', 'Test description', 'test', 'src/Test.php:10'),
        ];

        ob_start();
        GitHubActionsIntegration::outputAnnotations($findings);
        $output = ob_get_clean();

        $this->assertStringContainsString('::error', $output);
        $this->assertStringContainsString('file=src/Test.php', $output);
        $this->assertStringContainsString('line=10', $output);
    }

    public function test_annotation_level_for_severity(): void
    {
        $findings = [
            SecurityFinding::critical('Critical', 'Desc', 'test'),
            SecurityFinding::high('High', 'Desc', 'test'),
            SecurityFinding::medium('Medium', 'Desc', 'test'),
            SecurityFinding::low('Low', 'Desc', 'test'),
        ];

        ob_start();
        GitHubActionsIntegration::outputAnnotations($findings);
        $output = ob_get_clean();

        $this->assertStringContainsString('::error', $output);
        $this->assertStringContainsString('::warning', $output);
        $this->assertStringContainsString('::notice', $output);
    }

    public function test_annotation_handles_location_without_line(): void
    {
        $findings = [
            SecurityFinding::medium('Test', 'Desc', 'test', 'src/Controller.php'),
        ];

        ob_start();
        GitHubActionsIntegration::outputAnnotations($findings);
        $output = ob_get_clean();

        $this->assertStringContainsString('file=src/Controller.php', $output);
        $this->assertStringNotContainsString('line=', $output);
    }

    public function test_annotation_handles_no_location(): void
    {
        $findings = [
            SecurityFinding::medium('Test', 'Desc', 'test'),
        ];

        ob_start();
        GitHubActionsIntegration::outputAnnotations($findings);
        $output = ob_get_clean();

        $this->assertStringContainsString('::warning::Test', $output);
    }
}
