<?php

/**
 * GitHubActionsIntegration CI/CD integration.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\CiCd;

use ArtisanPackUI\Security\Testing\Reporting\SecurityFinding;

class GitHubActionsIntegration
{
    /**
     * Output findings as GitHub Actions annotations.
     *
     * @param  array<SecurityFinding>  $findings
     */
    public static function outputAnnotations(array $findings): void
    {
        foreach ($findings as $finding) {
            $level = match ($finding->severity) {
                'critical', 'high' => 'error',
                'medium'           => 'warning',
                default            => 'notice',
            };

            $file = '';
            $line = '';

            if ($finding->location) {
                if (preg_match('/^(.+):(\d+)(?::(\d+))?$/', $finding->location, $matches)) {
                    $file = $matches[1];
                    $line = $matches[2];
                } else {
                    $file = $finding->location;
                }
            }

            $params = [];
            if ($file) {
                $params[] = "file={$file}";
            }
            if ($line) {
                $params[] = "line={$line}";
            }

            $paramString = ! empty($params) ? ' '.implode(',', $params) : '';

            echo "::{$level}{$paramString}::{$finding->title}: {$finding->description}\n";
        }
    }

    /**
     * Set a GitHub Actions output variable.
     */
    public static function setOutput(string $name, string $value): void
    {
        $output = getenv('GITHUB_OUTPUT');

        if ($output && file_exists($output)) {
            file_put_contents($output, "{$name}={$value}\n", FILE_APPEND);
        }
    }

    /**
     * Set multiple output variables.
     *
     * @param  array<string, string>  $outputs
     */
    public static function setOutputs(array $outputs): void
    {
        foreach ($outputs as $name => $value) {
            self::setOutput($name, $value);
        }
    }

    /**
     * Add a summary to the GitHub Actions job summary.
     */
    public static function addSummary(string $markdown): void
    {
        $summaryFile = getenv('GITHUB_STEP_SUMMARY');

        if ($summaryFile && is_writable(dirname($summaryFile))) {
            file_put_contents($summaryFile, $markdown."\n", FILE_APPEND);
        }
    }

    /**
     * Generate a summary from findings.
     *
     * @param  array<SecurityFinding>  $findings
     * @param  array<string, mixed>  $summary
     */
    public static function generateSummary(array $findings, array $summary): string
    {
        $md = "## Security Scan Results\n\n";

        // Summary table
        $md .= "| Severity | Count |\n";
        $md .= "|----------|-------|\n";
        foreach ($summary['bySeverity'] ?? [] as $severity => $count) {
            $icon = match ($severity) {
                'critical' => ':red_circle:',
                'high'     => ':orange_circle:',
                'medium'   => ':yellow_circle:',
                'low'      => ':large_blue_circle:',
                'info'     => ':white_circle:',
                default    => '',
            };
            $md .= "| {$icon} ".ucfirst($severity)." | {$count} |\n";
        }
        $md .= '| **Total** | **'.($summary['total'] ?? 0)."** |\n\n";

        // Status badge
        if (($summary['bySeverity']['critical'] ?? 0) > 0) {
            $md .= ":x: **Status: Failed** - Critical vulnerabilities found\n\n";
        } elseif (($summary['bySeverity']['high'] ?? 0) > 0) {
            $md .= ":warning: **Status: Warning** - High severity issues found\n\n";
        } else {
            $md .= ":white_check_mark: **Status: Passed**\n\n";
        }

        // Top findings
        if (! empty($findings)) {
            $md .= "### Top Findings\n\n";

            $topFindings = array_slice($findings, 0, 5);
            foreach ($topFindings as $finding) {
                $icon = match ($finding->severity) {
                    'critical' => ':red_circle:',
                    'high'     => ':orange_circle:',
                    'medium'   => ':yellow_circle:',
                    default    => ':white_circle:',
                };
                $md .= "- {$icon} **{$finding->title}** ({$finding->severity})\n";
            }

            if (count($findings) > 5) {
                $remaining = count($findings) - 5;
                $md .= "\n*...and {$remaining} more findings*\n";
            }
        }

        return $md;
    }

    /**
     * Generate a GitHub Actions workflow file content.
     */
    public static function generateWorkflow(): string
    {
        return <<<'YAML'
name: Security Scan

on:
  push:
    branches: [main, master, develop]
  pull_request:
    branches: [main, master]
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday at midnight

jobs:
  security-scan:
    runs-on: ubuntu-latest

    permissions:
      contents: read
      security-events: write

    steps:
      - uses: actions/checkout@v6

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.2'
          coverage: none

      - name: Install Dependencies
        run: composer install --no-progress --prefer-dist

      - name: Run Security Scan
        run: |
          php artisan security:scan \
            --format=sarif \
            --output=security-results.sarif \
            --fail-on=high
        continue-on-error: true
        id: security-scan

      - name: Upload SARIF Results
        uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: security-results.sarif
          wait-for-processing: true

      - name: Run Dependency Scan
        run: |
          php artisan security:scan \
            --type=dependencies \
            --format=json \
            --output=dependencies.json

      - name: Upload Dependency Report
        uses: actions/upload-artifact@v6
        with:
          name: dependency-report
          path: dependencies.json

      - name: Check Scan Result
        if: steps.security-scan.outcome == 'failure'
        run: exit 1

  security-audit:
    runs-on: ubuntu-latest
    if: github.event_name == 'schedule'

    steps:
      - uses: actions/checkout@v6

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.2'
          coverage: none

      - name: Install Dependencies
        run: composer install --no-progress --prefer-dist

      - name: Run Full Security Audit
        run: |
          php artisan security:audit \
            --benchmark \
            --format=html \
            --output=security-audit.html

      - name: Upload Audit Report
        uses: actions/upload-artifact@v6
        with:
          name: security-audit-report
          path: security-audit.html
          retention-days: 30
YAML;
    }

    /**
     * Check if running in GitHub Actions environment.
     */
    public static function isGitHubActions(): bool
    {
        return 'true' === getenv('GITHUB_ACTIONS');
    }

    /**
     * Get the current GitHub repository.
     */
    public static function getRepository(): ?string
    {
        return getenv('GITHUB_REPOSITORY') ?: null;
    }

    /**
     * Get the current GitHub ref (branch/tag).
     */
    public static function getRef(): ?string
    {
        return getenv('GITHUB_REF') ?: null;
    }

    /**
     * Get the current GitHub SHA.
     */
    public static function getSha(): ?string
    {
        return getenv('GITHUB_SHA') ?: null;
    }
}
