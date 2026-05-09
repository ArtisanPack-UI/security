<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\Reporting\Formats;

use ArtisanPackUI\Security\Testing\Reporting\SecurityFinding;

class HtmlReportFormat implements ReportFormatInterface
{
    public function format(array $findings, array $metadata, array $summary): string
    {
        $projectName = htmlspecialchars($metadata['projectName'] ?? 'Security Report');
        $generatedAt = htmlspecialchars($metadata['generatedAt'] ?? date('c'));

        $summaryCards = $this->renderSummaryCards($summary);
        $findingsHtml = $this->renderFindings($findings);

        return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - {$projectName}</title>
    <style>
        :root {
            --critical: #dc2626;
            --high: #ea580c;
            --medium: #ca8a04;
            --low: #2563eb;
            --info: #6b7280;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: system-ui, -apple-system, sans-serif;
            line-height: 1.6;
            color: #1f2937;
            background: #f9fafb;
            padding: 2rem;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { font-size: 2rem; margin-bottom: 0.5rem; }
        h2 { font-size: 1.5rem; margin: 2rem 0 1rem; }
        .meta { color: #6b7280; margin-bottom: 2rem; }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .summary-card {
            background: white;
            padding: 1.5rem;
            border-radius: 0.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            text-align: center;
        }
        .summary-card .count {
            font-size: 2.5rem;
            font-weight: bold;
        }
        .summary-card .label {
            color: #6b7280;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
        }
        .summary-card.critical .count { color: var(--critical); }
        .summary-card.high .count { color: var(--high); }
        .summary-card.medium .count { color: var(--medium); }
        .summary-card.low .count { color: var(--low); }
        .summary-card.info .count { color: var(--info); }
        .finding {
            background: white;
            border-radius: 0.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            margin-bottom: 1rem;
            overflow: hidden;
        }
        .finding-header {
            padding: 1rem 1.5rem;
            display: flex;
            align-items: center;
            gap: 1rem;
            border-bottom: 1px solid #e5e7eb;
        }
        .severity-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            color: white;
        }
        .severity-badge.critical { background: var(--critical); }
        .severity-badge.high { background: var(--high); }
        .severity-badge.medium { background: var(--medium); }
        .severity-badge.low { background: var(--low); }
        .severity-badge.info { background: var(--info); }
        .finding-title { font-weight: 600; flex: 1; }
        .finding-id { color: #6b7280; font-size: 0.875rem; }
        .finding-body { padding: 1rem 1.5rem; }
        .finding-description { margin-bottom: 1rem; }
        .finding-meta {
            font-size: 0.875rem;
            color: #6b7280;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 0.5rem;
        }
        .finding-meta strong { color: #374151; }
        .remediation {
            background: #f0fdf4;
            border-left: 4px solid #22c55e;
            padding: 1rem;
            margin-top: 1rem;
            font-size: 0.875rem;
        }
        .no-findings {
            text-align: center;
            padding: 3rem;
            color: #6b7280;
        }
        .no-findings .icon { font-size: 3rem; margin-bottom: 1rem; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Report</h1>
        <p class="meta">
            Project: {$projectName} | Generated: {$generatedAt}
        </p>

        <div class="summary">
            {$summaryCards}
        </div>

        <h2>Findings</h2>
        {$findingsHtml}
    </div>
</body>
</html>
HTML;
    }

    public function getName(): string
    {
        return 'HTML';
    }

    public function getExtension(): string
    {
        return 'html';
    }

    public function getMimeType(): string
    {
        return 'text/html';
    }

    /**
     * Render summary cards.
     *
     * @param  array<string, mixed>  $summary
     */
    protected function renderSummaryCards(array $summary): string
    {
        $severities = $summary['bySeverity'] ?? [];
        $cards      = '';

        foreach ($severities as $severity => $count) {
            $cards .= <<<HTML
            <div class="summary-card {$severity}">
                <div class="count">{$count}</div>
                <div class="label">{$severity}</div>
            </div>
            HTML;
        }

        return $cards;
    }

    /**
     * Render findings.
     *
     * @param  array<SecurityFinding>  $findings
     */
    protected function renderFindings(array $findings): string
    {
        if (empty($findings)) {
            return <<<'HTML'
            <div class="no-findings">
                <div class="icon">✓</div>
                <p>No security findings detected.</p>
            </div>
            HTML;
        }

        $html = '';

        foreach ($findings as $finding) {
            $title       = htmlspecialchars($finding->title);
            $description = htmlspecialchars($finding->description);
            $category    = htmlspecialchars($finding->category);
            $location    = $finding->location ? htmlspecialchars($finding->location) : 'N/A';
            $remediation = $finding->remediation ? htmlspecialchars($finding->remediation) : null;

            $remediationHtml = $remediation
                ? "<div class=\"remediation\"><strong>Remediation:</strong> {$remediation}</div>"
                : '';

            $html .= <<<HTML
            <div class="finding">
                <div class="finding-header">
                    <span class="severity-badge {$finding->severity}">{$finding->severity}</span>
                    <span class="finding-title">{$title}</span>
                    <span class="finding-id">{$finding->id}</span>
                </div>
                <div class="finding-body">
                    <p class="finding-description">{$description}</p>
                    <div class="finding-meta">
                        <div><strong>Category:</strong> {$category}</div>
                        <div><strong>Location:</strong> {$location}</div>
                    </div>
                    {$remediationHtml}
                </div>
            </div>
            HTML;
        }

        return $html;
    }
}
