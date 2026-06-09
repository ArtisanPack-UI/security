<?php

/**
 * CspDashboard Livewire component.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Livewire;

use ArtisanPackUI\Security\Models\CspViolationReport;
use Livewire\Component;

class CspDashboard extends Component
{
    public int $days = 7;

    public int $totalViolations = 0;

    public int $uniqueViolations = 0;

    public int $enforcedCount = 0;

    public int $reportOnlyCount = 0;

    public array $violationsByDirectiveChart = [];

    public array $violationTrendChart = [];

    public array $topBlockedUris = [];

    public array $recentViolations = [];

    public array $directiveHeaders = [
        ['key' => 'directive', 'label' => 'Directive'],
        ['key' => 'count', 'label' => 'Violations'],
    ];

    public array $blockedUriHeaders = [
        ['key' => 'uri', 'label' => 'Blocked URI'],
        ['key' => 'count', 'label' => 'Occurrences'],
    ];

    public function mount(): void
    {
        if (! auth()->user()?->can('viewSecurityDashboard')) {
            abort(403, 'Unauthorized to view CSP dashboard.');
        }

        $this->loadStats();
    }

    public function updatedDays(): void
    {
        $this->loadStats();
    }

    public function render()
    {
        return view('security::livewire.csp-dashboard');
    }

    protected function loadStats(): void
    {
        $hours = $this->days * 24;

        // Summary stats
        $this->totalViolations = CspViolationReport::getTotalCount($hours);
        $this->uniqueViolations = CspViolationReport::getUniqueCount($hours);

        // Count by disposition
        $this->enforcedCount = (int) CspViolationReport::query()
            ->where('last_seen_at', '>=', now()->subHours($hours))
            ->where('disposition', 'enforce')
            ->sum('occurrence_count');

        $this->reportOnlyCount = (int) CspViolationReport::query()
            ->where('last_seen_at', '>=', now()->subHours($hours))
            ->where('disposition', 'report')
            ->sum('occurrence_count');

        // Chart: Violations by directive
        $byDirective = CspViolationReport::getViolationsByDirective();
        $this->violationsByDirectiveChart = $this->buildDirectiveChart($byDirective->toArray());

        // Chart: Trend over time
        $trend = CspViolationReport::getViolationTrend($this->days);
        $this->violationTrendChart = $this->buildTrendChart($trend);

        // Top blocked URIs
        $this->topBlockedUris = CspViolationReport::getTopBlockedUris(10)
            ->map(function ($count, $uri) {
                // Truncate long URIs for display
                $displayUri = strlen($uri) > 50 ? substr($uri, 0, 47).'...' : $uri;

                return ['uri' => $displayUri, 'full_uri' => $uri, 'count' => $count];
            })
            ->values()
            ->toArray();

        // Recent violations
        $this->recentViolations = CspViolationReport::query()
            ->orderByDesc('last_seen_at')
            ->limit(5)
            ->get()
            ->map(fn ($violation) => [
                'directive' => $violation->violated_directive,
                'blocked_uri' => $violation->blocked_uri
                    ? (strlen($violation->blocked_uri) > 30 ? substr($violation->blocked_uri, 0, 27).'...' : $violation->blocked_uri)
                    : 'N/A',
                'occurrence_count' => $violation->occurrence_count,
                'last_seen' => $violation->last_seen_at?->diffForHumans() ?? 'N/A',
            ])
            ->toArray();
    }

    /**
     * Build chart data for violations by directive.
     *
     * @param  array<string, int>  $data
     */
    protected function buildDirectiveChart(array $data): array
    {
        $colors = [
            'rgba(239, 68, 68, 0.7)',   // Red
            'rgba(245, 158, 11, 0.7)',  // Amber
            'rgba(59, 130, 246, 0.7)',  // Blue
            'rgba(16, 185, 129, 0.7)',  // Green
            'rgba(139, 92, 246, 0.7)',  // Purple
            'rgba(236, 72, 153, 0.7)',  // Pink
            'rgba(34, 211, 238, 0.7)',  // Cyan
            'rgba(156, 163, 175, 0.7)', // Gray
        ];

        return [
            'type' => 'doughnut',
            'data' => [
                'labels' => array_keys($data),
                'datasets' => [
                    [
                        'data' => array_values($data),
                        'backgroundColor' => array_slice($colors, 0, count($data)),
                    ],
                ],
            ],
            'options' => [
                'responsive' => true,
                'maintainAspectRatio' => false,
            ],
        ];
    }

    /**
     * Build chart data for violation trend.
     *
     * @param  array<string, int>  $data
     */
    protected function buildTrendChart(array $data): array
    {
        $labels = array_map(function ($date) {
            return date('M j', strtotime($date));
        }, array_keys($data));

        return [
            'type' => 'line',
            'data' => [
                'labels' => $labels,
                'datasets' => [
                    [
                        'label' => 'Violations',
                        'data' => array_values($data),
                        'borderColor' => 'rgba(239, 68, 68, 1)',
                        'backgroundColor' => 'rgba(239, 68, 68, 0.1)',
                        'fill' => true,
                        'tension' => 0.3,
                    ],
                ],
            ],
            'options' => [
                'responsive' => true,
                'maintainAspectRatio' => false,
                'scales' => [
                    'y' => [
                        'beginAtZero' => true,
                    ],
                ],
            ],
        ];
    }
}
