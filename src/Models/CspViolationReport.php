<?php

/**
 * CSP violation report Eloquent model.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;

class CspViolationReport extends Model
{
    /**
     * The table associated with the model.
     */
    protected $table = 'csp_violation_reports';

    /**
     * The attributes that are mass assignable.
     */
    protected $fillable = [
        'document_uri',
        'blocked_uri',
        'violated_directive',
        'effective_directive',
        'original_policy',
        'disposition',
        'referrer',
        'script_sample',
        'source_file',
        'line_number',
        'column_number',
        'status_code',
        'user_agent',
        'ip_address',
        'fingerprint',
        'occurrence_count',
        'first_seen_at',
        'last_seen_at',
    ];

    /**
     * The attributes that should be cast.
     */
    protected $casts = [
        'line_number' => 'integer',
        'column_number' => 'integer',
        'occurrence_count' => 'integer',
        'first_seen_at' => 'datetime',
        'last_seen_at' => 'datetime',
    ];

    /**
     * Scope to get recent violations.
     */
    public function scopeRecent(Builder $query, int $hours = 24): Builder
    {
        return $query->where('last_seen_at', '>=', now()->subHours($hours));
    }

    /**
     * Scope to filter by directive.
     */
    public function scopeByDirective(Builder $query, string $directive): Builder
    {
        return $query->where('violated_directive', $directive);
    }

    /**
     * Scope to filter by disposition.
     */
    public function scopeEnforced(Builder $query): Builder
    {
        return $query->where('disposition', 'enforce');
    }

    /**
     * Scope to filter by disposition.
     */
    public function scopeReportOnly(Builder $query): Builder
    {
        return $query->where('disposition', 'report');
    }

    /**
     * Get top violations by occurrence count.
     */
    public static function getTopViolations(int $limit = 10): Collection
    {
        return static::query()
            ->orderByDesc('occurrence_count')
            ->limit($limit)
            ->get();
    }

    /**
     * Get violations grouped by directive.
     *
     * @return Collection<string, int>
     */
    public static function getViolationsByDirective(): Collection
    {
        return static::query()
            ->selectRaw('violated_directive, SUM(occurrence_count) as total')
            ->groupBy('violated_directive')
            ->orderByDesc('total')
            ->pluck('total', 'violated_directive');
    }

    /**
     * Get violation trend data for charts.
     *
     * @return array<string, int>
     */
    public static function getViolationTrend(int $days = 7): array
    {
        $trend = [];
        $startDate = now()->subDays($days)->startOfDay();

        // Pre-fill with zeros for all dates in range
        for ($i = 0; $i <= $days; $i++) {
            $date = $startDate->copy()->addDays($i);
            $trend[$date->format('Y-m-d')] = 0;
        }

        // Fetch violations and group by date in PHP for database portability
        $violations = static::query()
            ->where('first_seen_at', '>=', $startDate)
            ->select('first_seen_at')
            ->get();

        foreach ($violations as $violation) {
            if ($violation->first_seen_at) {
                $date = $violation->first_seen_at->format('Y-m-d');
                if (isset($trend[$date])) {
                    $trend[$date]++;
                }
            }
        }

        return $trend;
    }

    /**
     * Get top blocked URIs.
     */
    public static function getTopBlockedUris(int $limit = 10): Collection
    {
        return static::query()
            ->whereNotNull('blocked_uri')
            ->where('blocked_uri', '!=', '')
            ->selectRaw('blocked_uri, SUM(occurrence_count) as total')
            ->groupBy('blocked_uri')
            ->orderByDesc('total')
            ->limit($limit)
            ->pluck('total', 'blocked_uri');
    }

    /**
     * Generate a fingerprint for deduplication.
     *
     * @param  array<string, mixed>  $report
     */
    public static function generateFingerprint(array $report): string
    {
        $components = [
            $report['document-uri'] ?? $report['documentUri'] ?? '',
            $report['blocked-uri'] ?? $report['blockedUri'] ?? '',
            $report['violated-directive'] ?? $report['violatedDirective'] ?? '',
            $report['source-file'] ?? $report['sourceFile'] ?? '',
            $report['line-number'] ?? $report['lineNumber'] ?? '',
        ];

        return hash('sha256', implode('|', $components));
    }

    /**
     * Prune old violation reports.
     */
    public static function prune(int $retentionDays = 30): int
    {
        return static::query()
            ->where('last_seen_at', '<', now()->subDays($retentionDays))
            ->delete();
    }

    /**
     * Get total violation count for a time period.
     */
    public static function getTotalCount(int $hours = 24): int
    {
        return (int) static::query()
            ->where('last_seen_at', '>=', now()->subHours($hours))
            ->sum('occurrence_count');
    }

    /**
     * Get unique violation count for a time period.
     */
    public static function getUniqueCount(int $hours = 24): int
    {
        return static::query()
            ->where('last_seen_at', '>=', now()->subHours($hours))
            ->count();
    }
}
