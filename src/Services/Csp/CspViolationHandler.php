<?php

/**
 * CspViolationHandler CSP service.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Services\Csp;

use ArtisanPackUI\Security\Contracts\SecurityEventLoggerInterface;
use ArtisanPackUI\Security\Events\CspViolationReceived;
use ArtisanPackUI\Security\Models\CspViolationReport;
use Illuminate\Support\Facades\Log;

/**
 * Handles CSP violation reports from browsers.
 */
class CspViolationHandler
{
    /**
     * Create a new violation handler instance.
     */
    public function __construct(
        protected ?SecurityEventLoggerInterface $logger = null,
    ) {}

    /**
     * Handle a CSP violation report.
     *
     * @param  array<string, mixed>  $report
     */
    public function handle(array $report): ?CspViolationReport
    {
        // Extract csp-report from wrapper if present
        $cspReport = $report['csp-report'] ?? $report;

        // Validate the report has required fields
        if (! $this->validateReport($cspReport)) {
            Log::warning('CSP: Invalid violation report received', ['report' => $report]);

            return null;
        }

        // Generate fingerprint for deduplication
        $fingerprint = CspViolationReport::generateFingerprint($cspReport);

        // Normalize the report data
        $data = $this->normalizeReport($cspReport);

        // Check if we should store violations
        if (! config('artisanpack.security.csp.reporting.storeViolations', true)) {
            // Just log and dispatch event without storing
            $this->logViolation($data);

            return null;
        }

        // Find existing or create new violation record
        $violation = CspViolationReport::where('fingerprint', $fingerprint)->first();

        if ($violation) {
            // Update existing violation
            $violation->update([
                'last_seen_at'     => now(),
                'occurrence_count' => $violation->occurrence_count + 1,
            ]);
        } else {
            // Create new violation record
            $violation = CspViolationReport::create(array_merge($data, [
                'fingerprint'      => $fingerprint,
                'occurrence_count' => 1,
                'first_seen_at'    => now(),
                'last_seen_at'     => now(),
            ]));
        }

        // Dispatch event for real-time monitoring
        event(new CspViolationReceived($violation));

        // Log to security events if enabled
        if (config('artisanpack.security.csp.reporting.logToSecurityEvents', true)) {
            $this->logSecurityEvent($violation);
        }

        return $violation;
    }

    /**
     * Validate that the report contains required fields.
     *
     * @param  array<string, mixed>  $report
     */
    protected function validateReport(array $report): bool
    {
        // At minimum, we need a violated directive
        $directive = $report['violated-directive']
            ?? $report['violatedDirective']
            ?? $report['effective-directive']
            ?? $report['effectiveDirective']
            ?? null;

        return null !== $directive;
    }

    /**
     * Normalize report data from different CSP report formats.
     *
     * @param  array<string, mixed>  $report
     *
     * @return array<string, mixed>
     */
    protected function normalizeReport(array $report): array
    {
        return [
            'document_uri'        => $this->getValue($report, ['document-uri', 'documentUri', 'documentURL']) ?? '',
            'blocked_uri'         => $this->getValue($report, ['blocked-uri', 'blockedUri', 'blockedURL']),
            'violated_directive'  => $this->getValue($report, ['violated-directive', 'violatedDirective']) ?? '',
            'effective_directive' => $this->getValue($report, ['effective-directive', 'effectiveDirective']),
            'original_policy'     => $this->getValue($report, ['original-policy', 'originalPolicy']),
            'disposition'         => $this->getValue($report, ['disposition']) ?? 'enforce',
            'referrer'            => $this->getValue($report, ['referrer']),
            'script_sample'       => $this->getValue($report, ['script-sample', 'scriptSample', 'sample']),
            'source_file'         => $this->getValue($report, ['source-file', 'sourceFile']),
            'line_number'         => $this->getIntValue($report, ['line-number', 'lineNumber']),
            'column_number'       => $this->getIntValue($report, ['column-number', 'columnNumber']),
            'status_code'         => $this->getValue($report, ['status-code', 'statusCode']),
            'user_agent'          => request()->userAgent(),
            'ip_address'          => config('artisanpack.security.csp.reporting.storeIpAddress', false)
                ? request()->ip()
                : null,
        ];
    }

    /**
     * Get a value from the report using multiple possible keys.
     *
     * @param  array<string, mixed>  $report
     * @param  array<string>  $keys
     */
    protected function getValue(array $report, array $keys): ?string
    {
        foreach ($keys as $key) {
            if (isset($report[$key]) && '' !== $report[$key]) {
                return (string) $report[$key];
            }
        }

        return null;
    }

    /**
     * Get an integer value from the report using multiple possible keys.
     *
     * @param  array<string, mixed>  $report
     * @param  array<string>  $keys
     */
    protected function getIntValue(array $report, array $keys): ?int
    {
        $value = $this->getValue($report, $keys);

        return null !== $value ? (int) $value : null;
    }

    /**
     * Log the violation for debugging.
     *
     * @param  array<string, mixed>  $data
     */
    protected function logViolation(array $data): void
    {
        Log::info('CSP Violation', [
            'directive'    => $data['violated_directive'],
            'blocked_uri'  => $data['blocked_uri'],
            'document_uri' => $data['document_uri'],
            'source_file'  => $data['source_file'],
            'line_number'  => $data['line_number'],
        ]);
    }

    /**
     * Log to the security event logger.
     */
    protected function logSecurityEvent(CspViolationReport $violation): void
    {
        if (! $this->logger) {
            return;
        }

        $this->logger->logSecurityViolation(
            'csp_violation',
            "CSP violation: {$violation->violated_directive}",
            [
                'blocked_uri'      => $violation->blocked_uri,
                'document_uri'     => $violation->document_uri,
                'source_file'      => $violation->source_file,
                'line_number'      => $violation->line_number,
                'occurrence_count' => $violation->occurrence_count,
            ],
        );
    }
}
