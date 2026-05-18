<?php

/**
 * JsonReportFormat security report formatter.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\Reporting\Formats;

use ArtisanPackUI\Security\Testing\Reporting\SecurityFinding;
use RuntimeException;

class JsonReportFormat implements ReportFormatInterface
{
    public function format(array $findings, array $metadata, array $summary): string
    {
        $json = json_encode([
            'metadata' => $metadata,
            'summary'  => $summary,
            'findings' => array_map(fn (SecurityFinding $f) => $f->toArray(), $findings),
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        if (false === $json) {
            throw new RuntimeException('Failed to encode security report as JSON: '.json_last_error_msg());
        }

        return $json;
    }

    public function getName(): string
    {
        return 'JSON';
    }

    public function getExtension(): string
    {
        return 'json';
    }

    public function getMimeType(): string
    {
        return 'application/json';
    }
}
