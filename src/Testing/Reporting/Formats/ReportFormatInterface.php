<?php

/**
 * ReportFormatInterface security report formatter.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\Reporting\Formats;

use ArtisanPackUI\Security\Testing\Reporting\SecurityFinding;

interface ReportFormatInterface
{
    /**
     * Format the findings into a string.
     *
     * @param  array<SecurityFinding>  $findings
     * @param  array<string, mixed>  $metadata
     * @param  array<string, mixed>  $summary
     */
    public function format(array $findings, array $metadata, array $summary): string;

    /**
     * Get the format name.
     */
    public function getName(): string;

    /**
     * Get the file extension for this format.
     */
    public function getExtension(): string;

    /**
     * Get the MIME type for this format.
     */
    public function getMimeType(): string;
}
