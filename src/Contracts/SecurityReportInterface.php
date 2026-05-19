<?php

/**
 * SecurityReportInterface contract.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Contracts;

use ArtisanPackUI\Security\Testing\Reporting\SecurityFinding;

interface SecurityReportInterface
{
    /**
     * Add findings to the report.
     *
     * @param  array<SecurityFinding>  $findings
     */
    public function addFindings(array $findings): self;

    /**
     * Add a single finding to the report.
     */
    public function addFinding(SecurityFinding $finding): self;

    /**
     * Generate the report in the specified format.
     */
    public function generate(string $format = 'json'): string;

    /**
     * Get a summary of the findings.
     *
     * @return array<string, mixed>
     */
    public function getSummary(): array;

    /**
     * Get all findings.
     *
     * @return array<SecurityFinding>
     */
    public function getFindings(): array;
}
