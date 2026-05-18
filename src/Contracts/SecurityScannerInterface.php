<?php

/**
 * SecurityScannerInterface contract.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Contracts;

use ArtisanPackUI\Security\Testing\Reporting\SecurityFinding;

interface SecurityScannerInterface
{
    /**
     * Run the security scan.
     *
     * @return array<SecurityFinding>
     */
    public function scan(): array;

    /**
     * Get the scanner name.
     */
    public function getName(): string;

    /**
     * Get the scanner description.
     */
    public function getDescription(): string;

    /**
     * Check if the scanner is enabled.
     */
    public function isEnabled(): bool;
}
