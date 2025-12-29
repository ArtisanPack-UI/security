<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Analytics\IncidentResponse\Contracts;

use ArtisanPackUI\Security\Models\Anomaly;
use ArtisanPackUI\Security\Models\SecurityIncident;

interface ResponseActionInterface
{
    /**
     * Get the action name.
     */
    public function getName(): string;

    /**
     * Execute the action.
     *
     * @param  array<string, mixed>  $config
     * @return array<string, mixed>
     */
    public function execute(Anomaly $anomaly, ?SecurityIncident $incident = null, array $config = []): array;

    /**
     * Check if the action requires approval.
     */
    public function requiresApproval(): bool;

    /**
     * Validate the action configuration.
     *
     * @param  array<string, mixed>  $config
     * @return array<int, string>
     */
    public function validate(array $config = []): array;
}
