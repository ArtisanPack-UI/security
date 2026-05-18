<?php

/**
 * AttackInterface penetration-testing support class.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\PenetrationTesting;

interface AttackInterface
{
    /**
     * Execute the attack against a target.
     *
     * @param  object  $testCase  The test case to use for HTTP requests
     * @param  string  $uri  The target URI
     * @param  array<string, mixed>  $options  Attack options
     */
    public function execute(object $testCase, string $uri, array $options = []): AttackResult;

    /**
     * Get the attack name.
     */
    public function getName(): string;

    /**
     * Get the attack description.
     */
    public function getDescription(): string;

    /**
     * Get the OWASP category for this attack.
     */
    public function getOwaspCategory(): string;
}
