<?php

/**
 * AttackSimulator penetration-testing support class.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\PenetrationTesting;

use ArtisanPackUI\Security\Testing\PenetrationTesting\Attacks\AuthBypassAttack;
use ArtisanPackUI\Security\Testing\PenetrationTesting\Attacks\CsrfAttack;
use ArtisanPackUI\Security\Testing\PenetrationTesting\Attacks\InjectionAttack;
use ArtisanPackUI\Security\Testing\PenetrationTesting\Attacks\PathTraversalAttack;
use ArtisanPackUI\Security\Testing\PenetrationTesting\Attacks\SqlInjectionAttack;
use ArtisanPackUI\Security\Testing\PenetrationTesting\Attacks\XssAttack;

class AttackSimulator
{
    /**
     * Registered attacks.
     *
     * @var array<AttackInterface>
     */
    protected array $attacks = [];

    /**
     * Results from the last simulation.
     *
     * @var array<AttackResult>
     */
    protected array $results = [];

    /**
     * Create a new attack simulator.
     *
     * @param  object  $testCase  The test case to use for HTTP requests
     */
    public function __construct(
        protected object $testCase,
    ) {}

    /**
     * Register an attack to simulate.
     */
    public function registerAttack(AttackInterface $attack): self
    {
        $this->attacks[] = $attack;

        return $this;
    }

    /**
     * Simulate all registered attacks against a target.
     *
     * @param  array<string, mixed>  $options
     */
    public function simulate(string $uri, array $options = []): AttackResults
    {
        $this->results = [];

        foreach ($this->attacks as $attack) {
            $result          = $attack->execute($this->testCase, $uri, $options);
            $this->results[] = $result;
        }

        return new AttackResults($this->results);
    }

    /**
     * Create a simulator with all standard attacks.
     */
    public static function fullScan(object $testCase): self
    {
        $simulator = new self($testCase);

        return $simulator
            ->registerAttack(new SqlInjectionAttack)
            ->registerAttack(new XssAttack)
            ->registerAttack(new CsrfAttack)
            ->registerAttack(new AuthBypassAttack)
            ->registerAttack(new PathTraversalAttack)
            ->registerAttack(new InjectionAttack);
    }

    /**
     * Create a simulator for SQL injection testing only.
     */
    public static function sqlInjection(object $testCase): self
    {
        return (new self($testCase))->registerAttack(new SqlInjectionAttack);
    }

    /**
     * Create a simulator for XSS testing only.
     */
    public static function xss(object $testCase): self
    {
        return (new self($testCase))->registerAttack(new XssAttack);
    }

    /**
     * Create a simulator for injection testing (command, template, etc.).
     */
    public static function injection(object $testCase): self
    {
        return (new self($testCase))
            ->registerAttack(new SqlInjectionAttack)
            ->registerAttack(new InjectionAttack);
    }

    /**
     * Get the last simulation results.
     *
     * @return array<AttackResult>
     */
    public function getResults(): array
    {
        return $this->results;
    }

    /**
     * Clear registered attacks.
     */
    public function clearAttacks(): self
    {
        $this->attacks = [];

        return $this;
    }

    /**
     * Get registered attacks.
     *
     * @return array<AttackInterface>
     */
    public function getAttacks(): array
    {
        return $this->attacks;
    }
}
